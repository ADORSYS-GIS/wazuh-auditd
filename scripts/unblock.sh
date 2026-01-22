#!/bin/bash
# External Domain/IP Unblocking Script for macOS/Linux
# Usage: ./unblock-destination.sh [domain|ip] [--keep-domain]

# -------------------------------------------------------------------------
# Global Configuration & OS Detection
# -------------------------------------------------------------------------

# Set shell options
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

OS_NAME=$(uname)

if [[ "$OS_NAME" == "Darwin" ]]; then
    LOG_FILE="/Library/Ossec/active-response/active-responses.log"
    STATE_DIR="/Library/Ossec/active-response/dlp-state"
    STATE_FILE="${STATE_DIR}/dlp_state.json"
    UNBLOCK_PLIST="/Library/LaunchDaemons/com.wazuh.unblock.plist"
elif [[ "$OS_NAME" == "Linux" ]]; then
    LOG_FILE="/var/ossec/logs/active-responses.log"
    STATE_DIR="/var/ossec/active-response/dlp-state"
    STATE_FILE="${STATE_DIR}/dlp_state.json"
    BLOCK_DOMAIN_TIMER="wazuh-blockdomain.timer"
    UNBLOCK_TIMER="wazuh-unblock.timer"
else
    echo "$(date +"%Y-%m-%d %H:%M:%S") wazuh-dlp(unblock): Error: Unsupported OS: $OS_NAME" >&2
    exit 1
fi

# Ensure state directory exists
if [[ ! -d "$STATE_DIR" ]]; then
    mkdir -p "$STATE_DIR"
    chmod 750 "$STATE_DIR"
fi

LOCK_FILE="${STATE_FILE}.lock"

# -------------------------------------------------------------------------
# Logging & Cleanup
# -------------------------------------------------------------------------
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") wazuh-dlp(unblock): $1" >> "$LOG_FILE"
}

cleanup() {
    flock -u 200 2>/dev/null || true
    flock -u 201 2>/dev/null || true
    exec 200>&- 2>/dev/null || true
    exec 201>&- 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# -------------------------------------------------------------------------
# State Management
# -------------------------------------------------------------------------
state_update() {
    exec 200>>"$LOCK_FILE" || exit 1
    flock -x -w 10 200 || exit 1

    local tmp
    tmp=$(mktemp "${STATE_FILE}.XXXXXX") || { flock -u 200; exit 1; }

    "$@" > "$tmp" || {
        rm -f "$tmp"
        flock -u 200
        exit 1
    }

    mv "$tmp" "$STATE_FILE" || {
        rm -f "$tmp"
        flock -u 200
        exit 1
    }
    flock -u 200
}

state_read() {
    exec 201>>"$LOCK_FILE" || exit 1
    flock -s -w 10 201 || exit 1
    jq "$@" "$STATE_FILE"
    local rc=$?
    flock -u 201
    return $rc
}

# -------------------------------------------------------------------------
# Unblocking Logic
# -------------------------------------------------------------------------
unblock_ip() {
    local ip="$1"
    if [[ "$OS_NAME" == "Linux" ]]; then
        local table="blocked_ipv4"
        [[ "$ip" =~ : ]] && table="blocked_ipv6"
        
        if nft get element inet egress "$table" { "$ip" } &>/dev/null; then
            if nft delete element inet egress "$table" { "$ip" }; then
                log "Info: Successfully removed $ip from nftables ($table)"
            else
                log "Error: Failed to remove $ip from nftables ($table)"
                return 1
            fi
        else
            log "Info: $ip not found in nftables ($table)"
        fi
    elif [[ "$OS_NAME" == "Darwin" ]]; then
        if pfctl -t wazuh_fwtable -T test "$ip" &>/dev/null; then
            if pfctl -t wazuh_fwtable -T delete "$ip" &>/dev/null; then
                log "Info: Successfully removed $ip from pf table (wazuh_fwtable)"
            else
                log "Error: Failed to remove $ip from pf table (wazuh_fwtable)"
                return 1
            fi
        else
            log "Info: $ip not found in pf table (wazuh_fwtable)"
        fi
    fi
}

remove_from_state() {
    local type="$1" # "ip" or "domain"
    local target="$2"
    local keep_domain="$3"

    if [[ "$type" == "ip" ]]; then
        log "Info: Removing IP $target from state"
        state_update jq --arg ip "$target" 'del(.blocked_ips[$ip])' "$STATE_FILE"
    else
        if [[ "$keep_domain" == "true" ]]; then
            log "Info: Clearing blocked IPs for domain $target in state (preserving domain)"
            state_update jq --arg domain "$target" \
                '.domains[$domain].blocked_ips = [] | .blocked_ips |= with_entries(select(.value.domain != $domain))' \
                "$STATE_FILE"
        else
            log "Info: Removing domain $target and its IPs from state"
            state_update jq --arg domain "$target" \
                'del(.domains[$domain]) | .blocked_ips |= with_entries(select(.value.domain != $domain))' \
                "$STATE_FILE"
        fi
    fi
}

process_scheduled_unblocks() {
    local now=$(date +%s)
    
    # Process domains
    local domains
    domains=$(state_read -r --argjson now "$now" '.domains | to_entries | map(select(.value.unblock_at != null and .value.unblock_at <= $now)) | map(.key) | .[]?' 2>/dev/null)
    for d in $domains; do
        log "Info: Processing scheduled unblock for domain $d"
        local ips
        ips=$(state_read -r --arg d "$d" '.domains[$d].blocked_ips[]?' 2>/dev/null)
        for ip in $ips; do unblock_ip "$ip"; done
        remove_from_state "domain" "$d" "false"
    done

    # Process individual IPs
    local ips
    ips=$(state_read -r --argjson now "$now" '.blocked_ips | to_entries | map(select(.value.unblock_at != null and .value.unblock_at <= $now)) | map(.key) | .[]?' 2>/dev/null)
    for ip in $ips; do
        log "Info: Processing scheduled unblock for IP $ip"
        unblock_ip "$ip"
        remove_from_state "ip" "$ip"
    done

    # Cleanup services if nothing left to unblock
    local scheduled_count
    scheduled_count=$(state_read -r '[.domains, .blocked_ips] | map(to_entries[] | select(.value.unblock_at != null)) | length' 2>/dev/null || echo 0)
    if [[ "$scheduled_count" -eq 0 ]]; then
        log "Info: No more scheduled unblocks. Ensuring background services are stopped."
        [[ "$OS_NAME" == "Darwin" ]] && launchctl unload "$UNBLOCK_PLIST" 2>/dev/null
        [[ "$OS_NAME" == "Linux" ]] && systemctl stop "$UNBLOCK_TIMER" 2>/dev/null
    fi
}

# -------------------------------------------------------------------------
# Main Execution
# -------------------------------------------------------------------------
input="$1"
keep_domain="false"
[[ "$2" == "--keep-domain" ]] && keep_domain="true"

if [[ -z "$input" ]]; then
    log "Info: Running scheduled unblock processing"
    process_scheduled_unblocks
    exit 0
fi

if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$input" =~ : ]]; then
    log "Info: Manual unblock requested for IP $input"
    unblock_ip "$input"
    remove_from_state "ip" "$input"
else
    log "Info: Manual unblock requested for domain $input (keep_domain=$keep_domain)"
    ips=$(state_read -r --arg d "$input" '.domains[$d].blocked_ips[]?' 2>/dev/null)
    for ip in $ips; do unblock_ip "$ip"; done
    remove_from_state "domain" "$input" "$keep_domain"
fi

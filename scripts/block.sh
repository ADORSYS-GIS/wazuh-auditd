#!/bin/bash
# External Domain Blocking Script for macOS/Linux
# Usage: ./block-domain.sh <domain|ip> [unblock_duration]

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
    UNBLOCK_SCRIPT="/Library/Ossec/active-response/bin/unblock.sh"
    BLOCK_DOMAIN_PLIST="/Library/LaunchDaemons/com.wazuh.blockdomain.plist"
elif [[ "$OS_NAME" == "Linux" ]]; then
    LOG_FILE="/var/ossec/logs/active-responses.log"
    STATE_DIR="/var/ossec/active-response/dlp-state"
    STATE_FILE="${STATE_DIR}/dlp_state.json"
    UNBLOCK_SCRIPT="/var/ossec/active-response/bin/unblock.sh"
    BLOCK_DOMAIN_TIMER="wazuh-blockdomain.timer"
else
    echo "$(date +"%Y-%m-%d %H:%M:%S") wazuh-dlp(block): Error: Unsupported OS: $OS_NAME" >&2
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
    echo "$(date +"%Y-%m-%d %H:%M:%S") wazuh-dlp(block): $1" >> "$LOG_FILE"
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

init_state_file() {
    if [[ ! -s "$STATE_FILE" ]]; then
        log "Info: Initializing new state file: $STATE_FILE"
        state_update jq -n '{blocked_ips: {}, domains: {}, meta: { version: "1.0", last_run: null }}'
    fi
}

init_state_file

# -------------------------------------------------------------------------
# Network Logic
# -------------------------------------------------------------------------
resolve_domain() {
    local domain=$1
    local ips=()

    if command -v dig &>/dev/null; then
        while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$ip" =~ : ]] && ips+=("$ip")
        done < <({ dig +short "$domain" A; dig +short "$domain" AAAA; } 2>/dev/null)
    elif command -v nslookup &>/dev/null; then
        while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$ip" =~ : ]] && ips+=("$ip")
        done < <(nslookup "$domain" 2>/dev/null | awk 'found && $1=="Address:" {print $2} /^Name:/{found=1}' | sed 's/#.*//')
    fi
    
    [[ ${#ips[@]} -eq 0 ]] && return 1
    printf "%s\n" "${ips[@]}"
}

block_ip() {
    local ip="$1"
    if [[ "$OS_NAME" == "Linux" ]]; then
        local table="blocked_ipv4"
        [[ "$ip" =~ : ]] && table="blocked_ipv6"
        
        if nft get element inet egress "$table" { "$ip" } &>/dev/null; then
            log "Info: $ip already exists in nftables ($table)"
            return 0
        fi
        if nft add element inet egress "$table" { "$ip" }; then
            log "Info: Successfully added $ip to nftables ($table)"
            return 0
        else
            log "Error: Failed to add $ip to nftables ($table)"
            return 1
        fi
    elif [[ "$OS_NAME" == "Darwin" ]]; then
        if ! pfctl -t wazuh_fwtable -T test "$ip" &>/dev/null; then
            if pfctl -t wazuh_fwtable -T add "$ip" &>/dev/null; then
                log "Info: Successfully added $ip to pf table (wazuh_fwtable)"
                return 0
            else
                log "Error: Failed to add $ip to pf table (wazuh_fwtable)"
                return 1
            fi
        else
            log "Info: $ip already exists in pf table (wazuh_fwtable)"
            return 0
        fi
    fi
}

# -------------------------------------------------------------------------
# Action Handlers
# -------------------------------------------------------------------------
update_state_block() {
    local type="$1" # "ip" or "domain"
    local target="$2"
    local now="$3"
    local unblock_at="$4"
    local domain_name="$5" # Domain name if type is "ip"
    
    if [[ "$type" == "ip" ]]; then
        state_update jq --arg ip "$target" --argjson blocked_at "$now" --argjson unblock_at "$unblock_at" --arg domain "$domain_name" \
            '.blocked_ips[$ip] |= {blocked_at: $blocked_at, unblock_at: $unblock_at, source: "wazuh-active-response", domain: $domain}' \
            "$STATE_FILE"
    else
        local resolved_json="$5"
        local blocked_json="$6"
        state_update jq --arg domain "$target" --argjson last_resolved "$now" --argjson resolved_ips "$resolved_json" \
            --argjson blocked_ips "$blocked_json" --argjson unblock_at "$unblock_at" \
            '.domains[$domain] = {last_resolved: $last_resolved, resolved_ips: $resolved_ips, blocked_ips: $blocked_ips, unblock_at: $unblock_at} | .meta.last_run = $last_resolved' \
            "$STATE_FILE"
    fi
}

# -------------------------------------------------------------------------
# Main Execution
# -------------------------------------------------------------------------
input="${1:-}"
unblock_duration="${2:-null}"
now=$(date +%s)
unblock_at="null"
[[ "$unblock_duration" =~ ^[0-9]+$ ]] && unblock_at=$((now + unblock_duration))

if [[ -z "$input" ]]; then
    log "Info: Starting periodic refresh for all blocked domains"
    domains=$(state_read -r '.domains | keys | .[]' 2>/dev/null)
    
    if [[ -z "$domains" ]]; then
        log "Info: No domains in state. Ensuring services are stopped."
        [[ "$OS_NAME" == "Darwin" ]] && launchctl unload "$BLOCK_DOMAIN_PLIST" 2>/dev/null
        [[ "$OS_NAME" == "Linux" ]] && systemctl stop "$BLOCK_DOMAIN_TIMER" 2>/dev/null
        exit 0
    fi

    while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        log "Info: Refreshing IPs for domain: $d"
        existing_unblock=$(state_read -r --arg d "$d" '.domains[$d].unblock_at // "null"')
        
        # Unblock old IPs but keep domain entry
        "$UNBLOCK_SCRIPT" "$d" "--keep-domain"
        
        if resolved_ips=$(resolve_domain "$d"); then
            log "Info: Resolved IPs for $d: $(echo $resolved_ips | xargs)"
            blocked_ips=()
            while IFS= read -r ip; do
                if block_ip "$ip"; then
                    blocked_ips+=("$ip")
                    update_state_block "ip" "$ip" "$now" "$existing_unblock" "$d"
                fi
            done <<< "$resolved_ips"
            
            if [[ ${#blocked_ips[@]} -gt 0 ]]; then
                update_state_block "domain" "$d" "$now" "$existing_unblock" \
                    "$(printf "%s\n" "$resolved_ips" | jq -R . | jq -s .)" \
                    "$(printf "%s\n" "${blocked_ips[@]}" | jq -R . | jq -s .)"
                log "Info: Refreshed $d with ${#blocked_ips[@]} active IPs"
            else
                log "Warning: No IPs could be blocked for $d after resolution (clearing domain IPs)"
                update_state_block "domain" "$d" "$now" "$existing_unblock" "[]" "[]"
            fi
        else
            log "Warning: Could not resolve any IPs for domain $d during refresh (clearing domain IPs)"
            update_state_block "domain" "$d" "$now" "$existing_unblock" "[]" "[]"
        fi
    done <<< "$domains"
    exit 0
fi

# Single Target Blocking
if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$input" =~ : ]]; then
    log "Info: Request to block specific IP: $input"
    if block_ip "$input"; then
        update_state_block "ip" "$input" "$now" "$unblock_at" ""
        log "Info: IP $input blocked until $([[ "$unblock_at" == "null" ]] && echo "permanently" || date -r $unblock_at)"
    fi
else
    log "Info: Request to block domain: $input"
    if resolved_ips=$(resolve_domain "$input"); then
        log "Info: Resolved IPs for $input: $(echo $resolved_ips | xargs)"
        blocked_ips=()
        while IFS= read -r ip; do
            if block_ip "$ip"; then
                blocked_ips+=("$ip")
                update_state_block "ip" "$ip" "$now" "$unblock_at" "$input"
            fi
        done <<< "$resolved_ips"
        
        if [[ ${#blocked_ips[@]} -gt 0 ]]; then
            update_state_block "domain" "$input" "$now" "$unblock_at" \
                "$(printf "%s\n" "$resolved_ips" | jq -R . | jq -s .)" \
                "$(printf "%s\n" "${blocked_ips[@]}" | jq -R . | jq -s .)"
            log "Info: Domain $input blocked with ${#blocked_ips[@]} IPs until $([[ "$unblock_at" == "null" ]] && echo "permanently" || date -r $unblock_at)"
        else
            log "Error: Failed to block any IPs for domain $input"
        fi
    else
        log "Error: Could not resolve domain $input"
    fi
fi

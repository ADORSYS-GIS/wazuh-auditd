#!/bin/bash
# DLP Active Response Script (Linux & macOS)
# Actions: Blocks destination IP/domain permanently until manual unblock

# -------------------------------------------------------------------------
# Global Configuration & Arguments
# -------------------------------------------------------------------------

set -euo pipefail

OS_NAME=$(uname -s)

if [[ "$OS_NAME" == "Linux" ]]; then
    LOG_FILE="/var/ossec/logs/active-responses.log"
    STATE_DIR="/var/ossec/active-response/dlp-state"
elif [[ "$OS_NAME" == "Darwin" ]]; then
    LOG_FILE="/Library/Ossec/active-response/active-responses.log"
    STATE_DIR="/Library/Ossec/active-response/dlp-state"
    PF_TABLE="wazuh_blocked"
else
    echo "Unsupported OS: $OS_NAME"
    exit 1
fi

# Ensure state directory exists
if [[ ! -d "$STATE_DIR" ]]; then
    mkdir -p "$STATE_DIR"
    chmod 750 "$STATE_DIR"
fi

# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------
log() {
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$ts wazuh-dlp: $1" >> "$LOG_FILE"
}

# -------------------------------------------------------------------------
# Input Sanitization
# -------------------------------------------------------------------------
remove_full_log() {
  awk '{
    if (match($0, /"full_log":"/)) {
      before = substr($0, 1, RSTART + RLENGTH - 1)
      after = substr($0, RSTART + RLENGTH)
      if (match(after, /","/)) {                                            
        after = substr(after, RSTART)
        print before after
      }
    }
  }'
}

# -------------------------------------------------------------------------
# Dependency Check
# -------------------------------------------------------------------------
DEPS=("jq")
[[ "$OS_NAME" == "Linux" ]] && DEPS+=("nft")
[[ "$OS_NAME" == "Darwin" ]] && DEPS+=("pfctl")

for bin in "${DEPS[@]}"; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        log "Error: $bin not found. Ensure it is installed and in PATH."
        exit 1
    fi
done

# -------------------------------------------------------------------------
# Network & Blocking Logic
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
    local source="${2:-Unknown}"
    
    log "Info: Attempting to block IP: $ip (Source: $source)"
    
    if [[ "$OS_NAME" == "Linux" ]]; then
        local table="blocked_ipv4"
        [[ "$ip" =~ : ]] && table="blocked_ipv6"
        if ! nft get element inet egress "$table" { "$ip" } &>/dev/null; then
            if nft add element inet egress "$table" { "$ip" }; then
                log "Info: Successfully blocked IP: $ip (Source: $source)"
                return 0
            else
                log "Error: Failed to block IP: $ip"
                return 1
            fi
        fi
    elif [[ "$OS_NAME" == "Darwin" ]]; then
        if ! pfctl -t "$PF_TABLE" -T test "$ip" &>/dev/null; then
            if pfctl -t "$PF_TABLE" -T add "$ip" &>/dev/null; then
                log "Info: Successfully blocked IP: $ip (Source: $source)"
                return 0
            else
                log "Error: Failed to block IP: $ip"
                return 1
            fi
        fi
    fi
    
    log "Info: $ip already exists in firewall"
    return 0
}

unblock_ip() {
    local ip="$1"
    log "Info: Attempting to unblock IP: $ip"

    if [[ "$OS_NAME" == "Linux" ]]; then
        local table="blocked_ipv4"
        [[ "$ip" =~ : ]] && table="blocked_ipv6"
        if nft get element inet egress "$table" { "$ip" } &>/dev/null; then
            if nft delete element inet egress "$table" { "$ip" }; then
                log "Info: Successfully unblocked IP: $ip"
                return 0
            else
                log "Error: Failed to unblock IP: $ip"
                return 1
            fi
        fi
    elif [[ "$OS_NAME" == "Darwin" ]]; then
        if pfctl -t "$PF_TABLE" -T test "$ip" &>/dev/null; then
            if pfctl -t "$PF_TABLE" -T delete "$ip" &>/dev/null; then
                log "Info: Successfully unblocked IP: $ip"
                return 0
            else
                log "Error: Failed to unblock IP: $ip"
                return 1
            fi
        fi
    fi

    log "Info: $ip not found in firewall - nothing to unblock"
    return 0
}

# -------------------------------------------------------------------------
# Unblocking Logic (Manual)
# -------------------------------------------------------------------------
process_unblock() {
    local state_file="$1"
    
    if [[ ! -f "$state_file" ]]; then
        log "Error: State file $state_file not found"
        exit 1
    fi

    log "Info: Processing manual unblock using state file: $state_file"
    
    local target
    target=$(jq -r '.target' "$state_file")
    local ips
    ips=$(jq -r '.ips[]' "$state_file")

    for ip in $ips; do
        unblock_ip "$ip"
    done

    log "Info: Unblocked all IPs for target: $target"
    rm -f "$state_file"
    log "Info: Removed state file: $state_file"
    exit 0
}

# -------------------------------------------------------------------------
# Argument Extraction
# -------------------------------------------------------------------------

extract_match() {
    local value="$1"
    local ip_regex='([0-9]{1,3}(\.[0-9]{1,3}){3})'
    local domain_regex='(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'

    if [[ $value =~ $ip_regex ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    elif [[ $value =~ $domain_regex ]]; then
        local domain="${BASH_REMATCH[1]}"
        # Filter out common false positives
        if [[ ! $domain =~ \.(txt|log|conf|json|yaml|yml)$ ]]; then
            echo "$domain"
            return 0
        fi
    fi
    return 1
}

extract_destination() {
    local input="$1"
    local arg

    if [[ "$OS_NAME" == "Darwin" ]]; then
        extract_match "$input"
    elif [[ "$OS_NAME" == "Linux" ]]; then
        while read -r arg; do
            if extract_match "$arg"; then
                return
            fi
        done < <(jq -r '.[]' <<< "$input")
    fi
}

# -------------------------------------------------------------------------
# Blocking Logic Handlers
# -------------------------------------------------------------------------
block_destination() {
    local target="$1"
    local resolved_ips=()
    
    log "Info: Initiating permanent block for $target"
    
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$target" =~ : ]]; then
        block_ip "$target" "Manual"
        resolved_ips+=("$target")
    else
        local ips
        ips=$(resolve_domain "$target" || echo "")
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            block_ip "$ip" "$target"
            resolved_ips+=("$ip")
        done <<< "$ips"
    fi
    
    # Create immutable state file for this block
    local safe_target=$(echo "$target" | tr '/:' '_')
    local state_file="${STATE_DIR}/block_${safe_target}_$(date +%s).json"
    
    printf '{"target": "%s", "ips": %s, "timestamp": "%s"}\n' \
        "$target" \
        "$(printf "%s\n" "${resolved_ips[@]}" | jq -R . | jq -s .)" \
        "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "$state_file"
    
    chmod 440 "$state_file"
    log "Info: Created state file: $state_file"
}

# -------------------------------------------------------------------------
# Main Execution
# -------------------------------------------------------------------------

# Check if unblock mode (state file passed as argument)
if [[ $# -eq 1 ]] && [[ -f "$1" ]]; then
    process_unblock "$1"
fi

# Otherwise, read JSON from stdin (standard block mode)
if ! read INPUT_JSON; then
    log "Error: No input JSON received on stdin"
    exit 0
fi

if [[ "$OS_NAME" == "Linux" ]]; then
    SANITIZED_JSON=$(echo "$INPUT_JSON" | remove_full_log)
    EXFIL_COMMAND=$(echo "$SANITIZED_JSON" | jq -r .parameters.alert.data.audit.execve)
else
    EXFIL_COMMAND=$(echo "$INPUT_JSON" | jq -r .parameters.alert.data.args)
fi

if [[ -z "$EXFIL_COMMAND" || "$EXFIL_COMMAND" == "null" ]]; then
    log "Error: Could not extract exfiltration command from alert"
    exit 0
fi

destination=$(extract_destination "$EXFIL_COMMAND")

if [[ -n "$destination" ]]; then
    block_destination "$destination"
else
    log "Info: No destination IP or domain found in command: $EXFIL_COMMAND"
fi

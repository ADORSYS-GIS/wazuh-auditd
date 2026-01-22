#!/bin/bash
# DLP Active Response Script
# Supports: Linux (Auditd), macOS (Santa)
# Actions: Blocks destination IP/domain temporarily or permanently

# -------------------------------------------------------------------------
# Global Configuration & OS Detection
# -------------------------------------------------------------------------
OS_NAME=$(uname)
UNBLOCK_DURATION=${UNBLOCK_DURATION:-60}
UNBLOCK_TIME=${UNBLOCK_TIME:-"now + 1 minute"}

# Path configuration based on OS
if [[ "$OS_NAME" == "Darwin" ]]; then
    LOG_FILE="/Library/Ossec/active-response/active-responses.log"
    ICON_PATH="/Library/Application Support/Ossec/wazuh-logo.png"
    STATE_DIR="/Library/Ossec/active-response/dlp-state"
    STATE_FILE="${STATE_DIR}/dlp_state.json"
    BLOCK_SH="/Library/Ossec/active-response/bin/block.sh"
    UNBLOCK_SH="/Library/Ossec/active-response/bin/unblock.sh"
    BLOCK_DOMAIN_PLIST="/Library/LaunchDaemons/com.wazuh.blockdomain.plist"
    UNBLOCK_PLIST="/Library/LaunchDaemons/com.wazuh.unblock.plist"
elif [[ "$OS_NAME" == "Linux" ]]; then
    LOG_FILE="/var/ossec/logs/active-responses.log"
    ICON_PATH="/usr/share/pixmaps/wazuh-logo.png"
    STATE_DIR="/var/ossec/active-response/dlp-state"
    STATE_FILE="${STATE_DIR}/dlp_state.json"
    BLOCK_SH="/var/ossec/active-response/bin/block.sh"
    UNBLOCK_SH="/var/ossec/active-response/bin/unblock.sh"
    BLOCK_DOMAIN_TIMER="wazuh-blockdomain.timer"
    UNBLOCK_TIMER="wazuh-unblock.timer"
else
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
    echo "$(date +"%Y-%m-%d %H:%M:%S") wazuh-dlp: $1" >> "$LOG_FILE"
}

cleanup() {
    flock -u 200 2>/dev/null || true
    exec 200>&- 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# -------------------------------------------------------------------------
# Dependency Check
# -------------------------------------------------------------------------
for bin in jq flock; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        log "Error: $bin not found. Ensure it is installed and in PATH."
        exit 1
    fi
done

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

# -------------------------------------------------------------------------
# Argument Extraction
# -------------------------------------------------------------------------
extract_match() {
    local value="$1"
    local ip_regex='([0-9]{1,3}(\.[0-9]{1,3}){3})'
    local domain_regex='https?://([^:/]+)'

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
    local duration="${2:-$UNBLOCK_DURATION}"
    log "Info: Initiating block for $target (Duration: ${duration}s)"
    "$BLOCK_SH" "$target" "$duration"
}

schedule_unblock() {
    local target="$1"
    local unblock_at

    if [[ "$OS_NAME" == "Darwin" ]]; then
        unblock_at=$(date -v+${UNBLOCK_DURATION}S +%s)
    else
        unblock_at=$(date -d "+${UNBLOCK_DURATION} seconds" +%s)
    fi
    
    log "Info: Scheduling unblock for $target at $(date -r $unblock_at 2>/dev/null || date -d @$unblock_at)"
    
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        state_update jq --arg ip "$target" --argjson at "$unblock_at" \
            '.blocked_ips[$ip].unblock_at = $at' "$STATE_FILE"
    else
        state_update jq --arg domain "$target" --argjson at "$unblock_at" \
            '.domains[$domain].unblock_at = $at | .blocked_ips |= with_entries(if .value.domain == $domain then .value.unblock_at = $at else . end)' \
            "$STATE_FILE"
    fi

    if [[ "$OS_NAME" == "Darwin" ]]; then
        if ! launchctl list | grep -q "com.wazuh.unblock"; then
            log "Info: Loading unblock daemon (com.wazuh.unblock)"
            launchctl load "$UNBLOCK_PLIST" 2>/dev/null || log "Warning: Failed to load unblock plist"
        fi
    elif [[ "$OS_NAME" == "Linux" ]]; then
        if ! systemctl is-active --quiet "$UNBLOCK_TIMER"; then
            log "Info: Starting unblock timer ($UNBLOCK_TIMER)"
            systemctl start "$UNBLOCK_TIMER" || log "Warning: Failed to start $UNBLOCK_TIMER"
        fi
    fi
}

ensure_block_daemon() {
    if [[ "$OS_NAME" == "Darwin" ]]; then
        if ! launchctl list | grep -q "com.wazuh.blockdomain"; then
            log "Info: Loading block refresh daemon (com.wazuh.blockdomain)"
            launchctl load "$BLOCK_DOMAIN_PLIST" 2>/dev/null || log "Warning: Failed to load blockdomain plist"
        fi
    elif [[ "$OS_NAME" == "Linux" ]]; then
        log "Info: Starting block refresh timer ($BLOCK_DOMAIN_TIMER)"
        systemctl start "$BLOCK_DOMAIN_TIMER" || log "Error: Failed to start $BLOCK_DOMAIN_TIMER"
    fi
}

# -------------------------------------------------------------------------
# Notification Logic
# -------------------------------------------------------------------------
confirm_action() {
    local action="$1"
    local message="$2"
    
    log "DEBUG: Requesting user confirmation for: $action"
    if [[ "$OS_NAME" == "Darwin" ]]; then
        local cmd="display dialog \"$message\" with title \"Wazuh DLP Confirmation\" buttons {\"Cancel\", \"$action\"} default button \"Cancel\" with icon caution"
        if osascript -e "$cmd" 2>/dev/null | grep -q "button returned:$action"; then
            log "Info: User confirmed action: $action"
            return 0
        else
            log "Info: User cancelled action: $action"
            return 1
        fi
    elif [[ "$OS_NAME" == "Linux" ]]; then
        local user=$(who | awk '{print $1}' | head -n 1)
        local uid=$(id -u "$user")
        if sudo -u "$user" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
            zenity --question --title="Wazuh DLP Confirmation" --text="$message" --ok-label="$action" --cancel-label="Cancel" --width=400 2>/dev/null; then
            log "Info: User confirmed action: $action"
            return 0
        else
            log "Info: User cancelled action: $action"
            return 1
        fi
    fi
}

send_notification() {
    local title="Wazuh-DLP Exfiltration Alert"
    local message="$1"
    local target="$2"
    local action=""

    log "Info: Sending user notification for event to $target"
    if [[ "$OS_NAME" == "Darwin" ]]; then
        local icon_arg=""
        [[ -f "$ICON_PATH" ]] && icon_arg="with icon POSIX file \"$ICON_PATH\""
        local cmd="display dialog \"$message\" with title \"$title\" buttons {\"Block Temporarily\", \"Block Permanently\", \"Dismiss\"} default button \"Dismiss\" $icon_arg"
        local result=$(osascript -e "$cmd" 2>/dev/null)
        
        if [[ "$result" == *"Block Temporarily"* ]]; then action="temp"
        elif [[ "$result" == *"Block Permanently"* ]]; then action="perm"
        else action="dismiss"; fi
    elif [[ "$OS_NAME" == "Linux" ]]; then
        local user=$(who | awk '{print $1}' | head -n 1)
        local uid=$(id -u "$user")
        local notify_cmd=(sudo -u "$user" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" notify-send --app-name=Wazuh -u critical)
        [[ -f "$ICON_PATH" ]] && notify_cmd+=( -i "$ICON_PATH" )
        notify_cmd+=( -A "temp=Block Temporarily" -A "perm=Block Permanently" -A "dismiss=Dismiss" "$title" "$message" )
        action=$("${notify_cmd[@]}" 2>/dev/null)
    fi

    case "$action" in
        "temp")
            log "Info: User selected 'Block Temporarily' for $target"
            if confirm_action "Block Temporarily" "Block $target for $UNBLOCK_DURATION seconds?"; then
                block_destination "$target" "$UNBLOCK_DURATION"
                schedule_unblock "$target"
                [[ "$target" =~ ^[0-9.]+$ ]] || ensure_block_daemon
            fi
            ;;
        "perm")
            log "Info: User selected 'Block Permanently' for $target"
            if confirm_action "Block Permanently" "Are you sure you want to block $target permanently?"; then
                block_destination "$target" "0"
                [[ "$target" =~ ^[0-9.]+$ ]] || ensure_block_daemon
            fi
            ;;
        *)
            log "Info: User dismissed notification for $target"
            ;;
    esac
}

# -------------------------------------------------------------------------
# Main Execution
# -------------------------------------------------------------------------
INPUT_JSON=$(cat)

if [[ "$OS_NAME" == "Darwin" ]]; then
    EXFIL_COMMAND=$(jq -r '.data.args' <<< "$INPUT_JSON")
    AGENT_ID=$(jq -r '.agent.id' <<< "$INPUT_JSON")
    RULE_ID=$(jq -r '.rule.id' <<< "$INPUT_JSON")
else
    EXFIL_COMMAND=$(jq -c '.data.audit.execve' <<< "$INPUT_JSON")
    AGENT_ID=$(jq -r '.agent.id' <<< "$INPUT_JSON")
    RULE_ID=$(jq -r '.rule.id' <<< "$INPUT_JSON")
fi

destination=$(extract_destination "$EXFIL_COMMAND")

if [[ -z "$destination" ]]; then
    log "Error: Could not extract destination from input command: $EXFIL_COMMAND"
    exit 0
fi

log "Info: Processing exfiltration event [Agent: $AGENT_ID, Rule: $RULE_ID, Destination: $destination]"
echo $destination

send_notification "Potential data exfiltration detected to $destination. Agent: $AGENT_ID, Rule: $RULE_ID" "$destination"
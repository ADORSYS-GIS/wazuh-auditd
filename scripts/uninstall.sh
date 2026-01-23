#!/bin/sh

# Set shell options
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Variables
LOG_LEVEL=${LOG_LEVEL:-INFO}
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
SYSTEMD_DIR="/etc/systemd/system"
ACTIVE_RESPONSE_DIR="/var/ossec/active-response"
BIN_DIR="$ACTIVE_RESPONSE_DIR/bin"
STATE_DIR="$ACTIVE_RESPONSE_DIR/dlp-state"
SERVICES=("wazuh-blockdomain.service" "wazuh-unblock.service")
TIMERS=("wazuh-blockdomain.timer" "wazuh-unblock.timer")

# Define text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Function for logging with timestamp
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${TIMESTAMP} ${LEVEL} ${MESSAGE}"
}

# Logging helpers
info_message() {
    log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"
}

warn_message() {
    log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"
}

error_message() {
    log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"
}

success_message() {
    log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"
}

print_step() {
    log "${BLUE}${BOLD}[STEP]${NORMAL}" "$1: $2"
}

print_step_header() {
    echo -e "\n${BOLD}===== STEP $1: $2 =====${NORMAL}\n";
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Ensure root privileges, either directly or through sudo
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        if command_exists sudo; then
            sudo "$@"
        else
            error_message "This script requires root privileges. Please run with sudo or as root."
            exit 1
        fi
    else
        "$@"
    fi
}

# Error Handler
error_exit() {
    error_message "$1"
    exit 1
}

# Check if running on Linux
if [[ "$(uname)" != "Linux" ]]; then
    error_exit "This script is designed for Linux systems only."
fi

print_step_header 1 "Stopping Auditd Service"
info_message "Stopping auditd service..."
maybe_sudo systemctl stop auditd > /dev/null 2>&1 || warn_message "Failed to stop auditd service"

print_step_header 2 "Removing Exfiltration Rules"
info_message "Removing exfiltration rules..."
maybe_sudo rm -f /etc/audit/rules.d/exfiltration.rules || warn_message "Failed to remove exfiltration rules"

print_step_header 3 "Disabling Auditd Service"
info_message "Disabling auditd service..."
maybe_sudo systemctl disable auditd > /dev/null 2>&1 || warn_message "Failed to disable auditd service"

print_step_header 4 "Removing Active Response Services"
info_message "Disabling and removing services and timers..."

remove_unit() {
    local unit="$1"
    if [ -f "${SYSTEMD_DIR}/${unit}" ]; then
        info_message "Stopping and disabling ${unit}..."
        maybe_sudo systemctl stop "${unit}" > /dev/null 2>&1 || true
        maybe_sudo systemctl disable "${unit}" > /dev/null 2>&1 || true
        
        info_message "Removing ${unit}..."
        maybe_sudo rm -f "${SYSTEMD_DIR}/${unit}"
    else
        info_message "${unit} not found. Skipping."
    fi
}

# Remove Services
for service in "${SERVICES[@]}"; do
    remove_unit "${service}"
done

# Remove Timers
for timer in "${TIMERS[@]}"; do
    remove_unit "${timer}"
done

info_message "Reloading systemd daemon..."
maybe_sudo systemctl daemon-reload

print_step_header 5 "Removing Active Response Scripts"
info_message "Removing active response scripts..."
maybe_sudo rm -f "$BIN_DIR/block.sh" "$BIN_DIR/unblock.sh" "$BIN_DIR/dlp.sh" || warn_message "Failed to remove one or more scripts"
maybe_sudo rm -rf "$STATE_DIR" || warn_message "Failed to remove DLP state directory"
success_message "Active response scripts removal attempted."

print_step_header 6 "Removing nftables Configuration"
info_message "Removing nftables configuration..."
maybe_sudo rm -f /etc/nftables.conf.d/wazuh.conf || warn_message "Failed to remove nftables.conf"
info_message "Flushing nftables ruleset..."
maybe_sudo nft delete table inet egress || warn_message "Failed to delete Wazuh nftables table"
success_message "nftables configuration removal attempted."

print_step_header 7 "Removing Packages"
info_message "Removing installed packages..."
maybe_sudo apt remove auditd audispd-plugins jq -y > /dev/null 2>&1 || warn_message "Failed to remove packages"
maybe_sudo apt autoremove -y > /dev/null 2>&1 || warn_message "Failed to auto-remove dependencies"

print_step_header 8 "Cleaning Up"
info_message "Cleaning up audit logs..."
maybe_sudo rm -f /var/log/audit/audit.log > /dev/null 2>&1 || warn_message "Failed to remove audit logs"

print_step_header 9 "Verifying Uninstallation"
# Validate uninstallation
if maybe_sudo auditctl -l | grep -q "exfil"; then
    warn_message "Exfiltration rules still appear to be loaded."
else
    success_message "Exfiltration rules are not loaded."
fi

# Validate services and timers
info_message "Verifying active response services..."
ALL_UNITS=("${SERVICES[@]}" "${TIMERS[@]}")
PRESENT_UNITS=0

for UNIT in "${ALL_UNITS[@]}"; do
    if [ -f "$SYSTEMD_DIR/$UNIT" ]; then
        error_message "$UNIT is still present in $SYSTEMD_DIR."
        PRESENT_UNITS=$((PRESENT_UNITS + 1))
    else
        success_message "$UNIT is not present in $SYSTEMD_DIR."
    fi
done

if [ "$PRESENT_UNITS" -eq 0 ]; then
    success_message "All active response configurations removed."
else
    warn_message "$PRESENT_UNITS active response configurations still present."
fi

# Validate scripts
info_message "Verifying active response scripts..."
if [ -f "$BIN_DIR/block.sh" ] || [ -f "$BIN_DIR/unblock.sh" ] || [ -f "$BIN_DIR/dlp.sh" ] || [ -d "$STATE_DIR" ]; then
    warn_message "One or more DLP active response scripts or state directory are still present in $BIN_DIR."
else
    success_message "All DLP active response scripts and state directory removed from $ACTIVE_RESPONSE_DIR."
fi

# Validate nftables configuration
info_message "Verifying nftables configuration..."
if maybe_sudo nft list ruleset | grep -q "@blocked_ipv4" || maybe_sudo nft list ruleset | grep -q "@blocked_ipv6"; then
    warn_message "nftables configuration still present."
else
    success_message "nftables configuration removed."
fi

success_message "Auditd uninstallation complete!"
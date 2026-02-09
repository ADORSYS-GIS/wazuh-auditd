#!/bin/bash

# Set shell options
set -euo pipefail

# Variables
OS_NAME=$(uname -s)
LOG_LEVEL=${LOG_LEVEL:-INFO}
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
SYSTEMD_DIR="/etc/systemd/system"
ACTIVE_RESPONSE_DIR="/var/ossec/active-response"
BIN_DIR="$ACTIVE_RESPONSE_DIR/bin"
STATE_DIR="$ACTIVE_RESPONSE_DIR/dlp-state"
SURICATA_RULE_FILE="suricata-exfiltration.rules"
case "$OS_NAME" in
    Linux)
        SURICATA_YAML_PATH="/opt/wazuh/suricata/etc/suricata/suricata.yaml"
        ;;
    *)
        error_message "Unsupported operating system: $OS_NAME. This script is designed for Linux systems only."
        exit 1
        ;;
esac

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

print_step_header 4 "Removing Active Response Scripts"
info_message "Removing active response scripts..."
maybe_sudo rm -f "$BIN_DIR/dlp.sh" || warn_message "Failed to remove script"
maybe_sudo rm -rf "$STATE_DIR" || warn_message "Failed to remove DLP state directory"
success_message "Active response scripts removal attempted."

print_step_header 5 "Removing nftables Configuration"
info_message "Removing nftables configuration..."
maybe_sudo rm -f /etc/nftables.conf.d/wazuh.conf || warn_message "Failed to remove nftables.conf"
info_message "Flushing nftables ruleset..."
maybe_sudo nft delete table inet egress || warn_message "Failed to delete Wazuh nftables table"
success_message "nftables configuration removal attempted."

print_step_header 6 "Removing Suricata Rules"
info_message "Removing Suricata rules..."
maybe_sudo rm -f /opt/wazuh/suricata/var/lib/suricata/rules/$SURICATA_RULE_FILE || warn_message "Failed to remove Suricata rules"
if yq -i "
  .[\"rule-files\"] |= map(select(. != \"$SURICATA_RULE_FILE\"))
" "$SURICATA_YAML_PATH"; then
    success_message "Suricata configuration updated to remove exfiltration rules."
else
    warn_message "Failed to update Suricata configuration. Please ensure suricata.yaml is configured correctly."
fi
maybe_sudo systemctl restart suricata-wazuh > /dev/null 2>&1 || warn_message "Failed to restart Suricata service"

print_step_header 7 "Removing Packages"
info_message "Removing installed packages..."
maybe_sudo apt remove auditd audispd-plugins jq yq -y > /dev/null 2>&1 || warn_message "Failed to remove packages"
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

# Validate Suricata rules
info_message "Verifying Suricata rules removal..."
if yq -e "
  .[\"rule-files\"][] == \"$SURICATA_RULE_FILE\"
" "$SURICATA_YAML_PATH" >/dev/null 2>&1; then
    warn_message "Rule file $SURICATA_RULE_FILE is still present in suricata.yaml"
else
    success_message "Rule file $SURICATA_RULE_FILE successfully removed from suricata.yaml"
fi

# Validate scripts
info_message "Verifying active response scripts..."
if [ -f "$BIN_DIR/dlp.sh" ] || [ -d "$STATE_DIR" ]; then
    warn_message "The DLP active response script or state directory are still present in $BIN_DIR."
else
    success_message "The DLP active response script and state directory removed from $ACTIVE_RESPONSE_DIR."
fi

# Validate nftables configuration
info_message "Verifying nftables configuration..."
if maybe_sudo nft list ruleset | grep -q "@blocked_ipv4" || maybe_sudo nft list ruleset | grep -q "@blocked_ipv6"; then
    warn_message "nftables configuration still present."
else
    success_message "nftables configuration removed."
fi

success_message "Auditd uninstallation complete!"
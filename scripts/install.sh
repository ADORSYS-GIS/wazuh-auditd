#!/bin/bash

# Set shell options
set -euo pipefail

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

# Variables
OS_NAME=$(uname -s)
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
BASE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-auditd/refs/heads/feat/DLP"
CONFIG_URL="${BASE_URL}/config"
SCRIPTS_URL="${BASE_URL}/scripts"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/var/ossec/active-response/bin"
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

remove_systemd_dropins() {
    UNIT_NAME="$1"
    DROPIN_DIR="$SYSTEMD_DIR/${UNIT_NAME}.d"

    if [ -d "$DROPIN_DIR" ]; then
        warn_message "Found existing systemd drop-in directory for ${UNIT_NAME}: ${DROPIN_DIR}. Removing to ensure incoming config takes precedence."
        maybe_sudo rm -rf "$DROPIN_DIR"
    fi
}

remove_journald_config() {
    if maybe_sudo grep -q "<log_format>journald</log_format>" "$OSSEC_CONF_PATH"; then
        # Remove the entire journald localfile block
        maybe_sudo sed -i '/<localfile>/{:a;N;/<\/localfile>/!ba;/journald/d;}' "$OSSEC_CONF_PATH" || {
                error_message "Error occurred while removing the journald localfile block."
                return 1
            }

        info_message "The journald localfile configuration was removed successfully."
    else
        info_message "No journald localfile configuration found. No changes were made."
    fi
}

# Check if running on Linux
if [[ "$(uname)" != "Linux" ]]; then
    error_exit "This script is designed for Linux systems only."
fi

# Check dependencies
print_step_header 1 "Installing Dependencies"
info_message "updating package list"
maybe_sudo apt update > /dev/null 2>&1
info_message "Checking dependencies"
for dep in "auditd" "audispd-plugins" "jq" "yq"; do
    if command_exists "$dep"; then
        success_message "$dep already installed... Skipping installation."
        continue
    fi
    maybe_sudo apt install "$dep" -y > /dev/null 2>&1 || error_exit "Failed to install $dep"
    success_message "$dep installed successfully."
done

print_step_header 2 "Configuring Exfiltration Rules"
info_message "Copying exfiltration rules to audit configuration..."
maybe_sudo mkdir -p /etc/audit/rules.d/ > /dev/null 2>&1
maybe_sudo curl -fsSL "${CONFIG_URL}/exfiltration.rules" -o /etc/audit/rules.d/exfiltration.rules || error_exit "Failed to copy exfiltration rules"

print_step_header 3 "Enabling and Starting Auditd Service"
info_message "Enabling and starting auditd service..."
maybe_sudo systemctl enable --now auditd > /dev/null 2>&1 || error_exit "Failed to enable/start auditd service"
success_message "Auditd service enabled and started."

print_step_header 4 "Loading Audit Rules"
info_message "Loading audit rules..."
maybe_sudo augenrules --load > /dev/null 2>&1 || error_exit "Failed to load audit rules"
success_message "Audit rules loaded successfully."

print_step_header 5 "Restarting Auditd Service"
info_message "Restarting auditd service to apply rules..."
maybe_sudo systemctl restart auditd > /dev/null 2>&1  || error_exit "Failed to restart auditd service"
success_message "Auditd service restarted successfully."

print_step_header 6 "Installing Active Response Scripts"
info_message "Installing active response scripts..."
maybe_sudo mkdir -p "$BIN_DIR" > /dev/null 2>&1
maybe_sudo curl -fsSL "$SCRIPTS_URL/dlp.sh" -o "$BIN_DIR/dlp.sh" || error_exit "Failed to install dlp.sh"
maybe_sudo chmod +x "$BIN_DIR/dlp.sh"
success_message "Active response scripts installed successfully."

print_step_header 7 "Installing nftables Configuration"
info_message "Installing nftables configuration..."
maybe_sudo mkdir -p /etc/nftables.conf.d/ > /dev/null 2>&1
maybe_sudo curl -fsSL "$CONFIG_URL/nftables.conf" -o "/etc/nftables.conf.d/wazuh.conf" || error_exit "Failed to install nftables.conf"
success_message "nftables configuration installed successfully."
info_message "Reloading nftables..."
maybe_sudo nft flush ruleset
maybe_sudo nft -f /etc/nftables.conf.d/wazuh.conf
success_message "nftables reloaded successfully."

print_step_header 8 "Installing Suricata Rules for Exfiltration Detection"
info_message "Backing up existing Suricata configuration..."
if [ -f "$SURICATA_YAML_PATH" ]; then
    maybe_sudo cp "$SURICATA_YAML_PATH" "${SURICATA_YAML_PATH}.bak" || warn_message "Failed to backup Suricata configuration. Please ensure you have a backup of your suricata.yaml before proceeding."
    success_message "Suricata configuration backed up successfully."
else
    warn_message "Suricata configuration file not found at $SURICATA_YAML_PATH. Please ensure Suricata is installed and configured correctly."
fi
info_message "Installing Suricata Rules for Exfiltration Detection"
maybe_sudo curl -fsSL "${CONFIG_URL}/$SURICATA_RULE_FILE" -o /opt/wazuh/suricata/var/lib/suricata/rules/$SURICATA_RULE_FILE || error_exit "Failed to install suricata rules"

maybe_sudo yq -i "
  .[\"rule-files\"] += [\"$SURICATA_RULE_FILE\"] |
  .[\"rule-files\"] |= unique
" "$SURICATA_YAML_PATH" || warn_message "Failed to update Suricata configuration. Please ensure suricata.yaml is configured correctly."
success_message "Suricata rules installed successfully."
info_message "Restarting Suricata service..."
maybe_sudo systemctl restart suricata-wazuh > /dev/null 2>&1 || warn_message "Failed to restart Suricata service. Please ensure it is configured correctly."

print_step_header 9 "Removing Journald Configuration"
remove_journald_config

print_step_header 10 "Verifying Installation"
# Validate installation
if maybe_sudo auditctl -l | grep -q "exfil"; then
    success_message "Exfiltration rules are loaded."
else
    warn_message "Exfiltration rules do not appear to be loaded."
fi

# Validate Suricata rules
info_message "Verifying Suricata rules..."
if suricata -T -c $SURICATA_YAML_PATH 2>&1 >/dev/null; then
    success_message "Suricata rules validated."
else
    warn_message "Suricata rules validation failed, restoring backup."
    maybe_sudo cp "${SURICATA_YAML_PATH}.bak" "$SURICATA_YAML_PATH" || warn_message "Failed to restore Suricata configuration backup. Please check your suricata.yaml file."
    maybe_sudo systemctl restart suricata-wazuh > /dev/null 2>&1 || warn_message "Failed to restart Suricata service after restoring configuration. Please check your Suricata setup."
fi
maybe_sudo rm -f "${SURICATA_YAML_PATH}.bak" || warn_message "Failed to remove Suricata configuration backup. Please check your suricata.yaml file."

# Validate scripts
info_message "Verifying active response scripts..."
if [ -f "$BIN_DIR/dlp.sh" ]; then
    success_message "All active response scripts are present in $BIN_DIR."
else
    warn_message "One or more active response scripts are missing from $BIN_DIR."
fi

# Validate nftables configuration
info_message "Verifying nftables configuration..."
if maybe_sudo nft list ruleset | grep -q "@blocked_ipv4" && maybe_sudo nft list ruleset | grep -q "@blocked_ipv6"; then
    success_message "nftables configuration verified."
else
    warn_message "nftables configuration is missing."
fi

success_message "Auditd installation and configuration complete!"
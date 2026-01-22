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
BASE_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-auditd/refs/heads/feat/DLP"
CONFIG_URL="${BASE_URL}/config"
SCRIPTS_URL="${BASE_URL}/scripts"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/var/ossec/active-response/bin"
SERVICES=("wazuh-blockdomain.service" "wazuh-unblock.service")
TIMERS=("wazuh-blockdomain.timer" "wazuh-unblock.timer")

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

remove_journald_config() {
    if maybe_sudo grep -q "<log_format>journald</log_format>" "$OSSEC_CONF_PATH"; then
        # Remove the entire journald localfile block
        sed -i '/<localfile>/{:a;N;/<\/localfile>/!ba;/journald/d;}' "$OSSEC_CONF_PATH" || {
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
for dep in auditctl augenrules jq util-linux; do
    if ! command_exists "$dep"; then
        info_message "Installing $dep..."
        maybe_sudo apt update > /dev/null 2>&1
        maybe_sudo apt install "$dep" -y > /dev/null 2>&1 || error_exit "Failed to install $dep"
        success_message "$dep installed successfully."
    fi
done 

print_step_header 2 "Configuring Exfiltration Rules"
info_message "Copying exfiltration rules to audit configuration..."
maybe_sudo mkdir -p /etc/audit/rules.d/ > /dev/null 2>&1
maybe_sudo curl -fsSL "${CONFIG_URL}/exfiltration.rules" -o /etc/audit/rules.d/exfiltration.rules || error_message "Failed to copy exfiltration rules"

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

print_step_header 6 "Configuring Active Response Services"
info_message "Configuring systemd services and timers..."

# Install Services
for SERVICE in "${SERVICES[@]}"; do
    URL="$CONFIG_URL/services/$SERVICE"
    info_message "Downloading and installing $SERVICE..."
    
    # Download and write to systemd directory
    if maybe_sudo curl -fsSL "$URL" -o "$SYSTEMD_DIR/$SERVICE"; then
        success_message "$SERVICE installed."
    else
        warn_message "Failed to download $SERVICE from $URL"
    fi
done

# Install Timers
for TIMER in "${TIMERS[@]}"; do
    URL="$CONFIG_URL/timers/$TIMER"
    info_message "Downloading and installing $TIMER..."
    if maybe_sudo curl -fsSL "$URL" -o "$SYSTEMD_DIR/$TIMER"; then
        success_message "$TIMER installed."
    else
        warn_message "Failed to download $TIMER from $URL"
    fi
done

info_message "Reloading systemd daemon..."
maybe_sudo systemctl daemon-reload

success_message "Active response services configured successfully."

print_step_header 7 "Installing Active Response Scripts"
info_message "Installing active response scripts..."
maybe_sudo mkdir -p "$BIN_DIR" > /dev/null 2>&1
maybe_sudo curl -fsSL "$SCRIPTS_URL/block.sh" -o "$BIN_DIR/block.sh" || error_message "Failed to install block.sh"
maybe_sudo curl -fsSL "$SCRIPTS_URL/unblock.sh" -o "$BIN_DIR/unblock.sh" || error_message "Failed to install unblock.sh"
maybe_sudo curl -fsSL "$SCRIPTS_URL/dlp.sh" -o "$BIN_DIR/dlp.sh" || error_message "Failed to install dlp.sh"
maybe_sudo chmod +x "$BIN_DIR/block.sh" "$BIN_DIR/unblock.sh" "$BIN_DIR/dlp.sh"
success_message "Active response scripts installed successfully."

print_step_header 9 "Installing nftables Configuration"
info_message "Installing nftables configuration..."
maybe_sudo mkdir -p /etc/nftables.conf.d/ > /dev/null 2>&1
maybe_sudo curl -fsSL "$CONFIG_URL/nftables.conf" -o "/etc/nftables.conf.d/wazuh.conf" || error_exit "Failed to install nftables.conf"
success_message "nftables configuration installed successfully."
info_message "Reloading nftables..."
maybe_sudo nft flush ruleset
maybe_sudo nft -f /etc/nftables.conf.d/wazuh.conf
success_message "nftables reloaded successfully."

print_step_header 10 "Removing Journald Configuration"
remove_journald_config

print_step_header 11 "Verifying Installation"
# Validate installation
if maybe_sudo auditctl -l | grep -q "exfil"; then
    success_message "Exfiltration rules are loaded."
else
    warn_message "Exfiltration rules do not appear to be loaded."
fi

# Validate services and timers
info_message "Verifying active response services..."
ALL_UNITS=("${SERVICES[@]}" "${TIMERS[@]}")
MISSING_UNITS=0

for UNIT in "${ALL_UNITS[@]}"; do
    if [ -f "$SYSTEMD_DIR/$UNIT" ]; then
        success_message "$UNIT is present in $SYSTEMD_DIR."
    else
        error_message "$UNIT is missing from $SYSTEMD_DIR."
        MISSING_UNITS=$((MISSING_UNITS + 1))
    fi
done

if [ "$MISSING_UNITS" -eq 0 ]; then
    success_message "All active response configurations verified."
else
    warn_message "$MISSING_UNITS active response configurations are missing."
fi

# Validate scripts
info_message "Verifying active response scripts..."
if [ -f "$BIN_DIR/block.sh" ] && [ -f "$BIN_DIR/unblock.sh" ] && [ -f "$BIN_DIR/dlp.sh" ]; then
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
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

# Check if auditd is already installed
if command_exists auditctl && command_exists augenrules; then
    info_message "Auditd tools are already installed."
else
    print_step_header 1 "Installing Auditd"
    info_message "Installing auditd and audispd-plugins..."
    maybe_sudo apt update > /dev/null 2>&1
    maybe_sudo apt install auditd audispd-plugins -y > /dev/null 2>&1 || error_exit "Failed to install auditd packages"
    success_message "Auditd packages installed successfully."
fi

print_step_header 2 "Configuring Exfiltration Rules"
info_message "Copying exfiltration rules to audit configuration..."
maybe_sudo mkdir -p /etc/audit/rules.d/ > /dev/null 2>&1
maybe_sudo curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-auditd/feat/install-configure/config/exfiltration.rules -o /etc/audit/rules.d/exfiltration.rules || error_message "Failed to copy exfiltration rules"

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

print_step_header 6 "Removing Journald Configuration"
remove_journald_config

print_step_header 7 "Verifying Installation"
# Validate installation
if maybe_sudo auditctl -l | grep -q "exfil"; then
    success_message "Exfiltration rules are loaded."
else
    warn_message "Exfiltration rules do not appear to be loaded."
fi

success_message "Auditd installation and configuration complete!"
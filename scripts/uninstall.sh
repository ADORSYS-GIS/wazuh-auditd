#!/bin/sh

# Set shell options
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Variables
LOG_LEVEL=${LOG_LEVEL:-INFO}

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

print_step_header 4 "Removing Auditd Packages"
info_message "Removing auditd packages..."
maybe_sudo apt remove auditd audispd-plugins -y > /dev/null 2>&1 || warn_message "Failed to remove auditd packages"
maybe_sudo apt autoremove -y > /dev/null 2>&1 || warn_message "Failed to auto-remove dependencies"

print_step_header 5 "Cleaning Up"
info_message "Cleaning up audit logs..."
maybe_sudo rm -f /var/log/audit/audit.log > /dev/null 2>&1 || warn_message "Failed to remove audit logs"

success_message "Auditd uninstallation complete!"
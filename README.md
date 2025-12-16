# Wazuh Auditd Integration

This repository contains scripts to install and configure auditd with exfiltration detection rules for integration with Wazuh endpoint security platform. Auditd is the Linux audit daemon that monitors system calls and logs security-relevant events.

## Prerequisites

1. Linux distribution
2. Administrator/sudo privileges
3. Internet connectivity to download packages
4. Wazuh agent installed on the system

## Installation

To install auditd:

1. Open Terminal.
2. Download and execute the installation script
   ```bash
   curl -sL 'https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-santa/main/scripts/install.sh' | sudo bash
   ```

This will:
- Install auditd and audispd-plugins packages (if not already installed)
- Copy exfiltration detection rules to `/etc/audit/rules.d/` (if not already present)
- Enable and start the auditd service
- Load audit rules for monitoring data exfiltration attempts
- Restart auditd service to apply all configurations

## Uninstallation

To uninstall auditd:

1. Open Terminal.
2. Execute the uninstallation script:
   ```bash
   curl -sL 'https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-santa/main/scripts/uninstall.sh' | sudo bash
   ```

This will:
- Stop the auditd service
- Remove exfiltration rules
- Disable the auditd service
- Remove auditd packages
- Clean up audit log files

## Configuration

The exfiltration rules monitor execution of common data exfiltration tools:
- curl
- wget
- nc (netcat)
- scp
- rsync
- sftp
- ftp
- python/python3
- perl
- ssh

These rules are configured in `config/exfiltration.rules` and are loaded into auditd during installation.

## Troubleshooting

1. **Permission Errors**: All commands must be run with sudo privileges.

2. **Auditd Not Logging**: Verify the log file exists and has proper permissions:
   ```bash
   sudo ls -la /var/log/audit/audit.log
   ```

3. **Rules Not Loaded**: Check if rules are loaded properly:
   ```bash
   sudo auditctl -l
   ```

4. **Service Not Starting**: Check service status and logs:
   ```bash
   sudo systemctl status auditd
   sudo journalctl -u auditd
   ```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Resources

- [Linux Audit Documentation](https://linux-audit.com/)
- [Auditd Manual](https://man7.org/linux/man-pages/man8/auditd.8.html)
- [Wazuh Documentation](https://documentation.wazuh.com/)
# SecureME Configuration Options

## Command Line Parameters

🔌 `--ssh-port PORT` - Set SSH port (default: 1337)

🚫 `--system-ipv6-disable` - Disable IPv6 via GRUB (requires reboot)  

⚡ `--all` - Run all hardening except AIDE, IPv6 GRUB disable, and VirtualBox

🛡️ `--aide` - Install and configure AIDE file integrity monitoring

📦 `--virtualbox` - Install VirtualBox virtualization

🎯 `--max-all` - Install everything including VirtualBox and AIDE

## Key Features

🔍 **Automatic System Detection** - Works with both systemd and legacy init systems

🌐 **Network Privacy** - DNS over TLS, Tor integration, MAC randomization

📊 **Comprehensive Monitoring** - File integrity, system auditing, intrusion detection

🔒 **Secure Communications** - Hardened SSH, encrypted messaging apps

🔐 **Application Security** - AppArmor profiles, Firejail sandboxing

⚙️ **Kernel Hardening** - Security parameters, vulnerability mitigations

🕵️ **Privacy Protection** - History wiping, timezone anonymization, anonymous hostname

## Requirements

🐧 Linux system with apt package manager (Debian/Ubuntu-based)

👑 Root privileges

🌍 Internet connection for package downloads

💾 Minimum 2GB free disk space for full installation

## Post-Installation

SecureME provides a comprehensive summary including:

📋 Complete list of installed packages

🔧 Network services and port configurations

📖 Security tools usage instructions

📁 Configuration file locations

✅ Recommended post-installation security checks

## ⚠️ Security Notice

SecureME makes significant system changes including firewall rules, service configurations, and kernel parameters. Review the code and test in a non-production environment before deployment. Some changes may require system reboot to take full effect.

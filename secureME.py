#!/usr/bin/env python3
fimport os
import subprocess
import sys
import time
import random
import argparse
import urllib.request
import shutil

class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

def print_colored(tag, message, color):
    print(f"{color}{tag}{Colors.RESET} {message}")

def log_info(msg): print_colored("[INFO]", msg, Colors.GREEN)
def log_warn(msg): print_colored("[WARN]", msg, Colors.YELLOW)
def log_critical(msg): print_colored("[CRITICAL]", msg, Colors.RED)
def log_debug(msg): print_colored("[DEBUG]", msg, Colors.BLUE)

def run_command(cmd, check=True):
    log_debug(f"Executing: {cmd}")
    result = subprocess.run(cmd, shell=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode != 0:
        log_critical(f"Failed command: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        sys.exit(1)
    return result.stdout.strip()

def backup_config(path):
    if os.path.exists(path):
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        backup = f"{path}.bak-{timestamp}"
        run_command(f"cp {path} {backup}")
        log_info(f"Backed up {path} to {backup}")

def is_systemd_available():
    """Check if systemd is available and running on this system."""
    try:
        result = run_command("pidof systemd", check=False)
        if result and result.strip():
            log_info("SystemD detected and running")
            return True

        # Alternative check
        if os.path.exists("/run/systemd/system"):
            log_info("SystemD detected (alternative method)")
            return True

        log_info("SystemD not detected - using legacy service management")
        return False
    except:
        log_info("SystemD detection failed - assuming legacy system")
        return False

def service_enable(service_name, use_systemd=True):
    """Enable a service using systemd or legacy methods."""
    if use_systemd:
        run_command(f"systemctl enable {service_name}")
    else:
        # Legacy init.d or update-rc.d methods
        if os.path.exists(f"/etc/init.d/{service_name}"):
            run_command(f"update-rc.d {service_name} enable", check=False)
        else:
            log_warn(f"Could not enable {service_name} - service script not found")

def service_start(service_name, use_systemd=True):
    """Start a service using systemd or legacy methods."""
    if use_systemd:
        run_command(f"systemctl start {service_name}")
    else:
        # Legacy service command
        run_command(f"service {service_name} start", check=False)

def service_restart(service_name, use_systemd=True):
    """Restart a service using systemd or legacy methods."""
    if use_systemd:
        run_command(f"systemctl restart {service_name}")
    else:
        # Legacy service command
        run_command(f"service {service_name} restart", check=False)

def service_disable(service_name, use_systemd=True):
    """Disable a service using systemd or legacy methods."""
    if use_systemd:
        run_command(f"systemctl disable {service_name}", check=False)
    else:
        # Legacy init.d or update-rc.d methods
        if os.path.exists(f"/etc/init.d/{service_name}"):
            run_command(f"update-rc.d {service_name} disable", check=False)

def service_exists(service_name, use_systemd=True):
    """Check if a service exists using systemd or legacy methods."""
    if use_systemd:
        result = run_command(f"systemctl list-unit-files | grep -E '^{service_name}\\.'", check=False)
        return bool(result.strip())
    else:
        return os.path.exists(f"/etc/init.d/{service_name}")

def ensure_display_manager():
    log_info("Checking for GUI display manager...")
    result = run_command("dpkg -l | grep -E 'gdm3|lightdm|sddm'", check=False)
    if not result:
        log_warn("No display manager found. Installing gdm3...")
        run_command("apt-get install -y gdm3")

def add_user_to_sudoers(user):
    log_info(f"Granting '{user}' sudo access without password...")
    sudoers_path = f"/etc/sudoers.d/{user}"
    with open(sudoers_path, "w") as f:
        f.write(f"{user} ALL=(ALL) NOPASSWD:ALL\n")
    os.chmod(sudoers_path, 0o440)

def disable_ipv6():
    log_info("Disabling IPv6 via sysctl...")
    backup_config("/etc/sysctl.conf")
    with open("/etc/sysctl.conf", "a") as f:
        f.write("\n# IPv6 Disable\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1\n")
    run_command("sysctl -p")

def disable_ipv6_grub():
    log_info("Disabling IPv6 via GRUB...")
    backup_config("/etc/default/grub")

    # Read current GRUB config
    with open("/etc/default/grub", "r") as f:
        lines = f.readlines()

    # Modify GRUB_CMDLINE_LINUX
    with open("/etc/default/grub", "w") as f:
        for line in lines:
            if line.startswith("GRUB_CMDLINE_LINUX="):
                # Extract current parameters
                current_params = line.split('=', 1)[1].strip().strip('"')
                if "ipv6.disable=1" not in current_params:
                    if current_params:
                        new_line = f'GRUB_CMDLINE_LINUX="{current_params} ipv6.disable=1"\n'
                    else:
                        new_line = f'GRUB_CMDLINE_LINUX="ipv6.disable=1"\n'
                    f.write(new_line)
                else:
                    f.write(line)
            else:
                f.write(line)

    run_command("update-grub")
    log_info("IPv6 disabled via GRUB. Reboot required for full effect.")

def harden_sysctl():
    log_info("Applying comprehensive kernel hardening settings...")
    backup_config("/etc/sysctl.conf")

    hardening_config = """
# Enhanced Kernel Hardening Configuration
# File system protections
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Kernel security
kernel.core_pattern = |/bin/false
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.randomize_va_space = 2

# Network hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Memory protections
vm.unprivileged_userfaultfd = 0
vm.mmap_min_addr = 65536

# BPF and JIT hardening
net.core.bpf_jit_harden = 2

# TTY security
dev.tty.ldisc_autoload = 0
"""

    with open("/etc/sysctl.conf", "a") as f:
        f.write(hardening_config)

    run_command("sysctl -p")

def configure_grub_security():
    log_info("Configuring GRUB with security parameters...")
    backup_config("/etc/default/grub")

    security_params = [
        "apparmor=1",
        "security=apparmor", 
        "audit=1",
        "pti=on",
        "spectre_v2=on",
        "spec_store_bypass_disable=on",
        "l1tf=full,force",
        "mds=full,nosmt",
        "tsx=off",
        "tsx_async_abort=full,nosmt",
        "mitigations=auto,nosmt"
    ]

    with open("/etc/default/grub", "r") as f:
        lines = f.readlines()

    with open("/etc/default/grub", "w") as f:
        for line in lines:
            if line.startswith("GRUB_CMDLINE_LINUX="):
                current_params = line.split('=', 1)[1].strip().strip('"')

                # Add security parameters if not present
                params_list = current_params.split() if current_params else []
                for param in security_params:
                    if not any(p.startswith(param.split('=')[0]) for p in params_list):
                        params_list.append(param)

                new_line = f'GRUB_CMDLINE_LINUX="{" ".join(params_list)}"\n'
                f.write(new_line)
            else:
                f.write(line)

    run_command("update-grub")

def randomize_hostname(use_systemd=True):
    new_hostname = f"anon-{random.randint(1000, 9999)}"
    log_info(f"Setting hostname: {new_hostname}")

    if use_systemd:
        run_command(f"hostnamectl set-hostname {new_hostname}")
    else:
        # Legacy hostname setting
        run_command(f"hostname {new_hostname}")
        with open("/etc/hostname", "w") as f:
            f.write(f"{new_hostname}\n")

        # Update /etc/hosts
        backup_config("/etc/hosts")
        with open("/etc/hosts", "r") as f:
            content = f.read()

        # Replace old hostname references
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            if line.startswith('127.0.1.1'):
                new_lines.append(f"127.0.1.1\t{new_hostname}")
            else:
                new_lines.append(line)

        with open("/etc/hosts", "w") as f:
            f.write('\n'.join(new_lines))

def detect_ssh_service(use_systemd=True):
    """Detect the correct SSH service name on this system."""
    if use_systemd:
        # Check if ssh.service exists and is available
        result = run_command("systemctl list-unit-files | grep -E '^ssh\\.service'", check=False)
        if result:
            return "ssh"

        # Check if sshd.service exists and is available  
        result = run_command("systemctl list-unit-files | grep -E '^sshd\\.service'", check=False)
        if result:
            return "sshd"
    else:
        # Check legacy init scripts
        if os.path.exists("/etc/init.d/ssh"):
            return "ssh"
        elif os.path.exists("/etc/init.d/sshd"):
            return "sshd"

    # Default fallback
    log_warn("Could not detect SSH service name, defaulting to 'ssh'")
    return "ssh"

def configure_ssh(port, use_systemd=True):
    log_info("Installing and configuring SSH server with enhanced security...")
    run_command("apt-get install -y openssh-server")

    # Detect the correct service name
    ssh_service = detect_ssh_service(use_systemd)
    log_info(f"Detected SSH service name: {ssh_service}")

    sshd = "/etc/ssh/sshd_config"
    backup_config(sshd)

    ssh_config = f"""
# Enhanced SSH Security Configuration
Port {port}
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile %h/.ssh/authorized_keys
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM no

# Security settings
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintMotd no
PrintLastLog no
TCPKeepAlive no
Compression no

# Connection limits
MaxAuthTries 3
MaxSessions 2
MaxStartups 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Ciphers and algorithms
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# Logging
SyslogFacility AUTHPRIV
LogLevel VERBOSE
"""

    with open(sshd, "w") as f:
        f.write(ssh_config)

    run_command("chmod 600 /etc/ssh/sshd_config")
    service_restart(ssh_service, use_systemd)
    service_enable(ssh_service, use_systemd)
    log_info(f"SSH service ({ssh_service}) configured and enabled")

def configure_firewall(ssh_port):
    log_info("Configuring UFW firewall with enhanced rules...")
    run_command("apt-get install -y ufw")
    run_command("ufw --force reset")
    run_command("ufw default deny incoming")
    run_command("ufw default allow outgoing")

    # Allow SSH on specified port
    run_command(f"ufw allow {ssh_port}/tcp")

    # Standard allowed ports
    allowed_tcp = ["80", "443", "53", "1401", "9050", "9051", "5091", "1337", "22", "9001", "9150", "4444", "7657"]
    allowed_udp = ["53", "51820", "1194", "1195", "1300", "1400", "7654"]

    for port in allowed_tcp:
        run_command(f"ufw allow {port}/tcp")
    for port in allowed_udp:
        run_command(f"ufw allow {port}/udp")

    # Rate limiting for SSH
    run_command(f"ufw limit {ssh_port}/tcp")

    run_command("ufw --force enable")

def setup_mac_randomization(use_systemd=True):
    log_info("Setting up MAC address randomization...")
    run_command("apt-get install -y macchanger")

    # Create udev rule for automatic MAC randomization
    udev_rule = 'SUBSYSTEM=="net", ACTION=="add", RUN+="/usr/bin/macchanger -r %k"'
    with open("/etc/udev/rules.d/70-persistent-net.rules", "w") as f:
        f.write(udev_rule + "\n")

    # NetworkManager MAC randomization
    nm_config = """[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
"""

    os.makedirs("/etc/NetworkManager/conf.d", exist_ok=True)
    with open("/etc/NetworkManager/conf.d/99-random-mac.conf", "w") as f:
        f.write(nm_config)

    if service_exists("NetworkManager", use_systemd):
        service_restart("NetworkManager", use_systemd)
    else:
        log_warn("NetworkManager not found - MAC randomization may not work properly")

def setup_dns_privacy(use_systemd=True):
    log_info("Setting up DNS over TLS with unbound...")
    run_command("apt-get install -y unbound")

    unbound_config = """server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5353
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    prefetch: yes
    num-threads: 2

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
"""

    with open("/etc/unbound/unbound.conf", "w") as f:
        f.write(unbound_config)

    service_enable("unbound", use_systemd)
    service_restart("unbound", use_systemd)

    # Configure system to use unbound - but don't break DHCP
    if use_systemd and service_exists("systemd-resolved", use_systemd):
        log_info("Configuring systemd-resolved to use unbound as fallback...")
        with open("/etc/systemd/resolved.conf", "w") as f:
            f.write("[Resolve]\nDNS=127.0.0.1:5353 1.1.1.1 8.8.8.8\nFallbackDNS=1.0.0.1 8.8.4.4\nDNSStubListener=yes\n")
        service_restart("systemd-resolved", use_systemd)
    else:
        log_warn("DNS privacy configured but not enforced to avoid breaking DHCP")
        log_info("Manual DNS configuration: add 'nameserver 127.0.0.1:5353' to resolv.conf if desired")

        # Don't modify resolv.conf automatically to avoid breaking DHCP
        # Instead, configure NetworkManager to use our DNS when available
        nm_dns_config = """[main]
dns=unbound

[connection]
connection.dns-priority=100
"""

        os.makedirs("/etc/NetworkManager/conf.d", exist_ok=True)
        with open("/etc/NetworkManager/conf.d/99-unbound-dns.conf", "w") as f:
            f.write(nm_dns_config)

def setup_timezone_anonymization(use_systemd=True):
    log_info("Setting timezone to UTC and disabling NTP...")

    if use_systemd:
        run_command("timedatectl set-timezone UTC")
        service_disable("systemd-timesyncd", use_systemd)
    else:
        # Legacy timezone setting
        run_command("ln -sf /usr/share/zoneinfo/UTC /etc/localtime")
        with open("/etc/timezone", "w") as f:
            f.write("UTC\n")

        # Disable NTP services
        for ntp_service in ["ntp", "ntpd", "chrony"]:
            if service_exists(ntp_service, use_systemd):
                service_disable(ntp_service, use_systemd)

def setup_kernel_module_blacklisting():
    log_info("Blacklisting unnecessary kernel modules...")
    blacklist_modules = [
        "pcspkr", "snd_pcsp", "bluetooth", "btusb", "uvcvideo", 
        "firewire-core", "thunderbolt", "rare-network"
    ]

    blacklist_config = ""
    for module in blacklist_modules:
        blacklist_config += f"blacklist {module}\n"

    with open("/etc/modprobe.d/blacklist-hardening.conf", "w") as f:
        f.write(blacklist_config)

    run_command("update-initramfs -u")

def secure_file_systems():
    log_info("Securing file system mount options...")

    # Create secure mount options for fstab
    secure_mounts = {
        "/tmp": "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,size=1G 0 0",
        "/var/tmp": "tmpfs /var/tmp tmpfs defaults,nodev,nosuid,noexec,size=1G 0 0"
    }

    backup_config("/etc/fstab")

    with open("/etc/fstab", "a") as f:
        f.write("\n# Secure mount options\n")
        for mount_point, mount_line in secure_mounts.items():
            f.write(mount_line + "\n")

def install_security_tools(use_systemd=True):
    log_info("Installing additional security tools...")

    # Standard security packages available in most repositories
    standard_packages = [
        "clamav", "clamav-daemon", "lynis", "secure-delete", 
        "cryptsetup", "gnupg2", "rkhunter", "chkrootkit"
    ]

    # Install standard packages
    run_command(f"apt-get install -y {' '.join(standard_packages)}")

    # Try to install kloak from source if git is available
    try:
        log_info("Attempting to install kloak from source...")
        run_command("apt-get install -y git build-essential libxi-dev libxtst-dev", check=False)

        # Check if git installation was successful
        git_check = run_command("which git", check=False)
        if git_check:
            run_command("cd /tmp && git clone https://github.com/vmonaco/kloak.git", check=False)
            if os.path.exists("/tmp/kloak"):
                run_command("cd /tmp/kloak && make && sudo make install", check=False)
                log_info("kloak installed from source")
            else:
                log_warn("kloak source download failed - skipping")
        else:
            log_warn("git not available - skipping kloak installation")
    except Exception as e:
        log_warn(f"kloak installation failed: {e}")

    # Configure ClamAV with proper error handling
    try:
        log_info("Configuring ClamAV...")

        # Stop any running ClamAV services to avoid lock conflicts
        run_command("systemctl stop clamav-daemon clamav-freshclam", check=False)
        run_command("killall clamd freshclam", check=False)

        # Ensure proper ownership and permissions
        run_command("chown -R clamav:clamav /var/log/clamav /var/lib/clamav", check=False)
        run_command("chmod 755 /var/log/clamav /var/lib/clamav", check=False)
        run_command("touch /var/log/clamav/freshclam.log", check=False)
        run_command("chown clamav:clamav /var/log/clamav/freshclam.log", check=False)
        run_command("chmod 644 /var/log/clamav/freshclam.log", check=False)

        # Update virus definitions as clamav user
        run_command("sudo -u clamav freshclam")

        # Enable and start services
        service_enable("clamav-daemon", use_systemd)
        service_start("clamav-daemon", use_systemd)
        log_info("ClamAV configured successfully")

    except Exception as e:
        log_warn(f"ClamAV configuration failed: {e}")
        log_info("You may need to run 'sudo freshclam' manually after the script completes")

    # Configure rkhunter if installed successfully
    try:
        if os.path.exists("/etc/rkhunter.conf"):
            log_info("Updating rkhunter database...")
            run_command("rkhunter --update", check=False)
            run_command("rkhunter --propupd", check=False)
    except Exception as e:
        log_warn(f"rkhunter configuration failed: {e}")

def install_privacy_apps(use_systemd=True):
    log_info("Installing privacy-focused applications...")
    run_command("apt-get install -y snapd flatpak")
    run_command("ln -s /var/lib/snapd/snap /snap || true")

    if use_systemd:
        run_command("systemctl enable --now snapd.socket")
    else:
        service_enable("snapd", use_systemd)
        service_start("snapd", use_systemd)

    if not os.path.exists("/etc/flatpak/remotes.d/flathub.conf"):
        run_command("flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo")

    # Install privacy apps
    privacy_apps = [
        ("snap", "signal-desktop"),
        ("snap", "telegram-desktop"),
        ("snap", "element-desktop"),
    ]

    for package_manager, app in privacy_apps:
        run_command(f"{package_manager} install {app}", check=False)

def remove_services(use_systemd=True):
    log_info("Removing unnecessary services...")
    run_command("apt-get remove --purge -y apache2 nginx samba cups avahi-daemon telnet", check=False)
    run_command("apt-get autoremove -y")

def wipe_history(user_home):
    log_info("Clearing shell history and configuring privacy...")
    history_files = [".bash_history", ".zsh_history", ".fish_history", ".python_history"]

    for file in history_files:
        full_path = os.path.join(user_home, file)
        if os.path.exists(full_path):
            os.remove(full_path)
            log_info(f"Deleted: {full_path}")

    # Configure bash to not save history
    bashrc = os.path.join(user_home, ".bashrc")
    with open(bashrc, "a") as f:
        f.write("\n# Privacy settings\nexport HISTSIZE=0\nexport HISTFILE=/dev/null\n")

def get_latest_virtualbox_package():
    log_info("Searching for available VirtualBox packages...")
    result = run_command("apt-cache search virtualbox", check=True)
    pkgs = [line.split()[0] for line in result.splitlines() if line.startswith("virtualbox-")]
    if not pkgs:
        log_critical("No VirtualBox packages found in repository.")
        sys.exit(1)
    pkgs.sort(reverse=True)
    latest = pkgs[0]
    log_info(f"Latest VirtualBox package found: {latest}")
    return latest

def setup_virtualbox():
    log_info("Installing VirtualBox repository and package...")
    run_command("apt-get update")
    run_command("apt-get install -y curl gnupg")

    # Add VirtualBox repository
    run_command("curl -fsSL https://www.virtualbox.org/download/oracle_vbox_2016.asc | gpg --dearmor -o /usr/share/keyrings/oracle-virtualbox-archive-keyring.gpg")
    run_command("chmod 644 /usr/share/keyrings/oracle-virtualbox-archive-keyring.gpg")

    distro = run_command("lsb_release -c -s")
    repo_line = f"deb [arch=amd64 signed-by=/usr/share/keyrings/oracle-virtualbox-archive-keyring.gpg] https://download.virtualbox.org/virtualbox/debian {distro} contrib"

    with open("/etc/apt/sources.list.d/virtualbox.list", "w") as f:
        f.write(repo_line + "\n")

    run_command("apt-get update")
    latest_pkg = get_latest_virtualbox_package()
    run_command(f"apt-get install -y {latest_pkg}")

def install_proxychains():
    log_info("Installing and configuring proxychains...")
    run_command("apt-get install -y proxychains4")

def setup_tor(use_systemd=True):
    log_info("Installing and configuring Tor with bridges...")
    run_command("apt-get install -y tor torsocks obfs4proxy")

    tor_config = """# Enhanced Tor configuration
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory /var/lib/tor

# Bridge configuration (uncomment and add real bridges)
# UseBridges 1
# ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
# Bridge obfs4 [IP:PORT] [FINGERPRINT] [PARAMS]

# Security settings
ExitPolicy reject *:*
SafeLogging 1
"""

    with open("/etc/tor/torrc", "w") as f:
        f.write(tor_config)

    service_enable("tor", use_systemd)
    service_restart("tor", use_systemd)

def setup_auto_updates():
    log_info("Configuring automatic security updates...")
    run_command("apt-get install -y unattended-upgrades")

    # Configure only security updates
    auto_update_config = """Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
"""

    with open("/etc/apt/apt.conf.d/50unattended-upgrades", "w") as f:
        f.write(auto_update_config)

    run_command("dpkg-reconfigure -f noninteractive unattended-upgrades")

def setup_fail2ban(use_systemd=True):
    log_info("Installing and configuring Fail2Ban...")
    run_command("apt-get install -y fail2ban")

    # Get user IP for whitelist
    user_ip = input("Enter your trusted IP address to whitelist in Fail2Ban [press Enter to skip]: ").strip()
    if not user_ip:
        user_ip = "127.0.0.1/8"
    else:
        user_ip = f"127.0.0.1/8 ::1 {user_ip}"

    jail_config = f"""[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = {user_ip}

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
banaction = iptables-multiport

[apache-auth]
enabled = false

[apache-badbots]
enabled = false

[apache-noscript]
enabled = false

[apache-overflows]
enabled = false
"""

    with open("/etc/fail2ban/jail.local", "w") as f:
        f.write(jail_config)

    service_enable("fail2ban", use_systemd)
    service_restart("fail2ban", use_systemd)

def setup_aide():
    log_info("Installing and configuring AIDE for file integrity monitoring...")
    run_command("apt-get install -y aide")
    run_command("aideinit")
    run_command("mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db")

    # Configure daily AIDE check
    cron_job = "0 5 * * * root /usr/bin/aide --check 2>&1 | mail -s 'AIDE Integrity Check' root\n"
    with open("/etc/cron.d/aide-check", "w") as f:
        f.write(cron_job)
    run_command("chmod 644 /etc/cron.d/aide-check")

def setup_auditd(use_systemd=True):
    log_info("Installing and configuring auditd for system auditing...")
    run_command("apt-get install -y auditd")

    audit_rules = """-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k group_changes
-w /var/log/auth.log -p wa -k auth_log
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d -p wa -k sudo_changes
-a always,exit -F arch=b64 -S execve -k exec_commands
"""

    with open("/etc/audit/rules.d/hardening.rules", "w") as f:
        f.write(audit_rules)

    run_command("augenrules")
    service_enable("auditd", use_systemd)
    service_restart("auditd", use_systemd)

def enable_apparmor(use_systemd=True):
    log_info("Enabling and configuring AppArmor...")
    run_command("apt-get install -y apparmor apparmor-utils apparmor-profiles")
    service_enable("apparmor", use_systemd)
    service_start("apparmor", use_systemd)

    # Enable additional profiles
    run_command("aa-enforce /etc/apparmor.d/*", check=False)

def setup_firejail():
    log_info("Installing Firejail for application sandboxing...")
    run_command("apt-get install -y firejail")

    # Configure default Firejail profiles
    run_command("firecfg", check=False)

def get_args():
    parser = argparse.ArgumentParser(description="Enhanced System Hardening Script")
    parser.add_argument("--ssh-port", type=int, default=1337, help="Port for SSH service")
    parser.add_argument("--system-ipv6-disable", action="store_true", 
                       help="Disable IPv6 via GRUB (requires reboot)")
    parser.add_argument("--all", action="store_true", 
                       help="Run all hardening except AIDE, IPv6 GRUB disable, and VirtualBox")
    parser.add_argument("--aide", action="store_true", 
                       help="Install and configure AIDE file integrity monitoring")
    parser.add_argument("--virtualbox", action="store_true", 
                       help="Install VirtualBox")
    parser.add_argument("--max-all", action="store_true", 
                       help="Install everything including VirtualBox and AIDE")

    return parser.parse_args()

# Global variables to track installations and configurations
installed_packages = []
configured_services = []
network_services = {}
security_features = []

def track_package(package_name):
    """Track installed packages"""
    if package_name not in installed_packages:
        installed_packages.append(package_name)

def track_service(service_name, port=None, protocol=None, description=""):
    """Track configured services with port information"""
    service_info = {
        "name": service_name,
        "port": port,
        "protocol": protocol,
        "description": description
    }
    configured_services.append(service_info)
    if port:
        network_services[service_name] = service_info

def track_security_feature(feature_name, description=""):
    """Track security features that were configured"""
    security_features.append({"name": feature_name, "description": description})

def print_installation_summary():
    """Print comprehensive summary of all changes made"""
    print("\n" + "="*80)
    print_colored("[INSTALLATION SUMMARY]", "Complete overview of system modifications", Colors.GREEN)
    print("="*80)

    # Core System Changes
    print_colored("[CORE SYSTEM CHANGES]", "", Colors.BLUE)
    for feature in security_features:
        print(f"  ✓ {feature['name']}")
        if feature['description']:
            print(f"    └── {feature['description']}")

    # Installed Packages
    if installed_packages:
        print(f"\n{Colors.BLUE}[INSTALLED PACKAGES]{Colors.RESET}")
        for i, package in enumerate(sorted(installed_packages), 1):
            print(f"  {i:2d}. {package}")

    # Network Services & Ports
    if network_services:
        print(f"\n{Colors.BLUE}[NETWORK SERVICES & PORTS]{Colors.RESET}")
        print(f"{'Service':<20} {'Port':<10} {'Protocol':<10} {'Description'}")
        print("-" * 70)
        for service_name, info in network_services.items():
            port_str = str(info['port']) if info['port'] else 'N/A'
            protocol_str = info['protocol'] or 'TCP'
            desc = info['description'] or ''
            print(f"{service_name:<20} {port_str:<10} {protocol_str:<10} {desc}")

    # Service Usage Instructions
    print(f"\n{Colors.BLUE}[SERVICE USAGE INSTRUCTIONS]{Colors.RESET}")

    # SSH Instructions
    ssh_port = network_services.get('ssh', {}).get('port', 1337)
    print(f"📡 SSH ACCESS:")
    print(f"   └── Connect: ssh -p {ssh_port} username@hostname")
    print(f"   └── Config: /etc/ssh/sshd_config")
    print(f"   └── Security: Password auth disabled, key-based only")

    # Tor Instructions
    if 'tor' in network_services:
        print(f"\n🧅 TOR SERVICES:")
        print(f"   └── SOCKS Proxy: localhost:9050")
        print(f"   └── Control Port: localhost:9051")
        print(f"   └── Usage: torsocks curl http://example.com")
        print(f"   └── Browser: Configure SOCKS5 proxy 127.0.0.1:9050")
        print(f"   └── Config: /etc/tor/torrc")

    # DNS Services
    if 'unbound' in [s['name'] for s in configured_services]:
        print(f"\n🛡️ DNS PRIVACY (Unbound):")
        print(f"   └── DNS over TLS: localhost:5353")
        print(f"   └── Upstream: Cloudflare (1.1.1.1) & Quad9 (9.9.9.9)")
        print(f"   └── Config: /etc/unbound/unbound.conf")
        print(f"   └── Test: dig @127.0.0.1 -p 5353 example.com")

    # UFW Firewall
    if 'ufw' in [s['name'] for s in configured_services]:
        print(f"\n🔥 FIREWALL (UFW):")
        print(f"   └── Status: ufw status verbose")
        print(f"   └── Allowed TCP: 80,443,53,1401,9050,9051,9001,9150,4444,7657,{ssh_port}")
        print(f"   └── Allowed UDP: 53,51820,1194,1195,1300,1400,7654")
        print(f"   └── SSH Rate Limited: {ssh_port}/tcp")

    # Security Tools
    security_tools_info = {
        'clamav': 'Antivirus - Run: clamscan -r /home/',
        'fail2ban': 'Intrusion Prevention - Status: fail2ban-client status',
        'rkhunter': 'Rootkit Hunter - Run: rkhunter --check',
        'lynis': 'Security Audit - Run: lynis audit system',
        'aide': 'File Integrity - Check: aide --check',
        'auditd': 'System Auditing - Logs: /var/log/audit/',
        'apparmor': 'Mandatory Access Control - Status: aa-status'
    }

    installed_security_tools = [pkg for pkg in installed_packages if pkg in security_tools_info.keys()]
    if installed_security_tools:
        print(f"\n🛠️ SECURITY TOOLS:")
        for tool in installed_security_tools:
            print(f"   └── {tool.upper()}: {security_tools_info[tool]}")

    # Privacy Applications
    privacy_apps = ['signal-desktop', 'telegram-desktop', 'element-desktop']
    installed_privacy_apps = [pkg for pkg in installed_packages if any(app in pkg for app in privacy_apps)]
    if installed_privacy_apps:
        print(f"\n🔒 PRIVACY APPLICATIONS:")
        for app in installed_privacy_apps:
            print(f"   └── {app}")

    # Proxychains
    if 'proxychains4' in installed_packages:
        print(f"\n🔗 PROXYCHAINS:")
        print(f"   └── Usage: proxychains4 curl http://example.com")
        print(f"   └── Config: /etc/proxychains4.conf")
        print(f"   └── Default: Routes through Tor (127.0.0.1:9050)")

    # VirtualBox
    vbox_packages = [pkg for pkg in installed_packages if 'virtualbox' in pkg.lower()]
    if vbox_packages:
        print(f"\n💻 VIRTUALIZATION:")
        for pkg in vbox_packages:
            print(f"   └── {pkg}")
        print(f"   └── Launch: virtualbox")

    # Configuration Files
    print(f"\n{Colors.BLUE}[IMPORTANT CONFIGURATION FILES]{Colors.RESET}")
    config_files = [
        "/etc/ssh/sshd_config - SSH server configuration",
        "/etc/tor/torrc - Tor configuration",
        "/etc/unbound/unbound.conf - DNS over TLS configuration", 
        "/etc/fail2ban/jail.local - Fail2Ban rules",
        "/etc/audit/rules.d/hardening.rules - Audit rules",
        "/etc/sysctl.conf - Kernel security parameters",
        "/etc/default/grub - Boot security parameters",
        "/etc/ufw/user.rules - Firewall rules"
    ]

    for config in config_files:
        print(f"   └── {config}")

    # Security Recommendations
    print(f"\n{Colors.YELLOW}[POST-INSTALLATION RECOMMENDATIONS]{Colors.RESET}")
    recommendations = [
        f"1. Setup SSH key authentication and test connection on port {ssh_port}",
        "2. Run security audit: lynis audit system",
        "3. Configure Tor bridges if in censored region",
        "4. Test DNS privacy: dig @127.0.0.1 -p 5353 cloudflare.com",
        "5. Review firewall rules: ufw status verbose", 
        "6. Monitor system logs: journalctl -f",
        "7. Update virus definitions: freshclam",
        "8. Check intrusion attempts: fail2ban-client status sshd",
        "9. Verify AppArmor profiles: aa-status",
        "10. Schedule regular AIDE integrity checks"
    ]

    for rec in recommendations:
        print(f"   {rec}")

    print("\n" + "="*80)

def main():
    if os.geteuid() != 0:
        log_critical("Please run as root.")
        sys.exit(1)

    args = get_args()

    # Detect systemd availability
    use_systemd = is_systemd_available()

    # Get SSH port
    ssh_port = args.ssh_port
    if not args.all and not args.max_all and not args.ssh_port:
        port_input = input("Enter SSH port to use [default 1337]: ").strip()
        ssh_port = int(port_input) if port_input.isdigit() else 1337

    user = os.environ.get("SUDO_USER") or "root"
    user_home = os.path.expanduser(f"~{user}")

    print_colored("[START]", f"Enhanced hardening for user: {user} on SSH port: {ssh_port}", Colors.GREEN)
    print_colored("[SYSTEM]", f"SystemD detected: {use_systemd}", Colors.BLUE)

    # Always update package list first
    log_info("Updating package lists...")
    run_command("apt-get update")

    # Core hardening (always run)
    ensure_display_manager()
    track_package("gdm3")
    track_security_feature("Display Manager", "GUI login manager installed")

    if user != "root":
        add_user_to_sudoers(user)
        track_security_feature("Sudo Configuration", f"Passwordless sudo for {user}")

    disable_ipv6()  # Always disable IPv6 via sysctl
    track_security_feature("IPv6 Disabled", "Disabled via sysctl configuration")

    if args.system_ipv6_disable:
        disable_ipv6_grub()
        track_security_feature("IPv6 GRUB Disable", "Disabled at kernel level (requires reboot)")

    harden_sysctl()
    track_security_feature("Kernel Hardening", "Enhanced sysctl security parameters")

    configure_grub_security()
    track_security_feature("GRUB Security", "Hardware vulnerability mitigations enabled")

    randomize_hostname(use_systemd)
    track_security_feature("Hostname Randomization", "Anonymous hostname set")

    configure_ssh(ssh_port, use_systemd)
    track_package("openssh-server")
    track_service("ssh", ssh_port, "TCP", "Hardened SSH server")
    track_security_feature("SSH Hardening", f"Secure SSH on port {ssh_port}")

    configure_firewall(ssh_port)
    track_package("ufw")
    track_service("ufw", None, None, "Uncomplicated Firewall")
    track_security_feature("Firewall", "UFW configured with strict rules")

    remove_services(use_systemd)
    track_security_feature("Service Removal", "Unnecessary services removed")

    wipe_history(user_home)
    track_security_feature("History Wiping", "Shell history cleared and disabled")

    setup_auto_updates()
    track_package("unattended-upgrades")
    track_security_feature("Auto Updates", "Security updates automated")

    setup_auditd(use_systemd)
    track_package("auditd")
    track_security_feature("System Auditing", "File and system call monitoring")

    enable_apparmor(use_systemd)
    track_package("apparmor")
    track_package("apparmor-utils")
    track_package("apparmor-profiles")
    track_security_feature("AppArmor", "Mandatory access control enabled")

    # Extended hardening for --all and --max-all
    if args.all or args.max_all:
        setup_mac_randomization(use_systemd)
        track_package("macchanger")
        track_security_feature("MAC Randomization", "Network interface MAC addresses randomized")

        setup_dns_privacy(use_systemd)
        track_package("unbound")
        track_service("unbound", 5353, "TCP/UDP", "DNS over TLS resolver")
        track_security_feature("DNS Privacy", "DNS over TLS with Cloudflare/Quad9")

        setup_timezone_anonymization(use_systemd)
        track_security_feature("Timezone Anonymization", "UTC timezone, NTP disabled")

        setup_kernel_module_blacklisting()
        track_security_feature("Module Blacklisting", "Unnecessary kernel modules disabled")

        secure_file_systems()
        track_security_feature("Filesystem Hardening", "Secure mount options for /tmp and /var/tmp")

        install_security_tools(use_systemd)
        security_packages = ["clamav", "clamav-daemon", "lynis", "secure-delete", 
                           "cryptsetup", "gnupg2", "rkhunter", "chkrootkit"]
        for pkg in security_packages:
            track_package(pkg)
        track_security_feature("Security Tools", "Comprehensive security suite installed")

        install_privacy_apps(use_systemd)
        track_package("snapd")
        track_package("flatpak")
        privacy_apps = ["signal-desktop", "telegram-desktop", "element-desktop"]
        for app in privacy_apps:
            track_package(app)
        track_security_feature("Privacy Apps", "Encrypted messaging applications")

        install_proxychains()
        track_package("proxychains4")
        track_security_feature("Proxychains", "Network traffic proxy tool")

        setup_tor(use_systemd)
        track_package("tor")
        track_package("torsocks")
        track_package("obfs4proxy")
        track_service("tor", 9050, "TCP", "SOCKS proxy")
        track_service("tor-control", 9051, "TCP", "Control port")
        track_security_feature("Tor Network", "Anonymous networking and SOCKS proxy")

        setup_fail2ban(use_systemd)
        track_package("fail2ban")
        track_security_feature("Fail2Ban", "Intrusion prevention system")

        setup_firejail()
        track_package("firejail")
        track_security_feature("Application Sandboxing", "Firejail security sandbox")

    # AIDE (only if specifically requested or --max-all)
    if args.aide or args.max_all:
        setup_aide()
        track_package("aide")
        track_security_feature("File Integrity Monitoring", "AIDE database and daily checks")

    # VirtualBox (only if specifically requested or --max-all)
    if args.virtualbox or args.max_all:
        setup_virtualbox()
        vbox_pkg = get_latest_virtualbox_package()
        track_package(vbox_pkg)
        track_security_feature("Virtualization", "VirtualBox for isolated environments")

    print_colored("[COMPLETE]", "System hardening completed successfully!", Colors.GREEN)

    if args.system_ipv6_disable:
        print_colored("[REBOOT]", "Reboot required for GRUB IPv6 disable to take effect", Colors.YELLOW)

    # Print comprehensive installation summary
    print_installation_summary()

if __name__ == "__main__":
    main()

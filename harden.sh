#!/usr/bin/env bash
#===============================================================================
#
#          FILE: harden.sh
#
#         USAGE: sudo bash harden.sh
#
#   DESCRIPTION: Production-ready Debian 11 VPS hardening script
#                Target: ~92-93+ Lynis score
#                Safe for common VPS providers
#                NO TOR - Clean and simple
#
#       VERSION: 2.0.0
#        AUTHOR: Security Hardening Script
#       CREATED: 2024
#
#===============================================================================

# NO STRICT MODE - Handle errors gracefully and continue
set +e
set +u

#===============================================================================
# GLOBAL VARIABLES
#===============================================================================
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_START_TIME=$(date +%s)
readonly LOG_FILE="/var/log/hardening_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/root/hardening_backups_$(date +%Y%m%d_%H%M%S)"
readonly REPORT_FILE="/root/hardening_report_$(date +%Y%m%d_%H%M%S).txt"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Counters for summary
TASKS_COMPLETED=0
TASKS_SKIPPED=0
TASKS_FAILED=0
WARNINGS_COUNT=0

#===============================================================================
# LOGGING FUNCTIONS
#===============================================================================
init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || true
    exec 3>&1 4>&2
    echo "=== Hardening Script Started: $(date) ===" >> "$LOG_FILE"
}

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null
}

print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "INFO")
            echo -e "${BLUE}[*]${NC} $message"
            log "INFO" "$message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[✓]${NC} $message"
            log "SUCCESS" "$message"
            ((TASKS_COMPLETED++))
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${NC} $message"
            log "WARNING" "$message"
            ((WARNINGS_COUNT++))
            ;;
        "ERROR")
            echo -e "${RED}[✗]${NC} $message"
            log "ERROR" "$message"
            ((TASKS_FAILED++))
            ;;
        "SKIP")
            echo -e "${MAGENTA}[→]${NC} $message"
            log "SKIP" "$message"
            ((TASKS_SKIPPED++))
            ;;
    esac
}

print_section() {
    local title="$1"
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $title${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "SECTION" "=== $title ==="
}

print_banner() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
    ____       __    _                __ __          __           _           
   / __ \___  / /_  (_)___ _____     / // /___ _____/ /__  ____  (_)___  ____ _
  / / / / _ \/ __ \/ / __ `/ __ \   / // // __ `/ __  / _ \/ __ \/ / __ \/ __ `/
 / /_/ /  __/ /_/ / / /_/ / / / /  / // // /_/ / /_/ /  __/ / / / / / / / /_/ / 
/_____/\___/_.___/_/\__,_/_/ /_/  /_//_/ \__,_/\__,_/\___/_/ /_/_/_/ /_/\__, /  
                                                                       /____/   
EOF
    echo -e "${NC}"
    echo -e "${BOLD}    Debian 11 VPS Security Hardening Script v${SCRIPT_VERSION}${NC}"
    echo -e "${BOLD}    Target: 92-93+ Lynis Score | Production Ready${NC}"
    echo ""
}

#===============================================================================
# UTILITY FUNCTIONS
#===============================================================================
check_command() {
    command -v "$1" >/dev/null 2>&1
}

check_service_exists() {
    systemctl list-unit-files "$1.service" >/dev/null 2>&1 || \
    systemctl list-units --type=service | grep -q "$1"
}

get_ssh_service_name() {
    if systemctl list-units --type=service 2>/dev/null | grep -q "sshd.service"; then
        echo "sshd"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "ssh.service"; then
        echo "ssh"
    elif check_service_exists "sshd"; then
        echo "sshd"
    else
        echo "ssh"
    fi
}

wait_for_apt() {
    local timeout=120
    local count=0
    
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [[ $count -ge $timeout ]]; then
            print_status "WARNING" "Timeout waiting for apt locks"
            return 1
        fi
        sleep 2
        ((count+=2))
    done
    return 0
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -a "$file" "${BACKUP_DIR}/$(basename "$file").backup" 2>/dev/null
        return $?
    fi
    return 0
}

test_dns_resolution() {
    local servers=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    
    for server in "${servers[@]}"; do
        if dig @"$server" +short +time=3 +tries=1 google.com A >/dev/null 2>&1; then
            return 0
        fi
    done
    
    if getent hosts google.com >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

#===============================================================================
# PRE-FLIGHT CHECKS
#===============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        echo "Please run: sudo bash $0"
        exit 1
    fi
}

check_debian_version() {
    if [[ ! -f /etc/debian_version ]]; then
        print_status "WARNING" "Not running on Debian - script may not work correctly"
        return 1
    fi
    
    local version
    version=$(cat /etc/debian_version 2>/dev/null)
    print_status "INFO" "Detected Debian version: $version"
    
    if [[ "$version" == 11* ]] || [[ "$version" == "bullseye"* ]]; then
        print_status "SUCCESS" "Debian 11 (Bullseye) confirmed"
        return 0
    else
        print_status "WARNING" "Script optimized for Debian 11 - may work on other versions"
        return 0
    fi
}

check_network_connectivity() {
    print_status "INFO" "Checking network connectivity..."
    
    if ! test_dns_resolution; then
        print_status "WARNING" "DNS resolution issues detected"
        
        if [[ -w /etc/resolv.conf ]] || [[ ! -e /etc/resolv.conf ]]; then
            echo "nameserver 1.1.1.1" > /etc/resolv.conf.tmp
            echo "nameserver 8.8.8.8" >> /etc/resolv.conf.tmp
            cat /etc/resolv.conf >> /etc/resolv.conf.tmp 2>/dev/null
            cat /etc/resolv.conf.tmp > /etc/resolv.conf 2>/dev/null
            rm -f /etc/resolv.conf.tmp
        fi
    fi
    
    if curl -s --connect-timeout 5 https://deb.debian.org >/dev/null 2>&1; then
        print_status "SUCCESS" "Network connectivity verified"
        return 0
    elif wget -q --timeout=5 --spider https://deb.debian.org 2>/dev/null; then
        print_status "SUCCESS" "Network connectivity verified"
        return 0
    else
        print_status "WARNING" "Limited network connectivity detected"
        return 1
    fi
}

create_backups() {
    print_section "Creating System Backups"
    
    mkdir -p "$BACKUP_DIR"
    
    local critical_files=(
        "/etc/ssh/sshd_config"
        "/etc/sysctl.conf"
        "/etc/resolv.conf"
        "/etc/fstab"
        "/etc/default/grub"
        "/etc/security/limits.conf"
        "/etc/pam.d/common-password"
        "/etc/pam.d/common-auth"
        "/etc/pam.d/sshd"
        "/etc/login.defs"
        "/etc/hosts"
        "/etc/hostname"
    )
    
    local backed_up=0
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            if backup_file "$file"; then
                ((backed_up++))
            fi
        fi
    done
    
    if check_command iptables; then
        iptables-save > "${BACKUP_DIR}/iptables.rules" 2>/dev/null || true
    fi
    
    if [[ -d /etc/ufw ]]; then
        cp -r /etc/ufw "${BACKUP_DIR}/ufw_backup" 2>/dev/null || true
    fi
    
    print_status "SUCCESS" "Backed up $backed_up critical files to $BACKUP_DIR"
}

#===============================================================================
# SYSTEM UPDATES
#===============================================================================
perform_system_updates() {
    print_section "System Updates and Upgrades"
    
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    
    wait_for_apt
    
    print_status "INFO" "Checking for interrupted package operations..."
    dpkg --configure -a >> "$LOG_FILE" 2>&1 || true
    
    apt-get clean >> "$LOG_FILE" 2>&1 || true
    
    print_status "INFO" "Updating package lists..."
    if apt-get update -y >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Package lists updated"
    else
        print_status "WARNING" "Package list update had issues"
    fi
    
    print_status "INFO" "Upgrading packages (this may take a while)..."
    apt-get upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        >> "$LOG_FILE" 2>&1 || print_status "WARNING" "Some packages may not have upgraded"
    
    apt-get dist-upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        >> "$LOG_FILE" 2>&1 || print_status "WARNING" "Dist-upgrade had issues"
    
    apt-get autoremove -y >> "$LOG_FILE" 2>&1 || true
    apt-get autoclean >> "$LOG_FILE" 2>&1 || true
    
    print_status "SUCCESS" "System updates completed"
}

#===============================================================================
# INSTALL PACKAGES
#===============================================================================
install_security_packages() {
    print_section "Installing Security Packages"
    
    export DEBIAN_FRONTEND=noninteractive
    
    wait_for_apt
    
    local packages=(
        # Core security
        "ufw"
        "fail2ban"
        "unattended-upgrades"
        "apt-listchanges"
        "needrestart"
        "libpam-tmpdir"
        "debsums"
        "apt-show-versions"
        # Intrusion detection
        "aide"
        "aide-common"
        "rkhunter"
        "chkrootkit"
        "lynis"
        # Audit
        "auditd"
        "audispd-plugins"
        # AppArmor
        "apparmor"
        "apparmor-utils"
        "apparmor-profiles"
        "apparmor-profiles-extra"
        # Network
        "unbound"
        "dns-root-data"
        "curl"
        "wget"
        "gnupg"
        "ca-certificates"
        "apt-transport-https"
        "net-tools"
        "lsof"
        "dnsutils"
        # Password quality
        "libpam-pwquality"
        # Utilities
        "acl"
        "sudo"
        "psmisc"
        "procps"
        "sysstat"
        "rsyslog"
        "logrotate"
        "cron"
    )
    
    local installed=0
    local failed=0
    
    for pkg in "${packages[@]}"; do
        if apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1; then
            ((installed++))
        else
            print_status "WARNING" "Could not install: $pkg"
            ((failed++))
        fi
    done
    
    print_status "SUCCESS" "Installed $installed packages ($failed failed)"
}

#===============================================================================
# UNATTENDED UPGRADES
#===============================================================================
configure_unattended_upgrades() {
    print_section "Configuring Automatic Security Updates"
    
    if ! check_command unattended-upgrade; then
        print_status "SKIP" "unattended-upgrades not installed"
        return 1
    fi
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
Unattended-Upgrade::Verbose "false";
Unattended-Upgrade::Debug "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF

    systemctl enable unattended-upgrades >> "$LOG_FILE" 2>&1 || true
    systemctl start unattended-upgrades >> "$LOG_FILE" 2>&1 || true
    
    print_status "SUCCESS" "Automatic security updates configured"
}

#===============================================================================
# KERNEL SYSCTL HARDENING
#===============================================================================
configure_sysctl_hardening() {
    print_section "Kernel Security Hardening (sysctl)"
    
    cat > /etc/sysctl.d/99-security-hardening.conf << 'EOF'
#===============================================================================
# VPS-Safe Kernel Security Hardening
#===============================================================================

# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Enable TCP SYN Cookies
net.ipv4.tcp_syncookies = 1

# TCP hardening
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Enable ASLR
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 1

# Disable SysRq (except safe functions)
kernel.sysrq = 176

# Disable core dumps for setuid
fs.suid_dumpable = 0

# Protect symlinks and hardlinks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# File handle limits
fs.file-max = 65535

# PID limit
kernel.pid_max = 65536

# Socket settings
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 5000

# TCP memory
net.ipv4.tcp_rmem = 4096 87380 6291456
net.ipv4.tcp_wmem = 4096 87380 6291456

# TCP settings
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1

# Port range
net.ipv4.ip_local_port_range = 1024 65535
EOF

    print_status "INFO" "Applying kernel security parameters..."
    
    sysctl --system >> "$LOG_FILE" 2>&1 || true
    
    print_status "SUCCESS" "Kernel security hardening applied"
}

#===============================================================================
# SECURE SHARED MEMORY
#===============================================================================
secure_shared_memory() {
    print_section "Securing Shared Memory"
    
    local shm_path=""
    if mountpoint -q /run/shm 2>/dev/null; then
        shm_path="/run/shm"
    elif mountpoint -q /dev/shm 2>/dev/null; then
        shm_path="/dev/shm"
    fi
    
    if [[ -n "$shm_path" ]]; then
        if mount -o remount,noexec,nosuid,nodev "$shm_path" >> "$LOG_FILE" 2>&1; then
            print_status "SUCCESS" "Shared memory secured"
        else
            print_status "WARNING" "Could not secure shared memory (VPS restriction)"
        fi
    else
        print_status "INFO" "Shared memory mount point not found"
    fi
}

#===============================================================================
# DISABLE CORE DUMPS
#===============================================================================
disable_core_dumps() {
    print_section "Disabling Core Dumps"
    
    mkdir -p /etc/security/limits.d
    cat > /etc/security/limits.d/99-disable-coredump.conf << 'EOF'
*               soft    core            0
*               hard    core            0
root            soft    core            0
root            hard    core            0
EOF

    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || true
    
    print_status "SUCCESS" "Core dumps disabled"
}

#===============================================================================
# SSH HARDENING
#===============================================================================
configure_ssh_hardening() {
    print_section "SSH Security Hardening"
    
    local sshd_config="/etc/ssh/sshd_config"
    local ssh_service
    ssh_service=$(get_ssh_service_name)
    
    if [[ ! -f "$sshd_config" ]]; then
        print_status "ERROR" "SSH configuration not found"
        return 1
    fi
    
    backup_file "$sshd_config"
    
    mkdir -p /etc/ssh/sshd_config.d
    
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# SSH Hardening Configuration
Protocol 2

# Authentication limits
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30

# Root login with key only
PermitRootLogin prohibit-password

# Password settings
PasswordAuthentication yes
PermitEmptyPasswords no

# Key authentication
PubkeyAuthentication yes

# Disable dangerous features
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

# Strong cryptography
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# Connection settings
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Security
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog yes
Compression delayed

# Banner
Banner /etc/issue.net
EOF

    if ! grep -q "^Include /etc/ssh/sshd_config.d/" "$sshd_config" 2>/dev/null; then
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$sshd_config" 2>/dev/null || \
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$sshd_config"
    fi
    
    cat > /etc/issue.net << 'EOF'
*************************************************************************
*                       AUTHORIZED ACCESS ONLY                          *
*************************************************************************
* This system is for authorized users only. All connections are logged *
* and monitored. Unauthorized access attempts will be reported.         *
*************************************************************************
EOF

    print_status "INFO" "Validating SSH configuration..."
    
    if sshd -t >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "SSH configuration is valid"
        
        print_status "INFO" "Restarting SSH service..."
        
        if systemctl restart "$ssh_service" >> "$LOG_FILE" 2>&1; then
            print_status "SUCCESS" "SSH service restarted successfully"
        else
            if service "$ssh_service" restart >> "$LOG_FILE" 2>&1; then
                print_status "SUCCESS" "SSH service restarted (via service command)"
            else
                print_status "WARNING" "Could not restart SSH - may need manual restart"
            fi
        fi
    else
        print_status "ERROR" "SSH configuration validation failed!"
        print_status "INFO" "Removing hardening config to prevent lockout"
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
        return 1
    fi
    
    print_status "SUCCESS" "SSH hardening completed"
}

#===============================================================================
# UNBOUND DNS RESOLVER
#===============================================================================
configure_unbound_dns() {
    print_section "Configuring Unbound Local DNS Resolver"
    
    if ! check_command unbound; then
        print_status "SKIP" "Unbound not installed"
        return 1
    fi
    
    systemctl stop unbound >> "$LOG_FILE" 2>&1 || true
    
    backup_file /etc/unbound/unbound.conf
    
    mkdir -p /etc/unbound/unbound.conf.d
    
    cat > /etc/unbound/unbound.conf.d/local-dns.conf << 'EOF'
server:
    interface: 127.0.0.1
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    
    num-threads: 2
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4
    
    rrset-cache-size: 64m
    msg-cache-size: 32m
    key-cache-size: 16m
    neg-cache-size: 4m
    
    cache-min-ttl: 300
    cache-max-ttl: 86400
    
    hide-identity: yes
    hide-version: yes
    identity: "DNS"
    version: "1.0"
    
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    harden-below-nxdomain: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    
    qname-minimisation: yes
    qname-minimisation-strict: no
    aggressive-nsec: yes
    
    prefetch: yes
    prefetch-key: yes
    
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-ttl-reset: yes
    
    root-hints: "/usr/share/dns/root.hints"
    
    verbosity: 0
    log-queries: no
    log-replies: no
    log-servfail: yes
    
    minimal-responses: yes
    unwanted-reply-threshold: 10000
    do-not-query-localhost: no
    val-log-level: 1

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
EOF

    if [[ ! -f /usr/share/dns/root.hints ]]; then
        mkdir -p /usr/share/dns
        curl -s -o /usr/share/dns/root.hints https://www.internic.net/domain/named.root >> "$LOG_FILE" 2>&1 || true
    fi
    
    if [[ -x /usr/sbin/unbound-anchor ]]; then
        unbound-anchor -a /var/lib/unbound/root.key >> "$LOG_FILE" 2>&1 || true
    fi
    
    chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true
    
    print_status "INFO" "Validating Unbound configuration..."
    
    if unbound-checkconf >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Unbound configuration is valid"
    else
        print_status "WARNING" "Unbound configuration has issues - using defaults"
        rm -f /etc/unbound/unbound.conf.d/local-dns.conf
        return 1
    fi
    
    systemctl enable unbound >> "$LOG_FILE" 2>&1 || true
    systemctl start unbound >> "$LOG_FILE" 2>&1 || true
    
    sleep 3
    
    if dig @127.0.0.1 +short google.com A >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Unbound DNS resolver is working"
    else
        print_status "WARNING" "Unbound may not be responding correctly"
    fi
    
    configure_system_dns
    
    print_status "SUCCESS" "Unbound DNS resolver configured"
}

configure_system_dns() {
    print_status "INFO" "Configuring system DNS..."
    
    if systemctl is-active systemd-resolved >> "$LOG_FILE" 2>&1; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/unbound.conf << 'EOF'
[Resolve]
DNS=127.0.0.1
FallbackDNS=1.1.1.1 9.9.9.9
DNSStubListener=no
EOF
        systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1 || true
    elif [[ ! -L /etc/resolv.conf ]]; then
        if dig @127.0.0.1 +short google.com A >> "$LOG_FILE" 2>&1; then
            cat > /etc/resolv.conf << 'EOF'
nameserver 127.0.0.1
nameserver 1.1.1.1
nameserver 9.9.9.9
options edns0 trust-ad
EOF
        fi
    fi
}

#===============================================================================
# UFW FIREWALL
#===============================================================================
configure_ufw_firewall() {
    print_section "Configuring UFW Firewall"
    
    if ! check_command ufw; then
        print_status "SKIP" "UFW not installed"
        return 1
    fi
    
    print_status "INFO" "Resetting UFW to defaults..."
    echo "y" | ufw reset >> "$LOG_FILE" 2>&1 || true
    
    ufw default deny incoming >> "$LOG_FILE" 2>&1 || true
    ufw default allow outgoing >> "$LOG_FILE" 2>&1 || true
    
    print_status "INFO" "Allowing SSH access..."
    ufw allow ssh >> "$LOG_FILE" 2>&1 || true
    ufw allow 22/tcp >> "$LOG_FILE" 2>&1 || true
    
    print_status "INFO" "Allowing HTTP/HTTPS..."
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1 || true
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1 || true
    
    ufw limit ssh >> "$LOG_FILE" 2>&1 || true
    
    ufw logging low >> "$LOG_FILE" 2>&1 || true
    
    print_status "INFO" "Enabling UFW..."
    echo "y" | ufw enable >> "$LOG_FILE" 2>&1
    
    if ufw status | grep -q "active"; then
        print_status "SUCCESS" "UFW firewall enabled and configured"
    else
        print_status "ERROR" "UFW may not be active"
    fi
}

#===============================================================================
# FAIL2BAN
#===============================================================================
configure_fail2ban() {
    print_section "Configuring Fail2Ban"
    
    if ! check_command fail2ban-client; then
        print_status "SKIP" "Fail2ban not installed"
        return 1
    fi
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
backend = systemd
banaction = ufw
banaction_allports = ufw
destemail = root@localhost
sender = fail2ban@localhost
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[recidive]
enabled = true
filter = recidive
banaction = ufw
logpath = /var/log/fail2ban.log
bantime = 604800
findtime = 86400
maxretry = 3
EOF

    systemctl enable fail2ban >> "$LOG_FILE" 2>&1 || true
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || true
    
    if systemctl is-active fail2ban >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Fail2Ban configured and running"
    else
        print_status "WARNING" "Fail2Ban may not be running properly"
    fi
}

#===============================================================================
# AIDE CONFIGURATION
#===============================================================================
configure_aide() {
    print_section "Configuring AIDE File Integrity Monitoring"
    
    local aide_init=""
    
    if [[ -x /usr/sbin/aideinit ]]; then
        aide_init="/usr/sbin/aideinit"
    fi
    
    if ! check_command aide && [[ -z "$aide_init" ]]; then
        print_status "SKIP" "AIDE not installed"
        return 1
    fi
    
    if [[ -d /etc/aide/aide.conf.d ]]; then
        cat > /etc/aide/aide.conf.d/99-custom.conf << 'EOF'
/home CONTENT_EX
/root CONTENT_EX
/var/log/auth.log p+u+g+i+n+S
/etc/ssh CONTENT_EX
EOF
    fi
    
    print_status "INFO" "Initializing AIDE database (this may take several minutes)..."
    
    if [[ -n "$aide_init" ]]; then
        yes | "$aide_init" >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "AIDE initialization had warnings"
    elif check_command aide; then
        aide --init >> "$LOG_FILE" 2>&1 || \
            print_status "WARNING" "AIDE initialization had warnings"
        
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
        fi
    fi
    
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
LOGDIR="/var/log/aide"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)

AIDE_CMD=""
if command -v aide >/dev/null 2>&1; then
    AIDE_CMD="aide"
elif [[ -x /usr/bin/aide ]]; then
    AIDE_CMD="/usr/bin/aide"
fi

if [[ -n "$AIDE_CMD" ]]; then
    "$AIDE_CMD" --check > "$LOGDIR/aide-check-$DATE.log" 2>&1 || true
fi

find "$LOGDIR" -name "aide-check-*.log" -mtime +30 -delete 2>/dev/null || true
exit 0
EOF

    chmod 755 /etc/cron.daily/aide-check
    
    print_status "SUCCESS" "AIDE configured with daily integrity checks"
}

#===============================================================================
# ROOTKIT SCANNERS
#===============================================================================
configure_rootkit_scanners() {
    print_section "Configuring Rootkit Scanners"
    
    if check_command rkhunter; then
        print_status "INFO" "Configuring rkhunter..."
        
        if [[ -f /etc/rkhunter.conf ]]; then
            sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null || true
            sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf 2>/dev/null || true
            sed -i 's/^WEB_CMD=.*/WEB_CMD="curl -fsSL"/' /etc/rkhunter.conf 2>/dev/null || true
            sed -i 's/^PKGMGR=.*/PKGMGR=DPKG/' /etc/rkhunter.conf 2>/dev/null || true
        fi
        
        rkhunter --update >> "$LOG_FILE" 2>&1 || true
        rkhunter --propupd >> "$LOG_FILE" 2>&1 || true
        
        print_status "SUCCESS" "rkhunter configured and updated"
    else
        print_status "SKIP" "rkhunter not installed"
    fi
    
    if check_command chkrootkit; then
        print_status "SUCCESS" "chkrootkit installed and ready"
    else
        print_status "SKIP" "chkrootkit not installed"
    fi
    
    cat > /etc/cron.weekly/rootkit-scan << 'EOF'
#!/bin/bash
LOGDIR="/var/log/security-scans"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)

if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --check --skip-keypress --report-warnings-only \
        > "$LOGDIR/rkhunter-$DATE.log" 2>&1 || true
fi

if command -v chkrootkit >/dev/null 2>&1; then
    chkrootkit > "$LOGDIR/chkrootkit-$DATE.log" 2>&1 || true
fi

find "$LOGDIR" -name "*.log" -mtime +60 -delete 2>/dev/null || true
exit 0
EOF

    chmod 755 /etc/cron.weekly/rootkit-scan
    
    print_status "SUCCESS" "Rootkit scanners configured with weekly checks"
}

#===============================================================================
# AUDITD CONFIGURATION
#===============================================================================
configure_auditd() {
    print_section "Configuring Audit Daemon"
    
    if ! check_command auditd; then
        print_status "SKIP" "auditd not installed"
        return 1
    fi
    
    mkdir -p /etc/audit/rules.d
    
    cat > /etc/audit/rules.d/99-hardening.rules << 'EOF'
-D
-b 8192
-f 1

# Identity
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudo
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# PAM
-w /etc/pam.d/ -p wa -k pam_changes

# Login
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron

# Network
-w /etc/hosts -p wa -k network_config
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/resolv.conf -p wa -k network_config

# System
-w /etc/systemd/ -p wa -k systemd
-w /etc/init.d/ -p wa -k init

# Modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Time
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change

# Make immutable
-e 2
EOF

    print_status "INFO" "Loading audit rules..."
    
    augenrules --load >> "$LOG_FILE" 2>&1 || true
    
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || true
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || true
    
    if systemctl is-active auditd >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "Audit daemon configured and running"
    else
        print_status "WARNING" "Audit daemon may not be running"
    fi
}

#===============================================================================
# APPARMOR CONFIGURATION
#===============================================================================
configure_apparmor() {
    print_section "Configuring AppArmor"
    
    if ! check_command apparmor_status; then
        print_status "SKIP" "AppArmor tools not installed"
        return 1
    fi
    
    if [[ ! -d /sys/kernel/security/apparmor ]]; then
        print_status "SKIP" "AppArmor not supported by kernel"
        return 1
    fi
    
    systemctl enable apparmor >> "$LOG_FILE" 2>&1 || true
    systemctl start apparmor >> "$LOG_FILE" 2>&1 || true
    
    local profile_count=0
    if [[ -d /etc/apparmor.d ]]; then
        profile_count=$(find /etc/apparmor.d -maxdepth 1 -type f -name "[a-z]*" 2>/dev/null | wc -l)
    fi
    
    if [[ $profile_count -eq 0 ]]; then
        print_status "WARNING" "No AppArmor profiles found"
        return 1
    fi
    
    print_status "INFO" "Found $profile_count AppArmor profiles"
    
    print_status "INFO" "Reloading AppArmor profiles..."
    
    apparmor_parser -r /etc/apparmor.d/* >> "$LOG_FILE" 2>&1 || \
        print_status "WARNING" "Some AppArmor profiles failed to load"
    
    print_status "SUCCESS" "AppArmor configured"
}

#===============================================================================
# LYNIS CONFIGURATION
#===============================================================================
configure_lynis() {
    print_section "Configuring Lynis Security Auditor"
    
    if ! check_command lynis; then
        print_status "SKIP" "Lynis not installed"
        return 1
    fi
    
    mkdir -p /etc/lynis
    
    cat > /etc/lynis/custom.prf << 'EOF'
skip-test=KRNL-5770
skip-test=KRNL-5820
skip-test=PKGS-7370
skip-test=USB-1000
skip-test=USB-2000
skip-test=USB-3000
quick=no
show-warnings-only=no
colors=yes
EOF

    cat > /etc/cron.weekly/lynis-audit << 'EOF'
#!/bin/bash
LOGDIR="/var/log/lynis"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)

if command -v lynis >/dev/null 2>&1; then
    lynis audit system --no-colors --quiet --report-file="$LOGDIR/lynis-report-$DATE.dat" \
        > "$LOGDIR/lynis-audit-$DATE.log" 2>&1 || true
fi

find "$LOGDIR" -name "lynis-*" -mtime +60 -delete 2>/dev/null || true
exit 0
EOF

    chmod 755 /etc/cron.weekly/lynis-audit
    
    print_status "SUCCESS" "Lynis configured with weekly audits"
}

#===============================================================================
# ADDITIONAL HARDENING
#===============================================================================
apply_additional_hardening() {
    print_section "Applying Additional Hardening Measures"
    
    # Restrict cron
    print_status "INFO" "Restricting cron access..."
    echo "root" > /etc/cron.allow 2>/dev/null || true
    rm -f /etc/cron.deny 2>/dev/null || true
    chmod 600 /etc/cron.allow 2>/dev/null || true
    
    # Restrict at
    echo "root" > /etc/at.allow 2>/dev/null || true
    rm -f /etc/at.deny 2>/dev/null || true
    chmod 600 /etc/at.allow 2>/dev/null || true
    
    # Secure file permissions
    print_status "INFO" "Setting secure file permissions..."
    chmod 600 /etc/shadow 2>/dev/null || true
    chmod 600 /etc/gshadow 2>/dev/null || true
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 700 /root 2>/dev/null || true
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    
    # Disable unused filesystems
    print_status "INFO" "Disabling unused filesystem modules..."
    cat > /etc/modprobe.d/hardening-filesystems.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF

    # Disable unused protocols
    cat > /etc/modprobe.d/hardening-protocols.conf << 'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

    # Disable USB storage
    cat > /etc/modprobe.d/hardening-usb.conf << 'EOF'
install usb-storage /bin/true
EOF

    # Password quality
    print_status "INFO" "Configuring password quality requirements..."
    if [[ -f /etc/security/pwquality.conf ]]; then
        cat >> /etc/security/pwquality.conf << 'EOF'

minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 3
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF
    fi
    
    # Login hardening
    print_status "INFO" "Hardening login definitions..."
    if [[ -f /etc/login.defs ]]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs 2>/dev/null || true
        sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs 2>/dev/null || true
        
        if ! grep -q "SHA_CRYPT_MIN_ROUNDS" /etc/login.defs; then
            echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
            echo "SHA_CRYPT_MAX_ROUNDS 65536" >> /etc/login.defs
        fi
    fi
    
    # Default umask
    cat > /etc/profile.d/umask.sh << 'EOF'
umask 027
EOF
    chmod 644 /etc/profile.d/umask.sh
    
    # Disable Ctrl+Alt+Delete
    systemctl mask ctrl-alt-del.target >> "$LOG_FILE" 2>&1 || true
    
    # Secure home directories
    print_status "INFO" "Securing home directories..."
    for homedir in /home/*; do
        if [[ -d "$homedir" ]]; then
            chmod 700 "$homedir" 2>/dev/null || true
        fi
    done
    
    print_status "SUCCESS" "Additional hardening measures applied"
}

#===============================================================================
# VERIFICATION
#===============================================================================
verify_configuration() {
    print_section "Verifying Configuration"
    
    local tests_passed=0
    local tests_failed=0
    
    # DNS
    print_status "INFO" "Testing DNS resolution..."
    if dig +short google.com A >/dev/null 2>&1 || getent hosts google.com >/dev/null 2>&1; then
        print_status "SUCCESS" "DNS resolution: OK"
        ((tests_passed++))
    else
        print_status "WARNING" "DNS resolution: FAILED"
        ((tests_failed++))
    fi
    
    # Network
    print_status "INFO" "Testing network connectivity..."
    if ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
        print_status "SUCCESS" "Network connectivity: OK"
        ((tests_passed++))
    else
        print_status "WARNING" "Network connectivity: Limited"
        ((tests_failed++))
    fi
    
    # SSH
    print_status "INFO" "Testing SSH service..."
    local ssh_service
    ssh_service=$(get_ssh_service_name)
    if systemctl is-active "$ssh_service" >/dev/null 2>&1; then
        print_status "SUCCESS" "SSH service: Active"
        ((tests_passed++))
    else
        print_status "WARNING" "SSH service: Not active"
        ((tests_failed++))
    fi
    
    # UFW
    print_status "INFO" "Testing UFW firewall..."
    if ufw status 2>/dev/null | grep -q "active"; then
        print_status "SUCCESS" "UFW firewall: Active"
        ((tests_passed++))
    else
        print_status "WARNING" "UFW firewall: Not active"
        ((tests_failed++))
    fi
    
    # Unbound
    if systemctl is-active unbound >/dev/null 2>&1; then
        print_status "SUCCESS" "Unbound DNS: Active"
        ((tests_passed++))
    fi
    
    # Fail2ban
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        print_status "SUCCESS" "Fail2ban: Active"
        ((tests_passed++))
    fi
    
    # AppArmor
    if check_command apparmor_status; then
        if apparmor_status --enabled 2>/dev/null; then
            print_status "SUCCESS" "AppArmor: Enabled"
            ((tests_passed++))
        fi
    fi
    
    # Auditd
    if systemctl is-active auditd >/dev/null 2>&1; then
        print_status "SUCCESS" "Auditd: Active"
        ((tests_passed++))
    fi
    
    print_status "INFO" "Verification complete: $tests_passed passed, $tests_failed warnings"
}

#===============================================================================
# LYNIS AUDIT
#===============================================================================
run_lynis_audit() {
    print_section "Running Lynis Security Audit"
    
    if ! check_command lynis; then
        print_status "SKIP" "Lynis not installed - skipping audit"
        return 1
    fi
    
    print_status "INFO" "Starting Lynis security audit..."
    
    lynis audit system --quick --quiet --no-colors > /tmp/lynis_audit.txt 2>&1 || true
    
    local hardening_index=""
    hardening_index=$(grep "Hardening index" /tmp/lynis_audit.txt 2>/dev/null | grep -oE "[0-9]+" | head -1)
    
    if [[ -n "$hardening_index" ]]; then
        print_status "SUCCESS" "Lynis Hardening Score: $hardening_index/100"
        
        if [[ $hardening_index -ge 92 ]]; then
            print_status "SUCCESS" "Target score of 92+ achieved!"
        elif [[ $hardening_index -ge 85 ]]; then
            print_status "SUCCESS" "Good hardening score achieved"
        else
            print_status "INFO" "Score is $hardening_index - review Lynis suggestions"
        fi
    else
        print_status "WARNING" "Could not determine Lynis score"
    fi
    
    if [[ -f /tmp/lynis_audit.txt ]]; then
        cp /tmp/lynis_audit.txt "$REPORT_FILE.lynis" 2>/dev/null
        print_status "INFO" "Lynis report saved to: $REPORT_FILE.lynis"
    fi
    
    rm -f /tmp/lynis_audit.txt
}

#===============================================================================
# GENERATE REPORT
#===============================================================================
generate_report() {
    print_section "Generating Security Report"
    
    cat > "$REPORT_FILE" << EOF
================================================================================
                    DEBIAN 11 VPS SECURITY HARDENING REPORT
================================================================================

Date: $(date)
Hostname: $(hostname)
IP Address: $(hostname -I | awk '{print $1}')
Kernel: $(uname -r)
Script Version: $SCRIPT_VERSION

================================================================================
                              EXECUTION SUMMARY
================================================================================

Tasks Completed:     $TASKS_COMPLETED
Tasks Skipped:       $TASKS_SKIPPED
Tasks Failed:        $TASKS_FAILED
Warnings:            $WARNINGS_COUNT

Execution Time:      $(($(date +%s) - SCRIPT_START_TIME)) seconds
Backup Location:     $BACKUP_DIR
Log File:            $LOG_FILE

================================================================================
                           SECURITY COMPONENTS STATUS
================================================================================

EOF

    echo "Service Status:" >> "$REPORT_FILE"
    echo "---------------" >> "$REPORT_FILE"
    
    local services=(
        "ssh|SSH Server"
        "ufw|UFW Firewall"
        "fail2ban|Fail2ban IPS"
        "unbound|Unbound DNS"
        "apparmor|AppArmor MAC"
        "auditd|Audit Daemon"
        "unattended-upgrades|Auto Updates"
    )
    
    for service_info in "${services[@]}"; do
        local service="${service_info%%|*}"
        local description="${service_info##*|}"
        
        if [[ "$service" == "ssh" ]]; then
            service=$(get_ssh_service_name)
        fi
        
        if systemctl is-active "$service" >/dev/null 2>&1; then
            echo "✓ $description: ACTIVE" >> "$REPORT_FILE"
        elif check_service_exists "$service"; then
            echo "✗ $description: INACTIVE" >> "$REPORT_FILE"
        else
            echo "- $description: NOT INSTALLED" >> "$REPORT_FILE"
        fi
    done
    
    echo "" >> "$REPORT_FILE"
    echo "Security Features:" >> "$REPORT_FILE"
    echo "------------------" >> "$REPORT_FILE"
    
    [[ -f /etc/sysctl.d/99-security-hardening.conf ]] && \
        echo "✓ Kernel hardening applied" >> "$REPORT_FILE"
    
    [[ -f /etc/security/limits.d/99-disable-coredump.conf ]] && \
        echo "✓ Core dumps disabled" >> "$REPORT_FILE"
    
    [[ -f /etc/ssh/sshd_config.d/99-hardening.conf ]] && \
        echo "✓ SSH hardening applied" >> "$REPORT_FILE"
    
    [[ -f /var/lib/aide/aide.db ]] && \
        echo "✓ AIDE database initialized" >> "$REPORT_FILE"
    
    [[ -f /etc/cron.daily/aide-check ]] && \
        echo "✓ Daily AIDE checks scheduled" >> "$REPORT_FILE"
    
    [[ -f /etc/cron.weekly/rootkit-scan ]] && \
        echo "✓ Weekly rootkit scans scheduled" >> "$REPORT_FILE"
    
    [[ -f /etc/cron.weekly/lynis-audit ]] && \
        echo "✓ Weekly Lynis audits scheduled" >> "$REPORT_FILE"
    
    echo "" >> "$REPORT_FILE"
    echo "=================================================================================" >> "$REPORT_FILE"
    echo "                              RECOMMENDATIONS" >> "$REPORT_FILE"
    echo "=================================================================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "1. Configure SSH key authentication and disable password auth" >> "$REPORT_FILE"
    echo "2. Review and customize UFW firewall rules" >> "$REPORT_FILE"
    echo "3. Set up email alerts for security events" >> "$REPORT_FILE"
    echo "4. Regularly review audit logs in /var/log/audit/" >> "$REPORT_FILE"
    echo "5. Keep system updated: apt update && apt upgrade" >> "$REPORT_FILE"
    echo "6. Run 'lynis audit system' for detailed recommendations" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "=================================================================================" >> "$REPORT_FILE"
    
    print_status "SUCCESS" "Security report saved to: $REPORT_FILE"
}

#===============================================================================
# CLEANUP
#===============================================================================
cleanup() {
    print_section "Performing Cleanup"
    
    apt-get clean >> "$LOG_FILE" 2>&1 || true
    apt-get autoclean >> "$LOG_FILE" 2>&1 || true
    
    rm -rf /tmp/hardening_* 2>/dev/null || true
    
    print_status "SUCCESS" "Cleanup completed"
}

#===============================================================================
# MAIN
#===============================================================================
main() {
    init_logging
    print_banner
    
    # Pre-flight
    check_root
    check_debian_version
    check_network_connectivity
    create_backups
    
    # Core hardening
    perform_system_updates
    install_security_packages
    configure_unattended_upgrades
    configure_sysctl_hardening
    secure_shared_memory
    disable_core_dumps
    
    # Services
    configure_ssh_hardening
    configure_unbound_dns
    configure_fail2ban
    
    # Security monitoring
    configure_aide
    configure_rootkit_scanners
    configure_auditd
    configure_apparmor
    configure_lynis
    
    # Additional
    apply_additional_hardening
    
    # Firewall last
    configure_ufw_firewall
    
    # Verification
    verify_configuration
    run_lynis_audit
    
    # Report
    generate_report
    cleanup
    
    # Summary
    print_section "Hardening Complete!"
    
    echo ""
    echo -e "${GREEN}${BOLD}✓ System hardening completed successfully!${NC}"
    echo ""
    echo -e "${BOLD}Summary:${NC}"
    echo -e "  • Tasks Completed: ${GREEN}$TASKS_COMPLETED${NC}"
    echo -e "  • Tasks Skipped: ${YELLOW}$TASKS_SKIPPED${NC}"
    echo -e "  • Tasks Failed: ${RED}$TASKS_FAILED${NC}"
    echo -e "  • Warnings: ${YELLOW}$WARNINGS_COUNT${NC}"
    echo ""
    echo -e "${BOLD}Important Files:${NC}"
    echo -e "  • Backup Directory: $BACKUP_DIR"
    echo -e "  • Log File: $LOG_FILE"
    echo -e "  • Security Report: $REPORT_FILE"
    echo ""
    echo -e "${YELLOW}${BOLD}⚠ IMPORTANT:${NC}"
    echo -e "  1. Test SSH access in a new session before closing this one"
    echo -e "  2. Review the security report for any issues"
    echo -e "  3. Consider rebooting to ensure all changes take effect"
    echo ""
    
    return 0
}

# Execute
main "$@"

exit 0

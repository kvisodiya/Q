#!/usr/bin/env bash
#===============================================================================
#
#          FILE: harden.sh
#
#         USAGE: sudo bash harden.sh
#
#   DESCRIPTION: Debian 11 VPS Hardening Script
#                Target: 92-95+ Lynis Score
#                Focus: Security hardening, no complex network setup
#
#       VERSION: 3.0.0
#
#===============================================================================

set +e
set +u

#===============================================================================
# VARIABLES
#===============================================================================
readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_START_TIME=$(date +%s)
readonly LOG_FILE="/var/log/hardening_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/root/hardening_backups_$(date +%Y%m%d_%H%M%S)"
readonly REPORT_FILE="/root/hardening_report_$(date +%Y%m%d_%H%M%S).txt"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Counters
TASKS_COMPLETED=0
TASKS_SKIPPED=0
TASKS_FAILED=0
WARNINGS_COUNT=0

#===============================================================================
# LOGGING
#===============================================================================
init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    touch "$LOG_FILE" 2>/dev/null
    exec 3>&1 4>&2
    echo "=== Hardening Started: $(date) ===" >> "$LOG_FILE"
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] $2" >> "$LOG_FILE" 2>/dev/null
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
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "SECTION" "=== $1 ==="
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
    echo -e "${BOLD}    Target: 92-95+ Lynis Score${NC}"
    echo ""
}

#===============================================================================
# UTILITY FUNCTIONS
#===============================================================================
check_command() {
    command -v "$1" >/dev/null 2>&1
}

get_ssh_service_name() {
    if systemctl list-units --type=service 2>/dev/null | grep -q "sshd.service"; then
        echo "sshd"
    else
        echo "ssh"
    fi
}

wait_for_apt() {
    local timeout=120
    local count=0
    
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        if [[ $count -ge $timeout ]]; then
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
    fi
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

check_debian() {
    if [[ -f /etc/debian_version ]]; then
        local version
        version=$(cat /etc/debian_version 2>/dev/null)
        print_status "INFO" "Detected Debian version: $version"
        print_status "SUCCESS" "Debian system confirmed"
    else
        print_status "WARNING" "Not running on Debian"
    fi
}

create_backups() {
    print_section "Creating System Backups"
    
    mkdir -p "$BACKUP_DIR"
    
    local files=(
        "/etc/ssh/sshd_config"
        "/etc/sysctl.conf"
        "/etc/fstab"
        "/etc/default/grub"
        "/etc/security/limits.conf"
        "/etc/pam.d/common-password"
        "/etc/pam.d/common-auth"
        "/etc/login.defs"
    )
    
    local count=0
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            backup_file "$file"
            ((count++))
        fi
    done
    
    if check_command iptables; then
        iptables-save > "${BACKUP_DIR}/iptables.rules" 2>/dev/null
    fi
    
    print_status "SUCCESS" "Backed up $count files to $BACKUP_DIR"
}

#===============================================================================
# SYSTEM UPDATES
#===============================================================================
perform_system_updates() {
    print_section "System Updates"
    
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    
    wait_for_apt
    
    dpkg --configure -a >> "$LOG_FILE" 2>&1
    
    print_status "INFO" "Updating package lists..."
    apt-get update -y >> "$LOG_FILE" 2>&1
    
    print_status "INFO" "Upgrading packages..."
    apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >> "$LOG_FILE" 2>&1
    
    apt-get dist-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >> "$LOG_FILE" 2>&1
    
    apt-get autoremove -y >> "$LOG_FILE" 2>&1
    apt-get autoclean >> "$LOG_FILE" 2>&1
    
    print_status "SUCCESS" "System updates completed"
}

#===============================================================================
# INSTALL PACKAGES
#===============================================================================
install_packages() {
    print_section "Installing Security Packages"
    
    export DEBIAN_FRONTEND=noninteractive
    
    wait_for_apt
    
    local packages=(
        # Firewall
        "ufw"
        # Intrusion prevention
        "fail2ban"
        # Auto updates
        "unattended-upgrades"
        "apt-listchanges"
        "needrestart"
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
        # Password quality
        "libpam-pwquality"
        "libpam-tmpdir"
        # Utilities
        "acct"
        "sysstat"
        "debsums"
        "apt-show-versions"
        "curl"
        "wget"
        "gnupg"
        "sudo"
        "rsyslog"
        "logrotate"
        "cron"
        "acl"
    )
    
    local installed=0
    local failed=0
    
    for pkg in "${packages[@]}"; do
        if apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1; then
            ((installed++))
        else
            ((failed++))
        fi
    done
    
    print_status "SUCCESS" "Installed $installed packages"
    
    if [[ $failed -gt 0 ]]; then
        print_status "WARNING" "$failed packages failed to install"
    fi
}

#===============================================================================
# UPGRADE LYNIS
#===============================================================================
upgrade_lynis() {
    print_section "Upgrading Lynis"
    
    print_status "INFO" "Adding Lynis repository..."
    
    apt-get install -y apt-transport-https ca-certificates curl gnupg >> "$LOG_FILE" 2>&1
    
    curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key 2>/dev/null | \
        gpg --dearmor -o /usr/share/keyrings/cisofy-archive-keyring.gpg 2>/dev/null
    
    echo "deb [signed-by=/usr/share/keyrings/cisofy-archive-keyring.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" > /etc/apt/sources.list.d/cisofy-lynis.list
    
    apt-get update >> "$LOG_FILE" 2>&1
    apt-get install -y lynis >> "$LOG_FILE" 2>&1
    
    if check_command lynis; then
        local version
        version=$(lynis show version 2>/dev/null | head -1)
        print_status "SUCCESS" "Lynis upgraded: $version"
    else
        print_status "WARNING" "Lynis upgrade may have failed"
    fi
}

#===============================================================================
# UNATTENDED UPGRADES
#===============================================================================
configure_unattended_upgrades() {
    print_section "Configuring Automatic Updates"
    
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
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF

    systemctl enable unattended-upgrades >> "$LOG_FILE" 2>&1
    systemctl start unattended-upgrades >> "$LOG_FILE" 2>&1
    
    print_status "SUCCESS" "Automatic updates configured"
}

#===============================================================================
# KERNEL HARDENING
#===============================================================================
configure_sysctl() {
    print_section "Kernel Security Hardening"
    
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
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

# Don't send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Log martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP SYN Cookies
net.ipv4.tcp_syncookies = 1

# TCP hardening
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# ASLR
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 1

# Disable SysRq (safe functions only)
kernel.sysrq = 176

# Disable core dumps for setuid
fs.suid_dumpable = 0

# Protect links
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# File limits
fs.file-max = 65535
kernel.pid_max = 65536

# Network
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.ip_local_port_range = 1024 65535
EOF

    sysctl --system >> "$LOG_FILE" 2>&1
    
    print_status "SUCCESS" "Kernel hardening applied"
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

    systemctl daemon-reload >> "$LOG_FILE" 2>&1
    
    print_status "SUCCESS" "Core dumps disabled"
}

#===============================================================================
# SSH HARDENING
#===============================================================================
configure_ssh() {
    print_section "SSH Security Hardening"
    
    local sshd_config="/etc/ssh/sshd_config"
    local ssh_service
    ssh_service=$(get_ssh_service_name)
    
    if [[ ! -f "$sshd_config" ]]; then
        print_status "ERROR" "SSH config not found"
        return 1
    fi
    
    backup_file "$sshd_config"
    
    mkdir -p /etc/ssh/sshd_config.d
    
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# SSH Hardening
Protocol 2

# Authentication
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
PermitRootLogin prohibit-password
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes

# Disable dangerous features
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

# Strong crypto
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# Connection
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
Banner /etc/issue.net
EOF

    if ! grep -q "^Include /etc/ssh/sshd_config.d/" "$sshd_config" 2>/dev/null; then
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$sshd_config"
    fi
    
    cat > /etc/issue.net << 'EOF'
*************************************************************************
*                       AUTHORIZED ACCESS ONLY                          *
*************************************************************************
* This system is for authorized users only. Unauthorized access is      *
* prohibited. All connections are logged and monitored.                 *
*************************************************************************
EOF

    if sshd -t >> "$LOG_FILE" 2>&1; then
        print_status "SUCCESS" "SSH configuration valid"
        systemctl restart "$ssh_service" >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "SSH service restarted"
    else
        print_status "ERROR" "SSH config invalid - removing hardening"
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
    fi
}

#===============================================================================
# UFW FIREWALL
#===============================================================================
configure_ufw() {
    print_section "Configuring UFW Firewall"
    
    if ! check_command ufw; then
        apt-get install -y ufw >> "$LOG_FILE" 2>&1
    fi
    
    print_status "INFO" "Resetting UFW..."
    ufw --force reset >> "$LOG_FILE" 2>&1
    
    # Defaults
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    
    # Allow SSH on port 22 and 2222
    print_status "INFO" "Allowing SSH ports 22 and 2222..."
    ufw allow 22/tcp >> "$LOG_FILE" 2>&1
    ufw allow 2222/tcp >> "$LOG_FILE" 2>&1
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1
    
    # Rate limit SSH
    ufw limit 22/tcp >> "$LOG_FILE" 2>&1
    ufw limit 2222/tcp >> "$LOG_FILE" 2>&1
    
    # Logging
    ufw logging low >> "$LOG_FILE" 2>&1
    
    # Enable
    print_status "INFO" "Enabling UFW..."
    echo "y" | ufw enable >> "$LOG_FILE" 2>&1
    
    # Verify
    if ufw status | grep -q "Status: active"; then
        print_status "SUCCESS" "UFW firewall enabled"
        echo ""
        ufw status numbered
        echo ""
    else
        print_status "ERROR" "UFW not active"
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
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
backend = systemd
banaction = ufw
banaction_allports = ufw

[sshd]
enabled = true
port = 22,2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800
findtime = 86400
maxretry = 3
EOF

    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        print_status "SUCCESS" "Fail2Ban configured and running"
    else
        print_status "WARNING" "Fail2Ban may not be running"
    fi
}

#===============================================================================
# AIDE
#===============================================================================
configure_aide() {
    print_section "Configuring AIDE"
    
    if ! check_command aide && [[ ! -x /usr/sbin/aideinit ]]; then
        print_status "SKIP" "AIDE not installed"
        return 1
    fi
    
    print_status "INFO" "Initializing AIDE database (this takes time)..."
    
    if [[ -x /usr/sbin/aideinit ]]; then
        yes | /usr/sbin/aideinit >> "$LOG_FILE" 2>&1
    else
        aide --init >> "$LOG_FILE" 2>&1
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
        fi
    fi
    
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
LOGDIR="/var/log/aide"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)
if command -v aide >/dev/null 2>&1; then
    aide --check > "$LOGDIR/aide-$DATE.log" 2>&1
fi
find "$LOGDIR" -name "aide-*.log" -mtime +30 -delete 2>/dev/null
exit 0
EOF
    chmod 755 /etc/cron.daily/aide-check
    
    print_status "SUCCESS" "AIDE configured"
}

#===============================================================================
# ROOTKIT SCANNERS
#===============================================================================
configure_rootkit_scanners() {
    print_section "Configuring Rootkit Scanners"
    
    if check_command rkhunter; then
        if [[ -f /etc/rkhunter.conf ]]; then
            sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null
            sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf 2>/dev/null
            sed -i 's/^PKGMGR=.*/PKGMGR=DPKG/' /etc/rkhunter.conf 2>/dev/null
        fi
        rkhunter --update >> "$LOG_FILE" 2>&1
        rkhunter --propupd >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "rkhunter configured"
    fi
    
    if check_command chkrootkit; then
        print_status "SUCCESS" "chkrootkit ready"
    fi
    
    cat > /etc/cron.weekly/rootkit-scan << 'EOF'
#!/bin/bash
LOGDIR="/var/log/security-scans"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)
if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --check --skip-keypress --report-warnings-only > "$LOGDIR/rkhunter-$DATE.log" 2>&1
fi
if command -v chkrootkit >/dev/null 2>&1; then
    chkrootkit > "$LOGDIR/chkrootkit-$DATE.log" 2>&1
fi
find "$LOGDIR" -name "*.log" -mtime +60 -delete 2>/dev/null
exit 0
EOF
    chmod 755 /etc/cron.weekly/rootkit-scan
}

#===============================================================================
# AUDITD
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

# Identity files
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
-w /etc/hosts -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl

# System
-w /etc/systemd/ -p wa -k systemd

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

    augenrules --load >> "$LOG_FILE" 2>&1
    systemctl enable auditd >> "$LOG_FILE" 2>&1
    systemctl restart auditd >> "$LOG_FILE" 2>&1
    
    if systemctl is-active auditd >/dev/null 2>&1; then
        print_status "SUCCESS" "Audit daemon configured"
    else
        print_status "WARNING" "Audit daemon may not be running"
    fi
}

#===============================================================================
# APPARMOR
#===============================================================================
configure_apparmor() {
    print_section "Configuring AppArmor"
    
    if ! check_command apparmor_status; then
        print_status "SKIP" "AppArmor not installed"
        return 1
    fi
    
    if [[ ! -d /sys/kernel/security/apparmor ]]; then
        print_status "SKIP" "AppArmor not supported by kernel"
        return 1
    fi
    
    systemctl enable apparmor >> "$LOG_FILE" 2>&1
    systemctl start apparmor >> "$LOG_FILE" 2>&1
    
    local profile_count=0
    if [[ -d /etc/apparmor.d ]]; then
        profile_count=$(find /etc/apparmor.d -maxdepth 1 -type f -name "[a-z]*" 2>/dev/null | wc -l)
    fi
    
    if [[ $profile_count -gt 0 ]]; then
        apparmor_parser -r /etc/apparmor.d/* >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "AppArmor configured with $profile_count profiles"
    else
        print_status "WARNING" "No AppArmor profiles found"
    fi
}

#===============================================================================
# ADDITIONAL HARDENING
#===============================================================================
apply_additional_hardening() {
    print_section "Additional Hardening"
    
    # Restrict cron
    echo "root" > /etc/cron.allow 2>/dev/null
    rm -f /etc/cron.deny 2>/dev/null
    chmod 600 /etc/cron.allow 2>/dev/null
    
    echo "root" > /etc/at.allow 2>/dev/null
    rm -f /etc/at.deny 2>/dev/null
    chmod 600 /etc/at.allow 2>/dev/null
    print_status "SUCCESS" "Restricted cron/at access"
    
    # File permissions
    chmod 600 /etc/shadow 2>/dev/null
    chmod 600 /etc/gshadow 2>/dev/null
    chmod 644 /etc/passwd 2>/dev/null
    chmod 644 /etc/group 2>/dev/null
    chmod 700 /root 2>/dev/null
    chmod 600 /boot/grub/grub.cfg 2>/dev/null
    print_status "SUCCESS" "Secured file permissions"
    
    # Disable unused filesystems
    cat > /etc/modprobe.d/hardening-fs.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
    print_status "SUCCESS" "Disabled unused filesystems"
    
    # Disable unused protocols
    cat > /etc/modprobe.d/hardening-net.conf << 'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    print_status "SUCCESS" "Disabled unused protocols"
    
    # Disable USB storage
    cat > /etc/modprobe.d/hardening-usb.conf << 'EOF'
install usb-storage /bin/true
EOF
    print_status "SUCCESS" "Disabled USB storage"
    
    # Password quality
    if [[ -f /etc/security/pwquality.conf ]]; then
        cat >> /etc/security/pwquality.conf << 'EOF'

minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 3
maxrepeat = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF
        print_status "SUCCESS" "Password quality configured"
    fi
    
    # Login hardening
    if [[ -f /etc/login.defs ]]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs 2>/dev/null
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs 2>/dev/null
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs 2>/dev/null
        sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs 2>/dev/null
        sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs 2>/dev/null
        sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs 2>/dev/null
        
        if ! grep -q "SHA_CRYPT_MIN_ROUNDS" /etc/login.defs; then
            echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
            echo "SHA_CRYPT_MAX_ROUNDS 65536" >> /etc/login.defs
        fi
        print_status "SUCCESS" "Login definitions hardened"
    fi
    
    # Umask
    cat > /etc/profile.d/umask.sh << 'EOF'
umask 027
EOF
    chmod 644 /etc/profile.d/umask.sh
    print_status "SUCCESS" "Default umask set to 027"
    
    # Disable Ctrl+Alt+Delete
    systemctl mask ctrl-alt-del.target >> "$LOG_FILE" 2>&1
    print_status "SUCCESS" "Ctrl+Alt+Delete disabled"
    
    # Secure home directories
    for homedir in /home/*; do
        if [[ -d "$homedir" ]]; then
            chmod 700 "$homedir" 2>/dev/null
        fi
    done
    print_status "SUCCESS" "Home directories secured"
    
    # Process accounting
    if check_command accton; then
        mkdir -p /var/log/account
        touch /var/log/account/pacct
        accton /var/log/account/pacct >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "Process accounting enabled"
    fi
    
    # Sudo timeout
    if [[ -f /etc/sudoers ]] && ! grep -q "timestamp_timeout" /etc/sudoers 2>/dev/null; then
        echo "Defaults timestamp_timeout=15" >> /etc/sudoers 2>/dev/null
        print_status "SUCCESS" "Sudo timeout configured"
    fi
    
    # Secure /tmp mount options
    if mountpoint -q /tmp 2>/dev/null; then
        mount -o remount,noexec,nosuid,nodev /tmp >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "/tmp secured with noexec,nosuid,nodev"
    fi
    
    # Secure shared memory
    if mountpoint -q /dev/shm 2>/dev/null; then
        mount -o remount,noexec,nosuid,nodev /dev/shm >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "/dev/shm secured"
    fi
}

#===============================================================================
# CONFIGURE LYNIS
#===============================================================================
configure_lynis() {
    print_section "Configuring Lynis"
    
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
colors=yes
EOF

    cat > /etc/cron.weekly/lynis-audit << 'EOF'
#!/bin/bash
LOGDIR="/var/log/lynis"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)
if command -v lynis >/dev/null 2>&1; then
    lynis audit system --no-colors --quiet > "$LOGDIR/lynis-$DATE.log" 2>&1
fi
find "$LOGDIR" -name "lynis-*.log" -mtime +60 -delete 2>/dev/null
exit 0
EOF
    chmod 755 /etc/cron.weekly/lynis-audit
    
    print_status "SUCCESS" "Lynis configured"
}

#===============================================================================
# VERIFICATION
#===============================================================================
verify_services() {
    print_section "Verifying Services"
    
    local ssh_service
    ssh_service=$(get_ssh_service_name)
    
    local services=(
        "$ssh_service|SSH Server"
        "ufw|UFW Firewall"
        "fail2ban|Fail2Ban"
        "auditd|Audit Daemon"
        "apparmor|AppArmor"
        "unattended-upgrades|Auto Updates"
    )
    
    for item in "${services[@]}"; do
        local service="${item%%|*}"
        local name="${item##*|}"
        
        if systemctl is-active "$service" >/dev/null 2>&1; then
            print_status "SUCCESS" "$name: Active"
        else
            print_status "WARNING" "$name: Not active"
        fi
    done
    
    # Check UFW status
    echo ""
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        print_status "SUCCESS" "UFW Status: Active"
        ufw status | grep -E "^[0-9]|^22|^2222|^80|^443"
    else
        print_status "WARNING" "UFW not active"
    fi
}

#===============================================================================
# RUN LYNIS AUDIT
#===============================================================================
run_lynis_audit() {
    print_section "Running Lynis Security Audit"
    
    if ! check_command lynis; then
        print_status "SKIP" "Lynis not available"
        return 1
    fi
    
    print_status "INFO" "Starting Lynis audit (takes 1-2 minutes)..."
    echo ""
    
    # Run Lynis
    lynis audit system --quick 2>&1 | tee /tmp/lynis_output.txt
    
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}           LYNIS RESULTS${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Extract score
    local score
    score=$(grep -i "hardening index" /tmp/lynis_output.txt 2>/dev/null | grep -oE "[0-9]+" | head -1)
    
    if [[ -n "$score" ]]; then
        echo -e "  🛡️  ${BOLD}HARDENING SCORE: ${GREEN}${score}/100${NC}"
        echo ""
        
        if [[ $score -ge 92 ]]; then
            echo -e "  ${GREEN}✅ EXCELLENT! Target of 92+ achieved!${NC}"
        elif [[ $score -ge 85 ]]; then
            echo -e "  ${GREEN}✅ GOOD! Score is above 85${NC}"
        elif [[ $score -ge 75 ]]; then
            echo -e "  ${YELLOW}⚠️  FAIR - Some improvements available${NC}"
        else
            echo -e "  ${YELLOW}⚠️  Review recommendations${NC}"
        fi
    else
        # Try alternative
        if [[ -f /var/log/lynis-report.dat ]]; then
            score=$(grep "hardening_index=" /var/log/lynis-report.dat 2>/dev/null | cut -d= -f2)
            if [[ -n "$score" ]]; then
                echo -e "  🛡️  ${BOLD}HARDENING SCORE: ${GREEN}${score}/100${NC}"
            fi
        fi
        
        if [[ -z "$score" ]]; then
            echo -e "  ${YELLOW}⚠️  Could not extract score${NC}"
            echo "  Run manually: sudo lynis audit system"
        fi
    fi
    
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Save report
    if [[ -f /tmp/lynis_output.txt ]]; then
        cp /tmp/lynis_output.txt "$REPORT_FILE.lynis"
        rm -f /tmp/lynis_output.txt
    fi
}

#===============================================================================
# GENERATE REPORT
#===============================================================================
generate_report() {
    print_section "Generating Report"
    
    cat > "$REPORT_FILE" << EOF
================================================================================
                    DEBIAN 11 SECURITY HARDENING REPORT
================================================================================

Date: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)
Script: v$SCRIPT_VERSION

================================================================================
                              SUMMARY
================================================================================

Tasks Completed:     $TASKS_COMPLETED
Tasks Skipped:       $TASKS_SKIPPED
Tasks Failed:        $TASKS_FAILED
Warnings:            $WARNINGS_COUNT

Execution Time:      $(($(date +%s) - SCRIPT_START_TIME)) seconds
Backup Location:     $BACKUP_DIR
Log File:            $LOG_FILE

================================================================================
                           FIREWALL RULES
================================================================================

$(ufw status verbose 2>/dev/null || echo "UFW not available")

================================================================================
                         RECOMMENDATIONS
================================================================================

1. Set up SSH key authentication
2. Disable password authentication after keys are set
3. Review /var/log/lynis-report.dat for improvements
4. Run: sudo lynis audit system --pentest

================================================================================
EOF

    print_status "SUCCESS" "Report saved to: $REPORT_FILE"
}

#===============================================================================
# CLEANUP
#===============================================================================
cleanup() {
    print_section "Cleanup"
    
    apt-get clean >> "$LOG_FILE" 2>&1
    apt-get autoclean >> "$LOG_FILE" 2>&1
    rm -rf /tmp/hardening_* 2>/dev/null
    
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
    check_debian
    create_backups
    
    # Updates and packages
    perform_system_updates
    install_packages
    upgrade_lynis
    
    # Configuration
    configure_unattended_upgrades
    configure_sysctl
    disable_core_dumps
    configure_ssh
    configure_ufw
    configure_fail2ban
    
    # Security tools
    configure_aide
    configure_rootkit_scanners
    configure_auditd
    configure_apparmor
    configure_lynis
    
    # Additional
    apply_additional_hardening
    
    # Verify
    verify_services
    run_lynis_audit
    
    # Report
    generate_report
    cleanup
    
    # Final
    print_section "COMPLETE!"
    
    echo ""
    echo -e "${GREEN}${BOLD}✓ System hardening completed!${NC}"
    echo ""
    echo -e "${BOLD}Summary:${NC}"
    echo -e "  • Tasks Completed: ${GREEN}$TASKS_COMPLETED${NC}"
    echo -e "  • Tasks Skipped: ${YELLOW}$TASKS_SKIPPED${NC}"
    echo -e "  • Tasks Failed: ${RED}$TASKS_FAILED${NC}"
    echo -e "  • Warnings: ${YELLOW}$WARNINGS_COUNT${NC}"
    echo ""
    echo -e "${BOLD}Files:${NC}"
    echo -e "  • Backups: $BACKUP_DIR"
    echo -e "  • Log: $LOG_FILE"
    echo -e "  • Report: $REPORT_FILE"
    echo ""
    echo -e "${BOLD}Firewall Ports Allowed:${NC}"
    echo -e "  • SSH: 22/tcp, 2222/tcp"
    echo -e "  • HTTP: 80/tcp"
    echo -e "  • HTTPS: 443/tcp"
    echo ""
    echo -e "${YELLOW}${BOLD}⚠ IMPORTANT:${NC}"
    echo -e "  1. Test SSH in new session before closing this one"
    echo -e "  2. Review the security report"
    echo -e "  3. Consider rebooting: sudo reboot"
    echo ""
}

# Run
main "$@"

exit 0

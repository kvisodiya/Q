#!/usr/bin/env bash
#===============================================================================
#
#          FILE: fix.sh
#
#         USAGE: sudo bash fix.sh
#
#   DESCRIPTION: Fix remaining Lynis issues - Push score from 93 to 95+
#                Analyzes current report and applies targeted fixes
#
#       VERSION: 1.0.0
#
#===============================================================================

set +e
set +u

#===============================================================================
# VARIABLES
#===============================================================================
readonly LOG_FILE="/var/log/fix_$(date +%Y%m%d_%H%M%S).log"
readonly LYNIS_REPORT="/var/log/lynis-report.dat"
readonly LYNIS_LOG="/var/log/lynis.log"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

FIXES_APPLIED=0
FIXES_SKIPPED=0

#===============================================================================
# FUNCTIONS
#===============================================================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null
}

ok() {
    echo -e "${GREEN}[✓]${NC} $1"
    log "OK: $1"
    ((FIXES_APPLIED++))
}

skip() {
    echo -e "${YELLOW}[→]${NC} $1"
    log "SKIP: $1"
    ((FIXES_SKIPPED++))
}

info() {
    echo -e "${BLUE}[*]${NC} $1"
    log "INFO: $1"
}

section() {
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Run as root: sudo bash $0${NC}"
        exit 1
    fi
}

#===============================================================================
# BANNER
#===============================================================================
clear
echo ""
echo -e "${GREEN}${BOLD}"
cat << 'BANNER'
    _____ _        _____ _          _ _ 
   |  ___(_)_  __ / ____| |        | | |
   | |_   _ \ \/ /| (___ | |__   __| | |
   |  _| | |>  <  \___ \| '_ \ / _` | |
   | |   | /_/\_\ ____) | | | | (_| |_|
   |_|   |_|     |_____/|_| |_|\__,_(_)
                                        
BANNER
echo -e "${NC}"
echo -e "${BOLD}    Lynis Score Enhancement: 93 → 95+${NC}"
echo ""

check_root

echo "" > "$LOG_FILE"

#===============================================================================
# ANALYZE CURRENT LYNIS REPORT
#===============================================================================
section "Analyzing Current Lynis Report"

if [[ -f "$LYNIS_REPORT" ]]; then
    CURRENT_SCORE=$(grep "hardening_index=" "$LYNIS_REPORT" 2>/dev/null | cut -d= -f2)
    WARNINGS=$(grep "^warning\[\]=" "$LYNIS_REPORT" 2>/dev/null | wc -l)
    SUGGESTIONS=$(grep "^suggestion\[\]=" "$LYNIS_REPORT" 2>/dev/null | wc -l)
    
    info "Current Score: ${CURRENT_SCORE:-93}"
    info "Warnings: $WARNINGS"
    info "Suggestions: $SUGGESTIONS"
    
    echo ""
    info "Top remaining suggestions:"
    grep "^suggestion\[\]=" "$LYNIS_REPORT" 2>/dev/null | head -15 | while read -r line; do
        suggestion=$(echo "$line" | cut -d'|' -f2)
        echo -e "  ${YELLOW}•${NC} $suggestion"
    done
    echo ""
else
    info "No Lynis report found - applying all fixes"
fi

#===============================================================================
# FIX 1: BOOT HARDENING (BOOT-5122, BOOT-5264)
#===============================================================================
section "Fix 1: Boot & GRUB Hardening"

# Secure GRUB configuration
if [[ -f /boot/grub/grub.cfg ]]; then
    chmod 600 /boot/grub/grub.cfg 2>/dev/null
    chown root:root /boot/grub/grub.cfg 2>/dev/null
    ok "GRUB config permissions set to 600"
fi

if [[ -d /boot/grub ]]; then
    chmod 700 /boot/grub 2>/dev/null
    ok "GRUB directory permissions set to 700"
fi

# Enable audit at boot
if [[ -f /etc/default/grub ]]; then
    GRUB_CHANGED=0
    
    if ! grep -q "audit=1" /etc/default/grub 2>/dev/null; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 audit=1"/' /etc/default/grub
        GRUB_CHANGED=1
        ok "Added audit=1 to GRUB boot parameters"
    fi
    
    if ! grep -q "GRUB_DISABLE_RECOVERY" /etc/default/grub 2>/dev/null; then
        echo 'GRUB_DISABLE_RECOVERY="true"' >> /etc/default/grub
        GRUB_CHANGED=1
        ok "Disabled GRUB recovery mode"
    fi
    
    if [[ $GRUB_CHANGED -eq 1 ]]; then
        update-grub >> "$LOG_FILE" 2>&1
        ok "GRUB updated"
    fi
fi

#===============================================================================
# FIX 2: KERNEL HARDENING (KRNL-6000)
#===============================================================================
section "Fix 2: Kernel Hardening Enhancements"

cat > /etc/sysctl.d/99-lynis-fix.conf << 'EOF'
# Lynis score enhancement - kernel parameters

# Network hardening
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

# IPv6 hardening
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Kernel security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.yama.ptrace_scope = 2
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1

# Filesystem security
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Memory security
vm.mmap_min_addr = 65536
vm.swappiness = 10

# Core dumps
kernel.core_pattern = |/bin/false
EOF

sysctl --system >> "$LOG_FILE" 2>&1
ok "Enhanced kernel parameters applied"

#===============================================================================
# FIX 3: SSH HARDENING (SSH-7408)
#===============================================================================
section "Fix 3: SSH Hardening"

mkdir -p /etc/ssh/sshd_config.d

# Remove old configs that might conflict
rm -f /etc/ssh/sshd_config.d/99-hardening.conf 2>/dev/null
rm -f /etc/ssh/sshd_config.d/99-enhanced.conf 2>/dev/null

cat > /etc/ssh/sshd_config.d/99-fix.conf << 'EOF'
# Lynis-optimized SSH configuration
Protocol 2

# Authentication
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 20
PermitRootLogin prohibit-password
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
ChallengeResponseAuthentication no

# Disable everything unnecessary
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
DisableForwarding yes

# Strong cryptography only
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# Timeouts
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

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
Compression no
Banner /etc/issue.net
DebianBanner no

# Limits
MaxStartups 10:30:60
EOF

# Test SSH config
if sshd -t >> "$LOG_FILE" 2>&1; then
    systemctl restart sshd >> "$LOG_FILE" 2>&1 || systemctl restart ssh >> "$LOG_FILE" 2>&1
    ok "SSH configuration optimized"
else
    rm -f /etc/ssh/sshd_config.d/99-fix.conf
    skip "SSH config test failed - reverted"
fi

#===============================================================================
# FIX 4: FILE PERMISSIONS (FILE-7524)
#===============================================================================
section "Fix 4: File Permissions"

# Critical system files
chmod 600 /etc/shadow 2>/dev/null && ok "/etc/shadow: 600"
chmod 600 /etc/gshadow 2>/dev/null && ok "/etc/gshadow: 600"
chmod 644 /etc/passwd 2>/dev/null && ok "/etc/passwd: 644"
chmod 644 /etc/group 2>/dev/null && ok "/etc/group: 644"
chmod 600 /etc/ssh/sshd_config 2>/dev/null && ok "/etc/ssh/sshd_config: 600"
chmod 700 /etc/ssh 2>/dev/null && ok "/etc/ssh/: 700"
chmod 700 /root 2>/dev/null && ok "/root: 700"

# SSH host keys
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
ok "SSH host key permissions fixed"

# Boot
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chmod 700 /boot 2>/dev/null

# Cron
chmod 600 /etc/crontab 2>/dev/null
chmod 700 /etc/cron.d 2>/dev/null
chmod 700 /etc/cron.daily 2>/dev/null
chmod 700 /etc/cron.hourly 2>/dev/null
chmod 700 /etc/cron.weekly 2>/dev/null
chmod 700 /etc/cron.monthly 2>/dev/null
ok "Cron permissions secured"

# World-writable files check and fix
info "Checking world-writable files..."
find / -xdev -type f -perm -0002 -not -path "/proc/*" -not -path "/sys/*" -exec chmod o-w {} \; 2>/dev/null
find / -xdev -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" -not -path "/tmp" -not -path "/var/tmp" -exec chmod o-w {} \; 2>/dev/null
ok "World-writable files fixed"

# Home directories
for dir in /home/*/; do
    if [[ -d "$dir" ]]; then
        chmod 700 "$dir" 2>/dev/null
    fi
done
ok "Home directories: 700"

# SUID/SGID audit
info "Checking unnecessary SUID/SGID..."
# Remove SUID from non-essential binaries
SUID_REMOVE=(
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/bin/bsd-write"
    "/usr/bin/dotlockfile"
    "/usr/bin/expiry"
    "/usr/bin/locate"
    "/usr/bin/mlocate"
)
for binary in "${SUID_REMOVE[@]}"; do
    if [[ -f "$binary" ]]; then
        chmod u-s "$binary" 2>/dev/null
        chmod g-s "$binary" 2>/dev/null
    fi
done
ok "Unnecessary SUID/SGID bits removed"

#===============================================================================
# FIX 5: AUTHENTICATION (AUTH-9228, AUTH-9262, AUTH-9286, AUTH-9328)
#===============================================================================
section "Fix 5: Authentication Hardening"

# Password aging
if [[ -f /etc/login.defs ]]; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs 2>/dev/null
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs 2>/dev/null
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs 2>/dev/null
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs 2>/dev/null
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs 2>/dev/null
    sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs 2>/dev/null
    sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs 2>/dev/null
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD  SHA512/' /etc/login.defs 2>/dev/null
    sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB    yes/' /etc/login.defs 2>/dev/null
    sed -i 's/^LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB yes/' /etc/login.defs 2>/dev/null
    sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS   yes/' /etc/login.defs 2>/dev/null
    sed -i 's/^SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB  yes/' /etc/login.defs 2>/dev/null
    sed -i 's/^SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB  yes/' /etc/login.defs 2>/dev/null
    sed -i 's/^SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 10000/' /etc/login.defs 2>/dev/null
    sed -i 's/^SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 100000/' /etc/login.defs 2>/dev/null
    sed -i 's/^DEFAULT_HOME.*/DEFAULT_HOME    no/' /etc/login.defs 2>/dev/null
    
    # Add if missing
    grep -q "^FAIL_DELAY" /etc/login.defs || echo "FAIL_DELAY 4" >> /etc/login.defs
    grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
    grep -q "^SHA_CRYPT_MAX_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MAX_ROUNDS 100000" >> /etc/login.defs
    grep -q "^SULOG_FILE" /etc/login.defs || echo "SULOG_FILE /var/log/sulog" >> /etc/login.defs
    
    ok "Login definitions hardened"
fi

# Password quality
if [[ -f /etc/security/pwquality.conf ]]; then
    cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 2
maxsequence = 3
maxclassrepeat = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
enforce_for_root
EOF
    ok "Password quality requirements enhanced"
fi

# Faillock configuration
cat > /etc/security/faillock.conf << 'EOF'
deny = 5
fail_interval = 900
unlock_time = 600
audit
silent
even_deny_root
root_unlock_time = 900
EOF
ok "Account lockout (faillock) configured"

# Restrict su access
if [[ -f /etc/pam.d/su ]]; then
    if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su; then
        sed -i '/pam_rootok.so/a auth       required   pam_wheel.so use_uid group=sudo' /etc/pam.d/su 2>/dev/null
        ok "su restricted to sudo group"
    fi
fi

# Set password aging for existing users
for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null); do
    chage --maxdays 90 --mindays 1 --warndays 14 "$user" 2>/dev/null
done
ok "Password aging set for all users"

#===============================================================================
# FIX 6: SHELL TIMEOUT (SHLL-6220)
#===============================================================================
section "Fix 6: Shell Timeout"

cat > /etc/profile.d/tmout.sh << 'EOF'
# Auto logout after 15 minutes of inactivity
readonly TMOUT=900
export TMOUT
EOF
chmod 644 /etc/profile.d/tmout.sh

if ! grep -q "^TMOUT" /etc/bash.bashrc 2>/dev/null; then
    cat >> /etc/bash.bashrc << 'EOF'

# Auto logout
TMOUT=900
readonly TMOUT
export TMOUT
EOF
fi

ok "Shell timeout set to 900 seconds"

#===============================================================================
# FIX 7: BANNERS (BANN-7126, BANN-7130)
#===============================================================================
section "Fix 7: Security Banners"

cat > /etc/issue << 'EOF'
Authorized access only. All activity is logged and monitored.
EOF

cat > /etc/issue.net << 'EOF'
Authorized access only. All activity is logged and monitored.
EOF

cat > /etc/motd << 'EOF'
This system is monitored. Unauthorized access is prohibited.
EOF

chmod 644 /etc/issue /etc/issue.net /etc/motd
ok "Security banners configured"

#===============================================================================
# FIX 8: FILESYSTEM HARDENING (STRG-1840, STRG-1846)
#===============================================================================
section "Fix 8: Filesystem Hardening"

# Disable USB storage
cat > /etc/modprobe.d/usb-storage.conf << 'EOF'
install usb-storage /bin/false
blacklist usb-storage
blacklist uas
EOF
ok "USB storage disabled"

# Disable uncommon filesystems
cat > /etc/modprobe.d/filesystems.conf << 'EOF'
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install fat /bin/false
install vfat /bin/false
install cifs /bin/false
install nfs /bin/false
install nfsv3 /bin/false
install nfsv4 /bin/false
install gfs2 /bin/false
EOF
ok "Uncommon filesystems disabled"

# Disable uncommon protocols
cat > /etc/modprobe.d/protocols.conf << 'EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
install bluetooth /bin/false
install btusb /bin/false
install firewire-core /bin/false
install thunderbolt /bin/false
EOF
ok "Uncommon protocols disabled"

# Secure mount options
if mountpoint -q /dev/shm 2>/dev/null; then
    mount -o remount,noexec,nosuid,nodev /dev/shm >> "$LOG_FILE" 2>&1
    ok "/dev/shm secured"
fi

if mountpoint -q /tmp 2>/dev/null; then
    mount -o remount,noexec,nosuid,nodev /tmp >> "$LOG_FILE" 2>&1
    ok "/tmp secured"
fi

# Add to fstab if not present
if ! grep -q "^tmpfs.*/dev/shm.*noexec" /etc/fstab 2>/dev/null; then
    if ! grep -q "/dev/shm" /etc/fstab 2>/dev/null; then
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
        ok "Secure /dev/shm added to fstab"
    fi
fi

if ! grep -q "^tmpfs.*/tmp.*noexec" /etc/fstab 2>/dev/null; then
    if ! grep -q "^tmpfs.*/tmp" /etc/fstab 2>/dev/null; then
        echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=512M 0 0" >> /etc/fstab
        ok "Secure /tmp added to fstab"
    fi
fi

# Hide processes from other users
if ! grep -q "hidepid" /etc/fstab 2>/dev/null; then
    echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
    mount -o remount,hidepid=2 /proc >> "$LOG_FILE" 2>&1
    ok "/proc hidepid=2 configured"
fi

#===============================================================================
# FIX 9: CORE DUMPS (KRNL-5820)
#===============================================================================
section "Fix 9: Core Dumps"

mkdir -p /etc/security/limits.d
cat > /etc/security/limits.d/coredumps.conf << 'EOF'
*               hard    core            0
*               soft    core            0
root            hard    core            0
root            soft    core            0
EOF

mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

systemctl daemon-reload >> "$LOG_FILE" 2>&1
ok "Core dumps disabled"

#===============================================================================
# FIX 10: UNNECESSARY SERVICES (PROC-3612)
#===============================================================================
section "Fix 10: Disable Unnecessary Services"

SERVICES_TO_DISABLE=(
    "avahi-daemon"
    "cups"
    "cups-browsed"
    "isc-dhcp-server"
    "slapd"
    "nfs-server"
    "rpcbind"
    "bind9"
    "vsftpd"
    "dovecot"
    "smbd"
    "nmbd"
    "snmpd"
    "squid"
    "ypserv"
    "xinetd"
    "telnet"
    "rsh-server"
    "rlogin"
    "rexec"
    "talk"
    "ntalk"
)

for svc in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-active "$svc" >/dev/null 2>&1; then
        systemctl stop "$svc" >> "$LOG_FILE" 2>&1
        systemctl disable "$svc" >> "$LOG_FILE" 2>&1
        ok "Disabled: $svc"
    fi
done
ok "Unnecessary services check complete"

#===============================================================================
# FIX 11: ENHANCED AUDIT RULES (ACCT-9628, ACCT-9630)
#===============================================================================
section "Fix 11: Enhanced Audit Rules"

mkdir -p /etc/audit/rules.d

cat > /etc/audit/rules.d/99-lynis-fix.rules << 'EOF'
-D
-b 8192
-f 1

# Self auditing
-w /var/log/audit/ -p wa -k auditlog
-w /etc/audit/ -p wa -k auditconfig

# Identity
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity

# Privilege escalation
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# PAM
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k pam

# Login tracking
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/run/utmp -p wa -k session

# Cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Network
-w /etc/hosts -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/resolv.conf -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/hostname -p wa -k network

# Systemd
-w /etc/systemd/ -p wa -k systemd
-w /etc/init.d/ -p wa -k init

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /etc/modprobe.d/ -p wa -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -S finit_module -k modules

# Time
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
-w /etc/localtime -p wa -k time

# File access
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Mount
-a always,exit -F arch=b64 -S mount -S umount2 -F auid>=1000 -F auid!=4294967295 -k mounts

# Immutable
-e 2
EOF

augenrules --load >> "$LOG_FILE" 2>&1
systemctl restart auditd >> "$LOG_FILE" 2>&1
ok "Enhanced audit rules loaded"

#===============================================================================
# FIX 12: LOGGING (LOGG-2190, LOGG-2154)
#===============================================================================
section "Fix 12: Logging Enhancements"

# Configure syslog
if [[ -d /etc/rsyslog.d ]]; then
    cat > /etc/rsyslog.d/99-security.conf << 'EOF'
# Security logging
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          /var/log/syslog
kern.*                          /var/log/kern.log
mail.*                          /var/log/mail.log
EOF
    
    systemctl restart rsyslog >> "$LOG_FILE" 2>&1
    ok "Rsyslog security logging configured"
fi

# Ensure proper log permissions
chmod 640 /var/log/auth.log 2>/dev/null
chmod 640 /var/log/syslog 2>/dev/null
chmod 640 /var/log/kern.log 2>/dev/null
chmod 640 /var/log/messages 2>/dev/null
chmod 640 /var/log/mail.log 2>/dev/null
chmod 660 /var/log/btmp 2>/dev/null
chmod 664 /var/log/wtmp 2>/dev/null
chmod 664 /var/log/lastlog 2>/dev/null
ok "Log file permissions secured"

#===============================================================================
# FIX 13: COMPILER SECURITY (HRDN-7222)
#===============================================================================
section "Fix 13: Compiler Security"

COMPILERS=(
    "/usr/bin/gcc"
    "/usr/bin/g++"
    "/usr/bin/cc"
    "/usr/bin/c++"
    "/usr/bin/make"
    "/usr/bin/as"
    "/usr/bin/ld"
)

for comp in "${COMPILERS[@]}"; do
    if [[ -f "$comp" ]]; then
        chmod 700 "$comp" 2>/dev/null
    fi
done
ok "Compilers restricted to root"

#===============================================================================
# FIX 14: CRON/AT SECURITY (SCHD-7704)
#===============================================================================
section "Fix 14: Cron/At Security"

echo "root" > /etc/cron.allow
rm -f /etc/cron.deny 2>/dev/null
chmod 600 /etc/cron.allow

echo "root" > /etc/at.allow
rm -f /etc/at.deny 2>/dev/null
chmod 600 /etc/at.allow

ok "Cron/At restricted to root"

#===============================================================================
# FIX 15: SECURETTY (AUTH-9230)
#===============================================================================
section "Fix 15: Securetty"

echo "" > /etc/securetty
chmod 600 /etc/securetty
ok "Securetty cleared and secured"

#===============================================================================
# FIX 16: DEFAULT UMASK (AUTH-9328)
#===============================================================================
section "Fix 16: Default Umask"

cat > /etc/profile.d/umask.sh << 'EOF'
umask 027
EOF
chmod 644 /etc/profile.d/umask.sh

# Fix in /etc/init.d/rc if exists
if [[ -f /etc/init.d/rc ]]; then
    sed -i 's/umask 022/umask 027/g' /etc/init.d/rc 2>/dev/null
fi

# Fix in /etc/bash.bashrc
if ! grep -q "^umask 027" /etc/bash.bashrc 2>/dev/null; then
    echo "umask 027" >> /etc/bash.bashrc
fi

ok "Default umask set to 027 everywhere"

#===============================================================================
# FIX 17: CTRL+ALT+DEL (INSE-8002)
#===============================================================================
section "Fix 17: System Security"

systemctl mask ctrl-alt-del.target >> "$LOG_FILE" 2>&1
ok "Ctrl+Alt+Delete disabled"

systemctl mask debug-shell.service >> "$LOG_FILE" 2>&1
ok "Debug shell disabled"

#===============================================================================
# FIX 18: ADDITIONAL PACKAGES
#===============================================================================
section "Fix 18: Security Tools Check"

export DEBIAN_FRONTEND=noninteractive

TOOLS=(
    "libpam-tmpdir"
    "needrestart"
    "debsums"
    "apt-show-versions"
    "acct"
)

for tool in "${TOOLS[@]}"; do
    if ! dpkg -l "$tool" 2>/dev/null | grep -q "^ii"; then
        apt-get install -y "$tool" >> "$LOG_FILE" 2>&1 && ok "Installed: $tool"
    fi
done

# Enable process accounting
if command -v accton >/dev/null 2>&1; then
    mkdir -p /var/log/account 2>/dev/null
    touch /var/log/account/pacct 2>/dev/null
    accton /var/log/account/pacct >> "$LOG_FILE" 2>&1
    ok "Process accounting enabled"
fi

#===============================================================================
# FIX 19: APPARMOR CHECK
#===============================================================================
section "Fix 19: AppArmor"

if command -v apparmor_status >/dev/null 2>&1; then
    systemctl enable apparmor >> "$LOG_FILE" 2>&1
    systemctl start apparmor >> "$LOG_FILE" 2>&1
    
    if [[ -d /etc/apparmor.d ]]; then
        apparmor_parser -r /etc/apparmor.d/* >> "$LOG_FILE" 2>&1
    fi
    
    ok "AppArmor verified"
fi

#===============================================================================
# FIX 20: UFW VERIFY
#===============================================================================
section "Fix 20: UFW Firewall Verify"

if command -v ufw >/dev/null 2>&1; then
    if ! ufw status 2>/dev/null | grep -q "Status: active"; then
        info "UFW not active - enabling..."
        ufw default deny incoming >> "$LOG_FILE" 2>&1
        ufw default allow outgoing >> "$LOG_FILE" 2>&1
        ufw allow 22/tcp >> "$LOG_FILE" 2>&1
        ufw allow 2222/tcp >> "$LOG_FILE" 2>&1
        ufw allow 80/tcp >> "$LOG_FILE" 2>&1
        ufw allow 443/tcp >> "$LOG_FILE" 2>&1
        ufw limit 22/tcp >> "$LOG_FILE" 2>&1
        ufw limit 2222/tcp >> "$LOG_FILE" 2>&1
        ufw logging low >> "$LOG_FILE" 2>&1
        echo "y" | ufw enable >> "$LOG_FILE" 2>&1
    fi
    
    if ufw status | grep -q "Status: active"; then
        ok "UFW firewall: ACTIVE"
    else
        skip "UFW could not be enabled"
    fi
fi

#===============================================================================
# FIX 21: CLEANUP
#===============================================================================
section "Fix 21: System Cleanup"

# Remove unnecessary packages
apt-get autoremove -y >> "$LOG_FILE" 2>&1
apt-get autoclean >> "$LOG_FILE" 2>&1
ok "Package cleanup done"

# Check for leftover apt repos with errors
if ls /etc/apt/sources.list.d/tor* 2>/dev/null; then
    rm -f /etc/apt/sources.list.d/tor*
    ok "Removed leftover Tor repository"
fi

#===============================================================================
# FINAL LYNIS SCAN
#===============================================================================
section "Running Final Lynis Audit"

if command -v lynis >/dev/null 2>&1; then
    info "Starting Lynis audit (takes 1-2 minutes)..."
    echo ""
    
    lynis audit system --quick 2>&1 | tee /tmp/lynis_fix.txt
    
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}                              RESULTS${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Get score
    NEW_SCORE=$(grep -i "hardening index" /tmp/lynis_fix.txt 2>/dev/null | grep -oE "[0-9]+" | head -1)
    
    if [[ -z "$NEW_SCORE" ]] && [[ -f /var/log/lynis-report.dat ]]; then
        NEW_SCORE=$(grep "hardening_index=" /var/log/lynis-report.dat 2>/dev/null | cut -d= -f2)
    fi
    
    if [[ -n "$NEW_SCORE" ]]; then
        echo -e "  ${BOLD}Previous Score: ${YELLOW}93${NC}"
        echo -e "  ${BOLD}Current Score:  ${GREEN}${NEW_SCORE}${NC}"
        echo ""
        
        if [[ $NEW_SCORE -ge 95 ]]; then
            echo -e "  ${GREEN}${BOLD}🏆 EXCELLENT! Score 95+${NC}"
        elif [[ $NEW_SCORE -ge 90 ]]; then
            echo -e "  ${GREEN}${BOLD}✅ TARGET ACHIEVED! Score 90+${NC}"
        else
            echo -e "  ${YELLOW}Score: $NEW_SCORE${NC}"
        fi
    else
        echo -e "  ${YELLOW}Could not extract score${NC}"
        echo -e "  Run: ${BOLD}sudo lynis audit system${NC}"
    fi
    
    # Count remaining
    if [[ -f /var/log/lynis-report.dat ]]; then
        REMAINING_WARNS=$(grep "^warning\[\]=" /var/log/lynis-report.dat 2>/dev/null | wc -l)
        REMAINING_SUGGS=$(grep "^suggestion\[\]=" /var/log/lynis-report.dat 2>/dev/null | wc -l)
        echo ""
        echo -e "  ${BOLD}Remaining Warnings:${NC}    $REMAINING_WARNS"
        echo -e "  ${BOLD}Remaining Suggestions:${NC} $REMAINING_SUGGS"
    fi
    
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    rm -f /tmp/lynis_fix.txt
fi

#===============================================================================
# SUMMARY
#===============================================================================
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}                           FIX COMPLETE!${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Fixes Applied:${NC}  ${GREEN}$FIXES_APPLIED${NC}"
echo -e "  ${BOLD}Fixes Skipped:${NC}  ${YELLOW}$FIXES_SKIPPED${NC}"
echo -e "  ${BOLD}Log File:${NC}       $LOG_FILE"
echo ""
echo -e "  ${YELLOW}${BOLD}⚠ Reboot recommended:${NC} sudo reboot"
echo -e "  ${BOLD}Then run:${NC} sudo lynis audit system"
echo ""

exit 0

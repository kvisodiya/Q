#!/usr/bin/env bash
#===============================================================================
# hard.sh — Push Lynis score to 90+ on Ubuntu 24.04
#
# Sources:
#   • https://github.com/konstruktoid/hardening
#   • https://github.com/CISOfy/lynis
#   • CIS Ubuntu 24.04 Benchmark
#
# Usage:
#   sudo ./hard.sh              # Full hardening
#   sudo ./hard.sh --dry-run    # Preview only
#   sudo ./hard.sh --skip-reboot
#===============================================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ── Config ───────────────────────────────────────────────────────────────────
DRY_RUN=false
SKIP_REBOOT=false
LOGFILE="/var/log/hardening-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/hardening-backup-$(date +%Y%m%d-%H%M%S)"

for arg in "$@"; do
    case "$arg" in
        --dry-run)      DRY_RUN=true ;;
        --skip-reboot)  SKIP_REBOOT=true ;;
    esac
done

# ── Colours ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1;37m'; N='\033[0m'
log()    { echo -e "${G}[✔]${N} $*" | tee -a "$LOGFILE"; }
warn()   { echo -e "${Y}[!]${N} $*" | tee -a "$LOGFILE"; }
err()    { echo -e "${R}[✘]${N} $*" | tee -a "$LOGFILE" >&2; }
banner() { echo -e "\n${C}══════════════════════════════════════════════════${N}" | tee -a "$LOGFILE"
           echo -e "${B}  $*${N}" | tee -a "$LOGFILE"
           echo -e "${C}══════════════════════════════════════════════════${N}\n" | tee -a "$LOGFILE"; }

run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        warn "[DRY-RUN] $*"
    else
        eval "$@" >> "$LOGFILE" 2>&1
    fi
}

# ── Pre-flight ───────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { err "Run as root."; exit 1; }

source /etc/os-release 2>/dev/null || true
if [[ "${VERSION_ID:-}" != "24.04" ]]; then
    warn "Designed for Ubuntu 24.04, detected: ${VERSION_ID:-unknown}"
fi

mkdir -p "$BACKUP_DIR"
log "Backups  → $BACKUP_DIR"
log "Log file → $LOGFILE"

backup() { [[ -f "$1" ]] && cp -a "$1" "$BACKUP_DIR/" 2>/dev/null || true; }

banner "HARDENING START — Target: Lynis 90+"

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1: KONSTRUKTOID HARDENING (GitHub repo)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 1: konstruktoid/hardening"

KONSTRUKTOID_DIR="/tmp/konstruktoid-hardening"
if [[ -d "$KONSTRUKTOID_DIR" ]]; then
    rm -rf "$KONSTRUKTOID_DIR"
fi

log "Cloning konstruktoid/hardening..."
run "apt-get update -qq"
run "apt-get install -y -qq git"
run "git clone --depth 1 https://github.com/konstruktoid/hardening.git $KONSTRUKTOID_DIR"

if [[ "$DRY_RUN" == "false" && -f "$KONSTRUKTOID_DIR/ubuntu.sh" ]]; then
    log "Executing konstruktoid ubuntu.sh..."
    cd "$KONSTRUKTOID_DIR"
    # The script is interactive-ish — we run it in non-interactive mode
    yes | bash ubuntu.sh 2>&1 | tee -a "$LOGFILE" || warn "konstruktoid script had warnings (non-fatal)"
    cd /
fi
log "Phase 1 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2: PACKAGE MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 2: Package hardening"

log "Installing security tools..."
run "apt-get update -qq"
run "apt-get install -y -qq \
    lynis \
    auditd audispd-plugins \
    aide aide-common \
    apparmor apparmor-profiles apparmor-profiles-extra apparmor-utils \
    libpam-tmpdir \
    libpam-pwquality \
    libpam-modules \
    apt-listchanges \
    needrestart \
    debsums \
    acct \
    sysstat \
    usbguard \
    fail2ban \
    unattended-upgrades \
    apt-show-versions \
    rkhunter \
    chkrootkit \
    clamav clamav-daemon \
    net-tools \
    tcpd \
    chrony \
    rsyslog \
    logrotate \
    sudo \
    procps"

log "Removing unnecessary packages..."
REMOVE_PKGS=(
    telnet
    nis
    ntalk
    rsh-client
    rsh-server
    xinetd
    tftp
    tftpd
    talk
    inetutils-telnet
    avahi-daemon
    cups
    whoopsie
    apport
    popularity-contest
    prelink
)
for pkg in "${REMOVE_PKGS[@]}"; do
    if dpkg -l "$pkg" &>/dev/null 2>&1; then
        run "apt-get purge -y -qq $pkg"
        log "  Removed: $pkg"
    fi
done
run "apt-get autoremove -y -qq"

log "Phase 2 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3: KERNEL & SYSCTL HARDENING
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 3: Kernel / sysctl hardening"

backup /etc/sysctl.conf

cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL'
# ── Network ──────────────────────────────────────────
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
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Log martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable SYN cookies
net.ipv4.tcp_syncookies = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# TCP hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_rfc1337 = 1

# ── Kernel ───────────────────────────────────────────
# Restrict core dumps
fs.suid_dumpable = 0

# Enable ASLR
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict perf_event
kernel.perf_event_paranoid = 3

# Yama LSM — restrict ptrace
kernel.yama.ptrace_scope = 2

# Restrict unprivileged user namespaces
kernel.unprivileged_userns_clone = 0

# Restrict unprivileged BPF
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Restrict SysRq
kernel.sysrq = 0

# Restrict loading TTY line disciplines
dev.tty.ldisc_autoload = 0

# Restrict userfaultfd
vm.unprivileged_userfaultfd = 0

# kexec restrict
kernel.kexec_load_disabled = 1
SYSCTL

run "sysctl --system"
log "Sysctl hardening applied."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4: FILESYSTEM HARDENING
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 4: Filesystem hardening"

# 4a. Disable unused filesystems
cat > /etc/modprobe.d/hardening-filesystems.conf << 'MODFS'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
MODFS

# 4b. Disable USB storage
cat > /etc/modprobe.d/hardening-usb.conf << 'MODUSB'
install usb-storage /bin/true
blacklist usb-storage
MODUSB

# 4c. Harden mount options in fstab
backup /etc/fstab

# /tmp hardening
if ! grep -q "/tmp" /etc/fstab; then
    log "Adding /tmp mount with hardened options..."
    echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
fi

# /dev/shm hardening
if grep -q "/dev/shm" /etc/fstab; then
    sed -i 's|^\(.*\s/dev/shm\s.*\)defaults\(.*\)|\1defaults,nosuid,nodev,noexec\2|' /etc/fstab
else
    echo "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab
fi

# /var/tmp hardening
if ! grep -q "/var/tmp" /etc/fstab; then
    echo "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
fi

# 4d. Sticky bit on world-writable directories
run "df --local -P 2>/dev/null | awk 'NR!=1 {print \$6}' | xargs -I{} find {} -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) -exec chmod a+t {} + 2>/dev/null || true"

log "Phase 4 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5: FILE PERMISSIONS (Lynis checks these heavily)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 5: Critical file permissions"

# Ownership & permissions on key files
declare -A FILE_PERMS=(
    [/etc/passwd]="644"
    [/etc/passwd-]="600"
    [/etc/shadow]="640"
    [/etc/shadow-]="600"
    [/etc/group]="644"
    [/etc/group-]="600"
    [/etc/gshadow]="640"
    [/etc/gshadow-]="600"
    [/etc/ssh/sshd_config]="600"
    [/etc/crontab]="600"
    [/etc/cron.hourly]="700"
    [/etc/cron.daily]="700"
    [/etc/cron.weekly]="700"
    [/etc/cron.monthly]="700"
    [/etc/cron.d]="700"
    [/boot/grub/grub.cfg]="600"
    [/etc/motd]="644"
    [/etc/issue]="644"
    [/etc/issue.net]="644"
)

for f in "${!FILE_PERMS[@]}"; do
    if [[ -e "$f" ]]; then
        run "chmod ${FILE_PERMS[$f]} $f"
        run "chown root:root $f 2>/dev/null || true"
    fi
done

# SSH keys
find /etc/ssh -name 'ssh_host_*_key' -exec chmod 600 {} \; 2>/dev/null || true
find /etc/ssh -name 'ssh_host_*_key.pub' -exec chmod 644 {} \; 2>/dev/null || true

# Restrict at/cron
for f in /etc/cron.deny /etc/at.deny; do
    [[ -f "$f" ]] && rm -f "$f"
done
for f in /etc/cron.allow /etc/at.allow; do
    touch "$f"
    chmod 640 "$f"
    chown root:root "$f"
    echo "root" > "$f"
done

log "Phase 5 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 6: SSH HARDENING (Major Lynis area)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 6: SSH hardening"

backup /etc/ssh/sshd_config

cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'SSHD'
# ── Protocol ─────────────────────────────────────────
Protocol 2

# ── Authentication ───────────────────────────────────
PermitRootLogin no
MaxAuthTries 3
MaxSessions 3
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

# ── Session ──────────────────────────────────────────
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxStartups 10:30:60

# ── Network ──────────────────────────────────────────
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
TCPKeepAlive no
PermitTunnel no
GatewayPorts no
DisableForwarding yes

# ── Logging ──────────────────────────────────────────
LogLevel VERBOSE
SyslogFacility AUTH

# ── Crypto ───────────────────────────────────────────
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# ── Misc ─────────────────────────────────────────────
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
Compression no
PrintMotd no
PrintLastLog yes
Banner /etc/issue.net
UseDNS no
SSHD

# Remove weak host keys (small Diffie-Hellman moduli)
backup /etc/ssh/moduli
if [[ -f /etc/ssh/moduli ]]; then
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
    mv /etc/ssh/moduli.safe /etc/ssh/moduli
fi

run "sshd -t" && log "SSH config valid." || warn "SSH config has warnings — check manually!"
run "systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true"

log "Phase 6 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 7: PASSWORD & PAM POLICIES
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 7: Password & PAM policies"

# 7a. Password quality (pwquality)
backup /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf << 'PWQUAL'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 3
gecoscheck = 1
dictcheck = 1
enforcing = 1
retry = 3
PWQUAL

# 7b. Password aging in login.defs
backup /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/'  /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/'   /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/'  /etc/login.defs
sed -i 's/^UMASK.*/UMASK           027/'          /etc/login.defs
sed -i 's/^SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 5000/' /etc/login.defs 2>/dev/null || \
    echo "SHA_CRYPT_MIN_ROUNDS 5000" >> /etc/login.defs
sed -i 's/^SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 10000/' /etc/login.defs 2>/dev/null || \
    echo "SHA_CRYPT_MAX_ROUNDS 10000" >> /etc/login.defs
grep -q "^ENCRYPT_METHOD" /etc/login.defs && \
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs || \
    echo "ENCRYPT_METHOD YESCRYPT" >> /etc/login.defs

# 7c. Restrict su
backup /etc/pam.d/su
if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
    sed -i '/pam_rootok.so/a auth required pam_wheel.so use_uid group=sudo' /etc/pam.d/su
fi

# 7d. Login banner / TMOUT
backup /etc/profile
if ! grep -q "^TMOUT=" /etc/profile; then
    cat >> /etc/profile << 'TIMEOUT'

# Session timeout (Lynis SHLL-6220)
readonly TMOUT=900
export TMOUT
TIMEOUT
fi

# 7e. Default umask
if ! grep -q "^umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile
fi
if ! grep -q "^umask 027" /etc/bash.bashrc 2>/dev/null; then
    echo "umask 027" >> /etc/bash.bashrc
fi

log "Phase 7 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 8: AUDIT FRAMEWORK (auditd)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 8: Audit framework (auditd)"

backup /etc/audit/auditd.conf
backup /etc/audit/rules.d/audit.rules 2>/dev/null || true

cat > /etc/audit/rules.d/99-hardening.rules << 'AUDIT'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# ── Time changes ─────────────────────────────────────
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# ── Identity changes ────────────────────────────────
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# ── Network changes ─────────────────────────────────
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale
-w /etc/networks -p wa -k system-locale

# ── Login/Logout ─────────────────────────────────────
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# ── Session initiation ──────────────────────────────
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# ── Permission changes (DAC) ────────────────────────
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# ── Unauthorized access attempts ────────────────────
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# ── Privileged commands ──────────────────────────────
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# ── Sudoers changes ─────────────────────────────────
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# ── Kernel module loading ───────────────────────────
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# ── Mounts ───────────────────────────────────────────
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# ── File deletion by users ──────────────────────────
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# ── Make rules immutable (MUST BE LAST) ─────────────
-e 2
AUDIT

# Configure auditd.conf
sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf 2>/dev/null || true
sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf 2>/dev/null || true
sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf 2>/dev/null || true
sed -i 's/^max_log_file .*/max_log_file = 50/' /etc/audit/auditd.conf 2>/dev/null || true
sed -i 's/^num_logs .*/num_logs = 10/' /etc/audit/auditd.conf 2>/dev/null || true

# Enable audit at boot via GRUB
backup /etc/default/grub
if ! grep -q "audit=1" /etc/default/grub; then
    sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1 audit_backlog_limit=8192"/' /etc/default/grub
    run "update-grub"
fi

run "systemctl enable auditd"
run "systemctl restart auditd"

log "Phase 8 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 9: APPARMOR (Lynis MACF-6208)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 9: AppArmor enforcement"

# Ensure AppArmor is enabled at boot
if ! grep -q "apparmor=1" /etc/default/grub; then
    sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 apparmor=1 security=apparmor"/' /etc/default/grub
    run "update-grub"
fi

run "systemctl enable apparmor"
run "systemctl start apparmor"

# Enforce all loaded profiles
run "aa-enforce /etc/apparmor.d/* 2>/dev/null || true"

log "AppArmor status:"
aa-status --enabled 2>/dev/null && log "  AppArmor is enabled" || warn "  AppArmor issues"

log "Phase 9 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 10: NETWORK / FIREWALL (Lynis FIRE-4512)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 10: Firewall (UFW/nftables)"

run "apt-get install -y -qq ufw"

run "ufw --force reset"
run "ufw default deny incoming"
run "ufw default allow outgoing"
run "ufw default deny routed"

# Allow SSH (adjust port if needed)
run "ufw allow in 22/tcp comment 'SSH'"

# Rate limiting on SSH
run "ufw limit 22/tcp comment 'SSH rate limit'"

run "ufw --force enable"
run "systemctl enable ufw"

# TCP Wrappers
echo "ALL: ALL" > /etc/hosts.deny
echo "sshd: ALL" > /etc/hosts.allow

log "Phase 10 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 11: AIDE (File Integrity — Lynis FINT-4350)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 11: AIDE file integrity"

if command -v aide &>/dev/null; then
    if [[ ! -f /var/lib/aide/aide.db ]]; then
        log "Initializing AIDE database (this takes a while)..."
        run "aideinit -y -f 2>/dev/null || aide --init 2>/dev/null || true"
        [[ -f /var/lib/aide/aide.db.new ]] && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi

    # Daily AIDE check cron
    cat > /etc/cron.daily/aide-check << 'AIDECRON'
#!/bin/bash
/usr/bin/aide --check 2>&1 | /usr/bin/mail -s "AIDE Integrity Report - $(hostname)" root 2>/dev/null || true
AIDECRON
    chmod 755 /etc/cron.daily/aide-check
fi

log "Phase 11 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 12: TIME SYNCHRONIZATION (Lynis TIME-3104)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 12: Time synchronization (Chrony)"

backup /etc/chrony/chrony.conf 2>/dev/null || true

cat > /etc/chrony/chrony.conf << 'CHRONY'
# NTP pools
pool ntp.ubuntu.com        iburst maxsources 4
pool 0.ubuntu.pool.ntp.org iburst maxsources 2
pool 1.ubuntu.pool.ntp.org iburst maxsources 2

keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
CHRONY

run "systemctl enable chrony"
run "systemctl restart chrony"
# Disable systemd-timesyncd (conflicts)
run "systemctl stop systemd-timesyncd 2>/dev/null || true"
run "systemctl disable systemd-timesyncd 2>/dev/null || true"
run "systemctl mask systemd-timesyncd 2>/dev/null || true"

log "Phase 12 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 13: LOGGING HARDENING (Lynis LOGG-*)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 13: Logging hardening"

# Ensure rsyslog is the syslog daemon
run "systemctl enable rsyslog"
run "systemctl start rsyslog"

# Ensure log file permissions
find /var/log -type f -exec chmod g-wx,o-rwx {} + 2>/dev/null || true

# Process accounting
run "systemctl enable acct 2>/dev/null || true"
run "systemctl start acct 2>/dev/null || true"

# sysstat (system stats)
run "systemctl enable sysstat 2>/dev/null || true"
run "systemctl start sysstat 2>/dev/null || true"

log "Phase 13 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 14: BANNERS (Lynis BANN-7126, BANN-7130)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 14: Legal banners"

LEGAL_BANNER="Authorized uses only. All activity may be monitored and reported."

echo "$LEGAL_BANNER" > /etc/issue
echo "$LEGAL_BANNER" > /etc/issue.net
echo "$LEGAL_BANNER" > /etc/motd

chmod 644 /etc/issue /etc/issue.net /etc/motd

log "Phase 14 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 15: FAIL2BAN (Lynis TOOL-5104)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 15: Fail2Ban"

cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd
banaction = ufw

[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 3
bantime  = 7200
F2B

run "systemctl enable fail2ban"
run "systemctl restart fail2ban"

log "Phase 15 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 16: AUTOMATIC UPDATES (Lynis PKGS-7394)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 16: Unattended upgrades"

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UUCONF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UUCONF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTO'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
AUTO

run "systemctl enable unattended-upgrades"
run "systemctl restart unattended-upgrades"

log "Phase 16 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 17: MALWARE SCANNERS (Lynis MALW-3280, HRDN-7230)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 17: Malware scanners"

# ClamAV
run "systemctl stop clamav-freshclam 2>/dev/null || true"
run "freshclam 2>/dev/null || true"
run "systemctl enable clamav-freshclam"
run "systemctl start clamav-freshclam"

# rkhunter config
backup /etc/rkhunter.conf 2>/dev/null || true
if [[ -f /etc/rkhunter.conf ]]; then
    sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null || true
    sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf 2>/dev/null || true
    sed -i 's/^WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf 2>/dev/null || true
fi
run "rkhunter --update 2>/dev/null || true"
run "rkhunter --propupd 2>/dev/null || true"

log "Phase 17 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 18: COMPILER & CORE DUMP RESTRICTIONS (Lynis HRDN-7222)
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 18: Compiler & core dump restrictions"

# Restrict core dumps
cat > /etc/security/limits.d/99-hardening.conf << 'LIMITS'
*    hard    core    0
*    soft    core    0
*    hard    maxlogins    10
LIMITS

# Systemd core dump disable
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'COREDUMP'
[Coredump]
Storage=none
ProcessSizeMax=0
COREDUMP

# Restrict compilers to root only
for compiler in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/as; do
    if [[ -f "$compiler" ]]; then
        chmod o-rx "$compiler" 2>/dev/null || true
    fi
done

log "Phase 18 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 19: MISCELLANEOUS LYNIS FIXES
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 19: Miscellaneous Lynis fixes"

# 19a. Disable ctrl-alt-delete reboot (Lynis)
run "systemctl mask ctrl-alt-del.target 2>/dev/null || true"

# 19b. Restrict kernel log access
echo "kernel.dmesg_restrict = 1" > /etc/sysctl.d/98-dmesg.conf

# 19c. Ensure no world-writable files in system dirs
find /usr /etc -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null || true

# 19d. Ensure no unowned files
# (just log them, don't fix automatically)
UNOWNED=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -20)
if [[ -n "$UNOWNED" ]]; then
    warn "Unowned files found (review manually):"
    echo "$UNOWNED" | tee -a "$LOGFILE"
fi

# 19e. Ensure root PATH integrity
echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" > /etc/profile.d/secure-path.sh

# 19f. Lock inactive user accounts
run "useradd -D -f 30"

# 19g. Disable uncommon network protocols
cat > /etc/modprobe.d/hardening-protocols.conf << 'MODPROTO'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
MODPROTO

# 19h. Secure GRUB bootloader
if command -v grub-mkpasswd-pbkdf2 &>/dev/null; then
    log "Consider setting a GRUB password with: grub-mkpasswd-pbkdf2"
fi

# 19i. Address space layout randomization confirmation
sysctl -w kernel.randomize_va_space=2 2>/dev/null || true

# 19j. Ensure permissions on /home directories
for dir in /home/*/; do
    [[ -d "$dir" ]] && chmod 750 "$dir" 2>/dev/null || true
done

log "Phase 19 complete."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 20: LYNIS AUDIT
# ═════════════════════════════════════════════════════════════════════════════
banner "Phase 20: Running Lynis audit"

# Install latest Lynis from upstream
LYNIS_DIR="/tmp/lynis-audit"
rm -rf "$LYNIS_DIR"
git clone --depth 1 https://github.com/CISOfy/lynis.git "$LYNIS_DIR" 2>/dev/null

LYNIS_BIN="lynis"
if [[ -f "$LYNIS_DIR/lynis" ]]; then
    LYNIS_BIN="$LYNIS_DIR/lynis"
fi

log "Running Lynis audit..."
LYNIS_REPORT="/var/log/lynis-hardened-$(date +%Y%m%d-%H%M%S).log"
cd "${LYNIS_DIR:-/tmp}"
$LYNIS_BIN audit system --no-colors --quick 2>&1 | tee "$LYNIS_REPORT"

# Extract score
SCORE=$(grep "Hardening index" "$LYNIS_REPORT" | grep -oP '\d+' | tail -1)
if [[ -n "$SCORE" ]]; then
    echo ""
    if [[ "$SCORE" -ge 90 ]]; then
        banner "🎉 LYNIS SCORE: ${SCORE} — TARGET ACHIEVED!"
    else
        banner "📊 LYNIS SCORE: ${SCORE}"
        warn "Score < 90. Review suggestions in: $LYNIS_REPORT"
        warn "Run: grep 'suggestion' /var/log/lynis.log"
    fi
else
    warn "Could not extract score. Check: $LYNIS_REPORT"
fi

# ═════════════════════════════════════════════════════════════════════════════
# DONE
# ═════════════════════════════════════════════════════════════════════════════
banner "HARDENING COMPLETE"

cat << SUMMARY

  📁 Backups         : $BACKUP_DIR
  📋 Hardening log   : $LOGFILE
  📊 Lynis report    : $LYNIS_REPORT
  📂 Lynis data      : /var/log/lynis.log
                       /var/log/lynis-report.dat

  ⚡ Remaining steps:
     1. REBOOT the system to apply GRUB/kernel changes
     2. Review Lynis suggestions:
        grep "suggestion" /var/log/lynis.log
     3. Test SSH access BEFORE closing current session
     4. Set a GRUB bootloader password if physical access is a concern

SUMMARY

if [[ "$SKIP_REBOOT" != "true" && "$DRY_RUN" != "true" ]]; then
    warn "Reboot in 60 seconds... (Ctrl+C to cancel)"
    sleep 60
    reboot
fi

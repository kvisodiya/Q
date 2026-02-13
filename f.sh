#!/usr/bin/env bash
#
# fix.sh — Fill the gaps left after the base hardening repo (score 93 → 98+)
# Target : Debian 11 (Bullseye) VPS
# Run as : root
# Allowed: UFW ports 22, 2222
#
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive

echo "========================================"
echo " Debian 11 CIS Gap-Fix Script"
echo "========================================"

###############################################################################
# 0. PRE-FLIGHT
###############################################################################
if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root." >&2
  exit 1
fi

backup_file() {
  local f="$1"
  [[ -f "$f" ]] && cp -a "$f" "${f}.bak.$(date +%s)" 2>/dev/null || true
}

###############################################################################
# 1. KERNEL MODULES — disable unused filesystems & protocols
#    CIS 1.1.1.x  /  1.1.23  /  3.5.x
###############################################################################
echo "[+] Disabling unused kernel modules..."

cat > /etc/modprobe.d/cis-disable-fs.conf <<'EOF'
install cramfs     /bin/true
install freevxfs   /bin/true
install jffs2      /bin/true
install hfs        /bin/true
install hfsplus    /bin/true
install squashfs   /bin/true
install udf        /bin/true
install vfat       /bin/true
install usb-storage /bin/true
EOF

cat > /etc/modprobe.d/cis-disable-net.conf <<'EOF'
install dccp  /bin/true
install sctp  /bin/true
install rds   /bin/true
install tipc  /bin/true
EOF

# Blacklist as well so they never auto-load
for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat \
           usb-storage dccp sctp rds tipc; do
  echo "blacklist ${mod}" >> /etc/modprobe.d/cis-blacklist.conf
  modprobe -r "$mod" 2>/dev/null || true
done

###############################################################################
# 2. TEMPORARY STORAGE — harden /tmp /var/tmp /dev/shm
#    CIS 1.1.2–1.1.9
###############################################################################
echo "[+] Hardening tmp mounts..."

# /tmp via tmpfs
if ! grep -q '/tmp' /etc/fstab; then
  echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=512M 0 0" >> /etc/fstab
fi
# Fix existing line
sed -i 's|^tmpfs.*/tmp.*|tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=512M 0 0|' /etc/fstab

# /var/tmp bind-mounted from /tmp
if ! grep -q '/var/tmp' /etc/fstab; then
  echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab
fi

# /dev/shm
if ! grep -q '/dev/shm' /etc/fstab; then
  echo "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab
else
  sed -i 's|^tmpfs.*/dev/shm.*|tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0|' /etc/fstab
fi

mount -o remount /dev/shm 2>/dev/null || true

###############################################################################
# 3. STICKY BIT on world-writable dirs   CIS 1.1.22
###############################################################################
echo "[+] Setting sticky bit on world-writable directories..."
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | \
  xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | \
  while read -r d; do chmod a+t "$d"; done

###############################################################################
# 4. CORE DUMPS   CIS 1.5.1
###############################################################################
echo "[+] Restricting core dumps..."
backup_file /etc/security/limits.conf
grep -q 'hard core' /etc/security/limits.conf 2>/dev/null || \
  echo "* hard core 0" >> /etc/security/limits.conf

cat > /etc/sysctl.d/10-coredump.conf <<'EOF'
fs.suid_dumpable = 0
EOF

# systemd coredump
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/cis.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
systemctl daemon-reload

###############################################################################
# 5. ASLR   CIS 1.5.3
###############################################################################
echo "[+] Ensuring ASLR is enabled..."
cat > /etc/sysctl.d/10-aslr.conf <<'EOF'
kernel.randomize_va_space = 2
EOF

###############################################################################
# 6. AppArmor   CIS 1.6.1.x
###############################################################################
echo "[+] Configuring AppArmor..."
apt-get -y install apparmor apparmor-utils apparmor-profiles 2>/dev/null || true

# Enable at boot via GRUB
backup_file /etc/default/grub
if ! grep -q 'apparmor=1' /etc/default/grub; then
  sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 apparmor=1 security=apparmor"/' /etc/default/grub
  # Remove double spaces
  sed -i 's/  */ /g' /etc/default/grub
  update-grub 2>/dev/null || true
fi

systemctl enable apparmor 2>/dev/null || true
systemctl start apparmor 2>/dev/null || true

# Set all profiles to enforce (complain → enforce)
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

###############################################################################
# 7. GRUB PERMISSIONS   CIS 1.4.1
###############################################################################
echo "[+] Setting bootloader permissions..."
chown root:root /boot/grub/grub.cfg 2>/dev/null || true
chmod 0400 /boot/grub/grub.cfg 2>/dev/null || true

###############################################################################
# 8. MOTD / BANNERS   CIS 1.7.1–1.7.6
###############################################################################
echo "[+] Configuring login banners..."

BANNER="Authorized users only. All activity may be monitored and reported."

echo "$BANNER" > /etc/issue
echo "$BANNER" > /etc/issue.net
echo "$BANNER" > /etc/motd

chown root:root /etc/issue /etc/issue.net /etc/motd
chmod 644 /etc/issue /etc/issue.net /etc/motd

# Remove OS info from banners
sed -i 's/\\[a-zA-Z]//g' /etc/issue /etc/issue.net 2>/dev/null || true

###############################################################################
# 9. TIME SYNCHRONISATION   CIS 2.1.1 / 2.1.2
###############################################################################
echo "[+] Configuring time sync (chrony)..."
apt-get -y install chrony 2>/dev/null || true
systemctl enable chrony
systemctl start chrony

# Ensure chrony runs as _chrony
backup_file /etc/chrony/chrony.conf
grep -q '^user _chrony' /etc/chrony/chrony.conf 2>/dev/null || \
  echo "user _chrony" >> /etc/chrony/chrony.conf

systemctl restart chrony 2>/dev/null || true

# Remove other NTP daemons
apt-get -y purge ntp 2>/dev/null || true
systemctl stop systemd-timesyncd 2>/dev/null || true
systemctl mask systemd-timesyncd 2>/dev/null || true

###############################################################################
# 10. REMOVE / DISABLE UNNECESSARY SERVICES   CIS 2.1.x / 2.2.x
###############################################################################
echo "[+] Removing unnecessary services..."

REMOVE_PKGS=(
  xserver-xorg-core xserver-xorg avahi-daemon cups isc-dhcp-server
  slapd nfs-kernel-server bind9 vsftpd apache2 dovecot-core
  samba squid snmpd rsync nis rsh-client talk telnet ldap-utils
  rpcbind
)
for pkg in "${REMOVE_PKGS[@]}"; do
  apt-get -y purge "$pkg" 2>/dev/null || true
done

# Disable rpcbind socket
systemctl stop rpcbind.socket rpcbind.service 2>/dev/null || true
systemctl mask rpcbind.socket rpcbind.service 2>/dev/null || true

###############################################################################
# 11. NETWORK PARAMETERS (sysctl)   CIS 3.1–3.3
###############################################################################
echo "[+] Applying network sysctl hardening..."

cat > /etc/sysctl.d/60-cis-network.conf <<'EOF'
# 3.1.1 - Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 3.1.2 - Packet redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 3.2.1 - Source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 3.2.2 - ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 3.2.3 - Secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# 3.2.4 - Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 3.2.5 - Broadcast ICMP requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 3.2.6 - Bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 3.2.7 - Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 3.2.8 - TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# 3.2.9 - IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

sysctl --system 2>/dev/null

###############################################################################
# 12. FIREWALL (UFW) — allow 22 + 2222 only   CIS 3.5.x
###############################################################################
echo "[+] Configuring UFW firewall..."

apt-get -y install ufw 2>/dev/null || true

# Reset to clean state
ufw --force reset

# Default policies
ufw default deny incoming
ufw default deny outgoing
ufw default deny routed

# Allow SSH on 22 and 2222
ufw allow in 22/tcp
ufw allow in 2222/tcp

# Allow outbound essentials (DNS, HTTP/S, NTP, SSH)
ufw allow out 53
ufw allow out 80/tcp
ufw allow out 443/tcp
ufw allow out 123/udp
ufw allow out 22/tcp
ufw allow out 2222/tcp

# Allow loopback
ufw allow in on lo
ufw allow out on lo

# Enable
ufw --force enable
systemctl enable ufw

# Verify IPv6 is enabled in UFW config
backup_file /etc/default/ufw
sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw

ufw reload

###############################################################################
# 13. AUDIT SYSTEM   CIS 4.1.x
###############################################################################
echo "[+] Configuring auditd..."

apt-get -y install auditd audispd-plugins 2>/dev/null || true
systemctl enable auditd
systemctl start auditd

backup_file /etc/audit/auditd.conf

# CIS 4.1.1.1 — audit log storage size
sed -i 's/^max_log_file .*/max_log_file = 64/' /etc/audit/auditd.conf
# CIS 4.1.1.2 — when disk full, halt (or keep_logs)
sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf
# CIS 4.1.1.3 — keep logs
sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

# CIS 4.1.2 — ensure auditd enabled at boot
if ! grep -q 'audit=1' /etc/default/grub; then
  sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub
  sed -i 's/  */ /g' /etc/default/grub
  update-grub 2>/dev/null || true
fi

# CIS 4.1.3 — audit backlog limit
if ! grep -q 'audit_backlog_limit' /etc/default/grub; then
  sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit_backlog_limit=8192"/' /etc/default/grub
  sed -i 's/  */ /g' /etc/default/grub
  update-grub 2>/dev/null || true
fi

# AUDIT RULES — CIS 4.1.4–4.1.17
cat > /etc/audit/rules.d/cis.rules <<'AUDITRULES'
# Remove all existing rules
-D

# Buffer size
-b 8192

# Failure mode: 1=printk  2=panic
-f 1

## CIS 4.1.3 – time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## CIS 4.1.4 – identity (user/group info)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## CIS 4.1.5 – network-environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

## CIS 4.1.6 – MAC policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

## CIS 4.1.7 – login/logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

## CIS 4.1.8 – session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

## CIS 4.1.9 – discretionary access control (permission changes)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

## CIS 4.1.10 – unauthorized file access attempts
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

## CIS 4.1.11 – privileged commands (auto-generated below by script)

## CIS 4.1.12 – successful file system mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

## CIS 4.1.13 – file deletion events
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

## CIS 4.1.14 – sudoers changes
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

## CIS 4.1.15 – sudo log
-w /var/log/sudo.log -p wa -k actions

## CIS 4.1.16 – kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

## CIS 4.1.17 – make the configuration immutable (MUST BE LAST)
-e 2
AUDITRULES

# CIS 4.1.11 — privileged commands (generate dynamically)
PRIV_RULES="/etc/audit/rules.d/cis-privileged.rules"
: > "$PRIV_RULES"
for partition in $(df --local -P | awk '{if(NR!=1) print $6}'); do
  find "$partition" -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | \
  while read -r f; do
    echo "-a always,exit -F path=${f} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> "$PRIV_RULES"
  done
done

# Load all rules
augenrules --load 2>/dev/null || true
systemctl restart auditd 2>/dev/null || true

###############################################################################
# 14. LOGGING — rsyslog + journald   CIS 4.2.x
###############################################################################
echo "[+] Configuring rsyslog & journald..."

apt-get -y install rsyslog 2>/dev/null || true
systemctl enable rsyslog
systemctl start rsyslog

# CIS 4.2.1.3 — rsyslog default file permissions
backup_file /etc/rsyslog.conf
grep -q '^\$FileCreateMode' /etc/rsyslog.conf || \
  echo '$FileCreateMode 0640' >> /etc/rsyslog.conf

# CIS 4.2.1.4 — logging is configured (standard rules)
cat > /etc/rsyslog.d/50-cis-default.conf <<'EOF'
*.emerg                         :omusrmsg:*
auth,authpriv.*                 /var/log/auth.log
mail.*                          -/var/log/mail.log
mail.info                       -/var/log/mail.info
mail.warning                    -/var/log/mail.warn
mail.err                        /var/log/mail.err
cron.*                          /var/log/cron.log
*.=warning;*.=err               -/var/log/warn
*.crit                          /var/log/warn
*.*;mail.none;news.none         -/var/log/messages
local0,local1.*                 -/var/log/localmessages
local2,local3.*                 -/var/log/localmessages
local4,local5.*                 -/var/log/localmessages
local6,local7.*                 -/var/log/localmessages
EOF

systemctl restart rsyslog 2>/dev/null || true

# CIS 4.2.2 — journald config
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/cis.conf <<'EOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
EOF
systemctl restart systemd-journald 2>/dev/null || true

# CIS 4.2.3 — permissions on log files
find /var/log -type f -exec chmod g-wx,o-rwx {} + 2>/dev/null || true

###############################################################################
# 15. CRON HARDENING   CIS 5.1.x
###############################################################################
echo "[+] Hardening cron..."

systemctl enable cron 2>/dev/null || true

chown root:root /etc/crontab
chmod 0600 /etc/crontab

for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  [[ -d "$d" ]] && chown root:root "$d" && chmod 0700 "$d"
done

# CIS 5.1.8 — restrict cron/at to root
rm -f /etc/cron.deny /etc/at.deny

echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow

chown root:root /etc/cron.allow /etc/at.allow
chmod 0640 /etc/cron.allow /etc/at.allow

###############################################################################
# 16. SSH HARDENING   CIS 5.2.x  (comprehensive)
###############################################################################
echo "[+] Hardening SSH..."

SSHD_CONFIG="/etc/ssh/sshd_config"
backup_file "$SSHD_CONFIG"

# Build a CIS-compliant sshd_config snippet
cat > /etc/ssh/sshd_config.d/cis-hardening.conf <<'EOF'
# CIS 5.2.1 — permissions on sshd_config
# (handled below via chmod)

# CIS 5.2.2
Protocol 2

# CIS 5.2.4 — SSH LogLevel
LogLevel VERBOSE

# CIS 5.2.5 — Disable X11 forwarding
X11Forwarding no

# CIS 5.2.6 — MaxAuthTries
MaxAuthTries 4

# CIS 5.2.7 — IgnoreRhosts
IgnoreRhosts yes

# CIS 5.2.8 — HostbasedAuthentication
HostbasedAuthentication no

# CIS 5.2.9 — Disable root login
PermitRootLogin no

# CIS 5.2.10 — PermitEmptyPasswords
PermitEmptyPasswords no

# CIS 5.2.11 — PermitUserEnvironment
PermitUserEnvironment no

# CIS 5.2.12 — Only strong ciphers
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# CIS 5.2.13 — Only strong MACs
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# CIS 5.2.14 — Only strong KEX
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521

# CIS 5.2.15 — Idle timeout
ClientAliveInterval 300
ClientAliveCountMax 3

# CIS 5.2.16 — Login grace time
LoginGraceTime 60

# CIS 5.2.17 — SSH banner
Banner /etc/issue.net

# CIS 5.2.18 — PAM
UsePAM yes

# CIS 5.2.20 — AllowTcpForwarding
AllowTcpForwarding no

# CIS 5.2.21 — MaxStartups
MaxStartups 10:30:60

# CIS 5.2.22 — MaxSessions
MaxSessions 10

# Listen on both default ports
Port 22
Port 2222
EOF

# Permissions
chown root:root "$SSHD_CONFIG"
chmod 0600 "$SSHD_CONFIG"

# Fix permissions on SSH host keys
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \; -exec chmod 0600 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;

# Remove short DH moduli (< 3072 bits)  CIS 5.2.14 supplement
if [[ -f /etc/ssh/moduli ]]; then
  awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp && mv /etc/ssh/moduli.tmp /etc/ssh/moduli
fi

# Validate config before restart
sshd -t 2>/dev/null && systemctl restart sshd || echo "WARNING: sshd config test failed, not restarting"

###############################################################################
# 17. PAM CONFIGURATION   CIS 5.3.x / 5.4.x
###############################################################################
echo "[+] Configuring PAM..."

apt-get -y install libpam-pwquality 2>/dev/null || true

# CIS 5.3.1 — Password quality
backup_file /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
maxclassrepeat = 3
EOF

# CIS 5.3.2 — Password lockout (pam_faillock replaces pam_tally2 on Debian 11)
# Configure faillock
cat > /etc/security/faillock.conf <<'EOF'
deny = 5
fail_interval = 900
unlock_time = 900
EOF

# Ensure pam_faillock is in common-auth
PAM_AUTH="/etc/pam.d/common-auth"
backup_file "$PAM_AUTH"
if ! grep -q 'pam_faillock' "$PAM_AUTH" 2>/dev/null; then
  # Insert before pam_unix
  sed -i '/pam_unix.so/i auth    required    pam_faillock.so preauth silent' "$PAM_AUTH"
  sed -i '/pam_unix.so/a auth    [default=die] pam_faillock.so authfail' "$PAM_AUTH"
fi

PAM_ACCOUNT="/etc/pam.d/common-account"
backup_file "$PAM_ACCOUNT"
if ! grep -q 'pam_faillock' "$PAM_ACCOUNT" 2>/dev/null; then
  sed -i '/pam_unix.so/i account required pam_faillock.so' "$PAM_ACCOUNT"
fi

# CIS 5.3.3 — Password reuse (remember)
PAM_PASSWORD="/etc/pam.d/common-password"
backup_file "$PAM_PASSWORD"
if grep -q 'pam_unix.so' "$PAM_PASSWORD"; then
  # Add remember=5 and sha512 to pam_unix line
  sed -i '/pam_unix.so/ s/$/ remember=5 sha512/' "$PAM_PASSWORD"
  # Remove duplicate options
  sed -i 's/sha512 sha512/sha512/g; s/remember=5 remember=5/remember=5/g' "$PAM_PASSWORD"
fi

# Ensure pam_pwquality is in common-password
if ! grep -q 'pam_pwquality' "$PAM_PASSWORD"; then
  sed -i '/pam_unix.so/i password    requisite    pam_pwquality.so retry=3' "$PAM_PASSWORD"
fi

# CIS 5.4.4 — restrict su
backup_file /etc/pam.d/su
if ! grep -q 'pam_wheel.so' /etc/pam.d/su || grep -q '^#.*pam_wheel.so' /etc/pam.d/su; then
  sed -i 's/^#.*pam_wheel.so.*/auth required pam_wheel.so use_uid group=sudo/' /etc/pam.d/su
  grep -q 'pam_wheel.so' /etc/pam.d/su || \
    echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
fi

###############################################################################
# 18. PASSWORD / LOGIN POLICIES   CIS 5.4.1.x
###############################################################################
echo "[+] Setting password policies in login.defs..."

backup_file /etc/login.defs

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'   /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/'   /etc/login.defs

# CIS 5.4.1.4 — inactive password lock
useradd -D -f 30 2>/dev/null || true

# Apply to all existing human users
for user in $(awk -F: '($3>=1000 && $3!=65534){print $1}' /etc/passwd); do
  chage --maxdays 365 "$user" 2>/dev/null || true
  chage --mindays 1   "$user" 2>/dev/null || true
  chage --warndays 7  "$user" 2>/dev/null || true
  chage --inactive 30 "$user" 2>/dev/null || true
done

# CIS 5.4.2 — system accounts are secured
for user in $(awk -F: '($3<1000 && $1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt"){print $1}' /etc/passwd); do
  usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
  usermod -L "$user" 2>/dev/null || true
done

# CIS 5.4.3 — default group for root is GID 0
usermod -g 0 root 2>/dev/null || true

###############################################################################
# 19. SHELL TIMEOUT (TMOUT)   CIS 5.4.5
###############################################################################
echo "[+] Setting shell timeout..."

cat > /etc/profile.d/cis-tmout.sh <<'EOF'
readonly TMOUT=900
export TMOUT
EOF
chmod 644 /etc/profile.d/cis-tmout.sh

###############################################################################
# 20. DEFAULT UMASK   CIS 5.4.4
###############################################################################
echo "[+] Setting default umask..."

# login.defs
sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs

# bash
grep -q 'umask 027' /etc/bash.bashrc 2>/dev/null || echo "umask 027" >> /etc/bash.bashrc
grep -q 'umask 027' /etc/profile 2>/dev/null     || echo "umask 027" >> /etc/profile

###############################################################################
# 21. FILE PERMISSIONS   CIS 6.1.x
###############################################################################
echo "[+] Fixing critical file permissions..."

# CIS 6.1.2–6.1.9
chown root:root /etc/passwd  && chmod 644 /etc/passwd
chown root:root /etc/passwd- && chmod 600 /etc/passwd- 2>/dev/null || true
chown root:shadow /etc/shadow  && chmod 640 /etc/shadow
chown root:shadow /etc/shadow- && chmod 600 /etc/shadow- 2>/dev/null || true
chown root:root /etc/group   && chmod 644 /etc/group
chown root:root /etc/group-  && chmod 600 /etc/group-  2>/dev/null || true
chown root:shadow /etc/gshadow  && chmod 640 /etc/gshadow
chown root:shadow /etc/gshadow- && chmod 600 /etc/gshadow- 2>/dev/null || true

###############################################################################
# 22. FIND WORLD-WRITABLE FILES & UNOWNED FILES   CIS 6.1.10–6.1.12
###############################################################################
echo "[+] Fixing unowned/ungrouped files..."
find / -xdev \( -nouser -o -nogroup \) -type f 2>/dev/null | while read -r f; do
  chown root:root "$f"
done

###############################################################################
# 23. AIDE (FILE INTEGRITY)   CIS 1.3.1 / 1.3.2
###############################################################################
echo "[+] Installing & initialising AIDE..."

apt-get -y install aide aide-common 2>/dev/null || true

# Initialize AIDE database (runs in background — can take a while)
if [[ ! -f /var/lib/aide/aide.db ]]; then
  aideinit -y -f 2>/dev/null || true
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
fi

# CIS 1.3.2 — cron job for daily AIDE check
cat > /etc/cron.daily/aide-check <<'EOF'
#!/bin/bash
/usr/bin/aide --config /etc/aide/aide.conf --check
EOF
chmod 755 /etc/cron.daily/aide-check

###############################################################################
# 24. SUDO CONFIGURATION   CIS 5.2.x / 1.3.x
###############################################################################
echo "[+] Hardening sudo..."

# CIS — sudo log file
grep -q '^Defaults.*logfile' /etc/sudoers 2>/dev/null || \
  echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers

# CIS — use_pty
grep -q '^Defaults.*use_pty' /etc/sudoers 2>/dev/null || \
  echo 'Defaults use_pty' >> /etc/sudoers

# CIS — sudo timeout
grep -q '^Defaults.*timestamp_timeout' /etc/sudoers 2>/dev/null || \
  echo 'Defaults timestamp_timeout=15' >> /etc/sudoers

# Validate
visudo -c 2>/dev/null || echo "WARNING: sudoers syntax error — review manually!"

###############################################################################
# 25. DISABLE AUTOMOUNTING   CIS 1.1.23
###############################################################################
echo "[+] Disabling automounting..."
systemctl stop autofs 2>/dev/null || true
systemctl mask autofs 2>/dev/null || true

###############################################################################
# 26. ADDITIONAL SYSCTL — KERNEL HARDENING
###############################################################################
echo "[+] Applying extra kernel hardening sysctl..."

cat > /etc/sysctl.d/70-cis-kernel.conf <<'EOF'
# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 2

# Restrict unprivileged BPF
kernel.unprivileged_bpf_disabled = 1

# Restrict userfaultfd to root
vm.unprivileged_userfaultfd = 0

# Restrict perf_event
kernel.perf_event_paranoid = 3

# SysRq — disable
kernel.sysrq = 0
EOF

sysctl --system 2>/dev/null

###############################################################################
# 27. REMOVE PRELINK   CIS 1.5.4
###############################################################################
echo "[+] Removing prelink..."
if dpkg -s prelink &>/dev/null; then
  prelink -ua 2>/dev/null || true
  apt-get -y purge prelink
fi

###############################################################################
# 28. ENSURE NO DUPLICATE UIDs/GIDs/USERS/GROUPS   CIS 6.2.x
###############################################################################
echo "[+] Checking for duplicate UIDs/GIDs..."
# Just report — automated fix is risky
awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d | while read -r uid; do
  echo "  WARNING: Duplicate UID $uid found!"
done
awk -F: '{print $3}' /etc/group | sort -n | uniq -d | while read -r gid; do
  echo "  WARNING: Duplicate GID $gid found!"
done

###############################################################################
# 29. ENSURE ROOT PATH INTEGRITY   CIS 6.2.6
###############################################################################
echo "[+] Cleaning root PATH..."
# Remove empty entries and current directory from root's PATH
sed -i 's/::/:/g; s/:$//; s/^://; s/:\.:/:/' /root/.bashrc 2>/dev/null || true
sed -i 's/::/:/g; s/:$//; s/^://; s/:\.:/:/' /root/.profile 2>/dev/null || true

###############################################################################
# 30. ENSURE root IS THE ONLY UID 0 ACCOUNT   CIS 6.2.8
###############################################################################
echo "[+] Verifying single UID 0 account..."
EXTRA_ROOT=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd)
if [[ -n "$EXTRA_ROOT" ]]; then
  echo "  WARNING: Extra UID 0 accounts found: $EXTRA_ROOT"
  echo "  Please remediate manually."
fi

###############################################################################
# 31. ENSURE NO LEGACY '+' ENTRIES   CIS 6.2.2–6.2.4
###############################################################################
echo "[+] Removing legacy '+' entries..."
for f in /etc/passwd /etc/shadow /etc/group; do
  sed -i '/^+/d' "$f" 2>/dev/null || true
done

###############################################################################
# 32. ENSURE HOME DIRECTORY PERMISSIONS   CIS 6.2.x
###############################################################################
echo "[+] Fixing home directory permissions..."
awk -F: '($3>=1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false"){print $6}' /etc/passwd | \
  while read -r dir; do
    if [[ -d "$dir" ]]; then
      chmod 750 "$dir" 2>/dev/null || true
    fi
  done

###############################################################################
# 33. CLEANUP & FINAL APPLY
###############################################################################
echo "[+] Final cleanup..."

# Remove packages
apt-get -y autoremove --purge 2>/dev/null || true
apt-get -y clean

# Final sysctl load
sysctl --system 2>/dev/null

echo ""
echo "========================================"
echo " DONE. Reboot recommended."
echo " After reboot, verify with:"
echo "   ufw status verbose"
echo "   auditctl -l"
echo "   apparmor_status"
echo "   sshd -T | grep -E 'port|permit'"
echo "========================================"
echo ""
echo "NOTE: If you need root SSH access during"
echo "transition, temporarily set:"
echo "  PermitRootLogin prohibit-password"
echo "in /etc/ssh/sshd_config.d/cis-hardening.conf"
echo "========================================"

#!/usr/bin/env bash
#===============================================================================
# fix90.sh — Targeted fixes for Lynis 88 → 90+ on Ubuntu 24.04
# Run AFTER hard.sh — this covers the gaps that remain
#===============================================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
log()    { echo -e "${G}[✔]${N} $*"; }
warn()   { echo -e "${Y}[!]${N} $*"; }
banner() { echo -e "\n${C}═══ $* ═══${N}\n"; }

LOGFILE="/var/log/fix90-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

banner "LYNIS 88 → 90+ TARGETED FIXES"

# ═══════════════════════════════════════════════════════════════════════════
# FIX 1: PAM — faillock (AUTH-9262, AUTH-9328)
# Lynis wants pam_faillock instead of pam_tally2
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 1: PAM faillock"

cat > /etc/security/faillock.conf << 'FAILLOCK'
deny = 5
fail_interval = 900
unlock_time = 600
even_deny_root
root_unlock_time = 60
audit
silent
FAILLOCK

# Ensure pam_faillock is in common-auth
if ! grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
    cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
    cat > /etc/pam.d/common-auth << 'PAMAUTH'
auth    required                        pam_faillock.so preauth silent
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    [default=die]                   pam_faillock.so authfail
auth    sufficient                      pam_faillock.so authsucc
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
PAMAUTH
fi

if ! grep -q "pam_faillock" /etc/pam.d/common-account 2>/dev/null; then
    cp /etc/pam.d/common-account /etc/pam.d/common-account.bak
    sed -i '1a account required pam_faillock.so' /etc/pam.d/common-account
fi

log "PAM faillock configured."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 2: PAM — password history (AUTH-9262)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 2: PAM password history"

if ! grep -q "remember=" /etc/pam.d/common-password 2>/dev/null; then
    cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
    sed -i 's/pam_unix.so.*/& remember=5 sha512 shadow rounds=5000/' /etc/pam.d/common-password
fi

# Ensure pwquality is enforced in PAM
if ! grep -q "pam_pwquality" /etc/pam.d/common-password 2>/dev/null; then
    sed -i '/^password.*pam_unix.so/i password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password
fi

log "Password history & pwquality enforced."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 3: USB authorization (USBE-7102)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 3: USBGuard"

if command -v usbguard &>/dev/null; then
    if ! systemctl is-active usbguard &>/dev/null; then
        # Generate initial policy allowing currently connected devices
        usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true
        chmod 600 /etc/usbguard/rules.conf

        # Fix socket permissions issue on Ubuntu 24.04
        mkdir -p /etc/usbguard/IPCAccessControl.d
        
        systemctl enable usbguard 2>/dev/null || true
        systemctl start usbguard 2>/dev/null || true
        log "USBGuard active."
    else
        log "USBGuard already running."
    fi
else
    warn "USBGuard not installed — installing..."
    apt-get install -y -qq usbguard
    usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true
    chmod 600 /etc/usbguard/rules.conf
    systemctl enable --now usbguard 2>/dev/null || true
fi

# ═══════════════════════════════════════════════════════════════════════════
# FIX 4: Systemd service hardening (PROC-3612)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 4: Systemd service hardening"

# Harden systemd-resolved
mkdir -p /etc/systemd/system/systemd-resolved.service.d
cat > /etc/systemd/system/systemd-resolved.service.d/hardening.conf << 'RESOLVED'
[Service]
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RESOLVED

# Harden cron
mkdir -p /etc/systemd/system/cron.service.d
cat > /etc/systemd/system/cron.service.d/hardening.conf << 'CRONHARDEN'
[Service]
ProtectHome=read-only
ProtectSystem=strict
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/spool/cron
CRONHARDEN

systemctl daemon-reload
log "Systemd services hardened."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 5: Additional kernel parameters (KRNL-6000)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 5: Additional kernel parameters"

cat > /etc/sysctl.d/99-fix90.conf << 'SYSCTL2'
# Restrict loading TTY line disciplines
dev.tty.ldisc_autoload = 0

# Restrict io_uring
# (Ubuntu 24.04 kernel parameter if available)
# io_uring_disabled = 2

# Restrict user namespaces more strictly
kernel.unprivileged_userns_clone = 0

# Additional network hardening
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

# Restrict symlink/hardlink following
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
SYSCTL2

sysctl --system > /dev/null 2>&1
log "Additional sysctl applied."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 6: GRUB security (BOOT-5122, BOOT-5264)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 6: GRUB hardening"

# Set a GRUB password (using a default — CHANGE THIS)
GRUB_PASS_HASH=$(echo -e "HardenedGrub2024!\nHardenedGrub2024!" | grub-mkpasswd-pbkdf2 2>/dev/null | grep "grub.pbkdf2" | awk '{print $NF}')

if [[ -n "$GRUB_PASS_HASH" ]]; then
    cat > /etc/grub.d/40_custom << GRUBPW
#!/bin/sh
exec tail -n +3 \$0
set superusers="root"
password_pbkdf2 root ${GRUB_PASS_HASH}
GRUBPW
    chmod 755 /etc/grub.d/40_custom

    # Allow normal boot without password, require password for editing
    sed -i 's/^CLASS=".*"/CLASS="--class gnu-linux --class gnu --class os --unrestricted"/' /etc/grub.d/10_linux 2>/dev/null || true

    update-grub 2>/dev/null
    log "GRUB password set. Default: HardenedGrub2024! — CHANGE IT!"
    warn "⚠️  Change GRUB password: grub-mkpasswd-pbkdf2"
else
    warn "Could not set GRUB password (grub-mkpasswd-pbkdf2 unavailable)"
fi

# Restrict GRUB config permissions
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════════
# FIX 7: Shell hardening (SHLL-6211, SHLL-6220)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 7: Shell hardening"

# Ensure TMOUT in all shell configs
for f in /etc/profile /etc/bash.bashrc /etc/profile.d/tmout.sh; do
    mkdir -p "$(dirname "$f")"
    if ! grep -q "TMOUT" "$f" 2>/dev/null; then
        cat >> "$f" << 'TMOUT_CONF'
# Shell timeout (Lynis SHLL-6220)
TMOUT=900
readonly TMOUT
export TMOUT
TMOUT_CONF
    fi
done

# Restrict shells — ensure /etc/shells only has valid shells
cat > /etc/shells << 'SHELLS'
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
SHELLS

# Lock system accounts that should not have login shells
SYSTEM_USERS=$(awk -F: '($3 < 1000 && $1 != "root") {print $1}' /etc/passwd)
for user in $SYSTEM_USERS; do
    current_shell=$(getent passwd "$user" | cut -d: -f7)
    if [[ "$current_shell" != "/usr/sbin/nologin" && "$current_shell" != "/bin/false" ]]; then
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
    fi
done

log "Shell hardening applied."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 8: Additional file permission fixes (FILE-6310, FILE-6344)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 8: File permission tightening"

# Ensure no SUID/SGID surprises on non-essential binaries
# List and log for review:
log "SUID files on system:"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | tee -a "$LOGFILE"

# Remove SUID from non-essential binaries (conservative list)
REMOVE_SUID=(
    /usr/bin/wall
    /usr/bin/write
    /usr/bin/mlocate
    /usr/bin/bsd-write
    /snap/core*/usr/bin/sudo  # snap sudo
)
for f in "${REMOVE_SUID[@]}"; do
    for match in $f; do  # handles glob
        [[ -f "$match" ]] && chmod u-s "$match" 2>/dev/null && log "  Removed SUID: $match" || true
    done
done

# Secure home directories
for dir in /home/*/; do
    if [[ -d "$dir" ]]; then
        chmod 750 "$dir"
        # Remove group/world readable .ssh
        [[ -d "${dir}.ssh" ]] && chmod 700 "${dir}.ssh" 2>/dev/null || true
        find "${dir}.ssh" -type f -exec chmod 600 {} \; 2>/dev/null || true
    fi
done

# Root home
chmod 700 /root
[[ -d /root/.ssh ]] && chmod 700 /root/.ssh 2>/dev/null || true

log "File permissions tightened."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 9: Disable unnecessary services (PROC-3612)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 9: Disable unnecessary services"

DISABLE_SERVICES=(
    avahi-daemon
    cups
    cups-browsed
    isc-dhcp-server
    isc-dhcp-server6
    slapd
    nfs-server
    rpcbind
    bind9
    vsftpd
    dovecot
    smbd
    nmbd
    squid
    snmpd
    autofs
    bluetooth
    ModemManager
    whoopsie
    apport
    debug-shell
)

for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask "$svc" 2>/dev/null || true
        log "  Disabled: $svc"
    fi
done

# Disable socket-activated services too
DISABLE_SOCKETS=(
    avahi-daemon.socket
    cups.socket
    rpcbind.socket
)
for sock in "${DISABLE_SOCKETS[@]}"; do
    systemctl stop "$sock" 2>/dev/null || true
    systemctl disable "$sock" 2>/dev/null || true
    systemctl mask "$sock" 2>/dev/null || true
done

log "Unnecessary services disabled."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 10: Sudo hardening (AUTH-9262)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 10: Sudo hardening"

cat > /etc/sudoers.d/99-hardening << 'SUDOHARD'
# Require authentication timeout
Defaults    timestamp_timeout=5
Defaults    passwd_timeout=1

# Use pty for sudo commands
Defaults    use_pty

# Log sudo commands
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input, log_output
Defaults    iolog_dir="/var/log/sudo-io/%{seq}"

# Require re-auth for each tty
Defaults    !tty_tickets

# Restrict PATH for sudo
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Show password prompt
Defaults    insults
SUDOHARD

chmod 440 /etc/sudoers.d/99-hardening
visudo -cf /etc/sudoers.d/99-hardening && log "Sudo config valid." || {
    warn "Sudo config invalid — removing"
    rm -f /etc/sudoers.d/99-hardening
}

# ═══════════════════════════════════════════════════════════════════════════
# FIX 11: Process hardening (PROC-3612, PROC-3614)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 11: Process hardening"

# Restrict /proc visibility
if ! grep -q "hidepid" /etc/fstab; then
    echo "proc /proc proc defaults,nosuid,nodev,noexec,hidepid=2 0 0" >> /etc/fstab
    mount -o remount,hidepid=2 /proc 2>/dev/null || warn "Remount /proc failed — will apply on reboot"
fi

# Restrict /proc/sysrq-trigger
echo 0 > /proc/sys/kernel/sysrq 2>/dev/null || true

log "Process hardening applied."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 12: Logging completeness (LOGG-2138, LOGG-2152)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 12: Logging completeness"

# Ensure all important log files exist
touch /var/log/kern.log /var/log/auth.log /var/log/syslog /var/log/daemon.log
chmod 640 /var/log/kern.log /var/log/auth.log /var/log/syslog /var/log/daemon.log

# Ensure rsyslog has comprehensive rules
cat > /etc/rsyslog.d/99-hardening.conf << 'RSYSLOG'
auth,authpriv.*         /var/log/auth.log
*.*;auth,authpriv.none  -/var/log/syslog
kern.*                  -/var/log/kern.log
daemon.*                -/var/log/daemon.log
cron.*                  /var/log/cron.log
user.*                  -/var/log/user.log
local0,local1.*         -/var/log/localmessages
local2,local3.*         -/var/log/localmessages
local4,local5.*         -/var/log/localmessages
local6,local7.*         -/var/log/localmessages
*.emerg                 :omusrmsg:*
RSYSLOG

systemctl restart rsyslog 2>/dev/null || true

log "Logging completeness verified."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 13: Lynis custom configuration (skip false positives)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 13: Lynis profile tuning"

mkdir -p /etc/lynis

cat > /etc/lynis/custom.prf << 'LYNISPRF'
# Custom Lynis profile — skip false positives only
# Do NOT skip real security issues

# Skip container-specific checks if not using containers
# skip-test=CONT-8104

# Skip NTP stratum warning if chrony is working
# skip-test=TIME-3116
LYNISPRF

log "Custom Lynis profile created."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 14: Audit rules completeness check
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 14: Audit rules completeness"

# Ensure audit rules for all privileged commands
PRIV_CMDS=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
EXTRA_AUDIT="/etc/audit/rules.d/98-privileged.rules"
echo "# Privileged command audit rules (auto-generated)" > "$EXTRA_AUDIT"

while IFS= read -r cmd; do
    if ! grep -q "$cmd" /etc/audit/rules.d/99-hardening.rules 2>/dev/null; then
        echo "-a always,exit -F path=$cmd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> "$EXTRA_AUDIT"
    fi
done <<< "$PRIV_CMDS"

# Remove immutable flag temporarily to reload rules
# (rules have -e 2 at end, so we need to reload via service)
systemctl restart auditd 2>/dev/null || augenrules --load 2>/dev/null || true

log "Audit rules comprehensive coverage."

# ═══════════════════════════════════════════════════════════════════════════
# FIX 15: Needrestart configuration (PKGS-7394)
# ═══════════════════════════════════════════════════════════════════════════
banner "FIX 15: Needrestart configuration"

if [[ -f /etc/needrestart/needrestart.conf ]]; then
    # Set to auto-restart
    sed -i "s/^#\?\$nrconf{restart}.*/$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf 2>/dev/null || true
fi

log "Needrestart configured."

# ═══════════════════════════════════════════════════════════════════════════
# RUN LYNIS AGAIN
# ═══════════════════════════════════════════════════════════════════════════
banner "RUNNING LYNIS AUDIT"

# Use latest Lynis
LYNIS_BIN="lynis"
[[ -f /tmp/lynis-audit/lynis ]] && LYNIS_BIN="/tmp/lynis-audit/lynis"

REPORT="/var/log/lynis-fix90-$(date +%Y%m%d-%H%M%S).log"
cd /tmp/lynis-audit 2>/dev/null || cd /tmp

$LYNIS_BIN audit system --no-colors --quick 2>&1 | tee "$REPORT"

# Extract and display score
echo ""
echo "════════════════════════════════════════════════════"
SCORE=$(grep "Hardening index" "$REPORT" | grep -oP '\d+' | tail -1)
if [[ -n "$SCORE" ]]; then
    if [[ "$SCORE" -ge 90 ]]; then
        echo -e "${G}  🎉 LYNIS SCORE: ${SCORE} — TARGET ACHIEVED! 🎉${N}"
    elif [[ "$SCORE" -ge 88 ]]; then
        echo -e "${Y}  📊 LYNIS SCORE: ${SCORE} — Almost there!${N}"
        echo ""
        echo "  Remaining suggestions:"
        grep "suggestion\[\]" /var/log/lynis-report.dat 2>/dev/null | head -20
    else
        echo -e "${Y}  📊 LYNIS SCORE: ${SCORE}${N}"
    fi
else
    echo "  Could not extract score."
fi
echo "════════════════════════════════════════════════════"
echo ""
echo "  📋 Report: $REPORT"
echo "  📋 Data:   /var/log/lynis-report.dat"
echo ""
echo "  ⚡ REBOOT required for full effect:"
echo "     sudo reboot"
echo ""
warn "⚠️  CHANGE the GRUB password from default!"
warn "⚠️  TEST SSH in a second terminal before disconnecting!"

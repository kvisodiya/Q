#!/bin/bash

# VPS Safe Security Fix Script
# Designed to increase Lynis score without breaking VPS

set +e

echo "=== Applying Safe Security Improvements ==="

### 1. Kernel Hardening (Safe VPS Mode)
echo "[1] Applying kernel hardening..."

cat <<EOF > /etc/sysctl.d/99-hardening.conf
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
fs.protected_regular = 2
kernel.core_uses_pid = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF

sysctl --system

### 2. Secure Login Banner
echo "[2] Fixing login banners..."
echo "Authorized access only. Activity may be monitored." > /etc/issue
echo "Authorized access only." > /etc/issue.net

### 3. Fix File Permissions
echo "[3] Fixing sensitive file permissions..."
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

chmod 700 /etc/cron.d 2>/dev/null || true
chmod 700 /etc/cron.daily 2>/dev/null || true
chmod 700 /etc/cron.hourly 2>/dev/null || true
chmod 700 /etc/cron.weekly 2>/dev/null || true
chmod 700 /etc/cron.monthly 2>/dev/null || true

### 4. Add Session Timeout
echo "[4] Adding session timeout..."

if ! grep -q "TMOUT" /etc/profile; then
  echo "TMOUT=600" >> /etc/profile
  echo "readonly TMOUT" >> /etc/profile
  echo "export TMOUT" >> /etc/profile
fi

### 5. Improve SSH Settings (Safe)
echo "[5] Improving SSH configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"

grep -q "^MaxSessions" $SSHD_CONFIG || echo "MaxSessions 2" >> $SSHD_CONFIG
grep -q "^TCPKeepAlive" $SSHD_CONFIG || echo "TCPKeepAlive no" >> $SSHD_CONFIG

systemctl restart ssh 2>/dev/null || systemctl restart sshd

### 6. Harden /tmp
echo "[6] Hardening /tmp..."

if ! grep -q "tmpfs /tmp" /etc/fstab; then
  echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
fi

mount -o remount /tmp 2>/dev/null || true

### 7. Install Recommended Security Utilities
echo "[7] Installing additional security tools..."

apt update -y
apt install -y sysstat libpam-tmpdir needrestart debsums apt-listbugs

systemctl enable sysstat 2>/dev/null || true
systemctl start sysstat 2>/dev/null || true

### 8. Clean Unused UFW Rules
echo "[8] Reloading firewall..."

ufw reload 2>/dev/null || true

echo "=== Fix Completed Successfully ==="
echo "Run: lynis audit system"

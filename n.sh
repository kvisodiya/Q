#!/bin/bash

set +e

echo "=== Remounting Root Filesystem RW ==="
mount -o remount,rw /

echo "=== Fixing Broken dpkg State ==="
dpkg --configure -a
apt -f install -y
apt clean

echo "=== Resetting Failed Systemd Units ==="
systemctl reset-failed

echo "=== Disabling Potentially Problematic Services ==="
systemctl disable unbound 2>/dev/null
systemctl disable tor 2>/dev/null

echo "=== Stopping Services Safely ==="
systemctl stop unbound 2>/dev/null
systemctl stop tor 2>/dev/null

echo "=== Checking /etc/fstab for Errors ==="
if grep -q "UUID=" /etc/fstab; then
    echo "fstab looks normal."
else
    echo "WARNING: fstab may contain invalid entries."
fi

echo "=== Restoring Basic DNS ==="
echo "nameserver 1.1.1.1" > /etc/resolv.conf

echo "=== Restarting Networking ==="
systemctl restart networking 2>/dev/null

echo "=== Rebuilding Initramfs (Safety) ==="
update-initramfs -u

echo "=== Done. Reboot Recommended ==="
echo "Run: reboot"

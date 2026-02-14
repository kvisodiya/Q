#!/bin/bash
set -e

echo "=== Stopping Services ==="
systemctl stop tor unbound 2>/dev/null || true

echo "=== Removing Old Configs ==="
rm -rf /etc/unbound/unbound.conf.d/*
rm -f /etc/tor/torrc
rm -f /etc/resolv.conf

echo "=== Resetting DNS ==="
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

echo "=== Reloading Systemd Daemon ==="
systemctl daemon-reload

echo "=== Removing Emergency Mode Flags ==="
# If emergency mode triggered due to systemd targets
systemctl set-default multi-user.target
systemctl default || true

echo "=== Clean-Up Done ==="
echo "Tor and Unbound configs removed, DNS reset, system ready."

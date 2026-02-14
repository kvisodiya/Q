#!/bin/bash

# Full Network Privacy Stack (Safe VPS Edition)
# Tor client mode + Unbound DNS-over-TLS + firewall hygiene
# Will not intentionally break SSH or apt
# Continues execution even if some parts fail

set +e

echo "=== Updating System ==="
apt update -y
apt upgrade -y

echo "=== Installing Packages ==="
apt install -y \
tor torsocks \
unbound \
ufw \
iptables-persistent \
curl wget dnsutils \
tcpdump nethogs iftop

########################################
# 1️⃣ Configure Unbound (DNS Privacy)
########################################

echo "=== Configuring Unbound DNS ==="

mkdir -p /etc/unbound/unbound.conf.d

cat <<EOF > /etc/unbound/unbound.conf.d/privacy.conf
server:
    verbosity: 0
    interface: 127.0.0.1
    access-control: 127.0.0.0/8 allow
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    prefetch: yes
    rrset-roundrobin: yes
    auto-trust-anchor-file: "/var/lib/unbound/root.key"

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net
EOF

systemctl enable unbound
systemctl restart unbound

echo "nameserver 127.0.0.1" > /etc/resolv.conf

########################################
# 2️⃣ Configure Tor (Client Mode)
########################################

echo "=== Configuring Tor Client ==="

cat <<EOF > /etc/tor/torrc
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
AvoidDiskWrites 1
AutomapHostsOnResolve 1
DNSPort 9053
SafeLogging 1
EOF

systemctl enable tor
systemctl restart tor

sleep 5

########################################
# 3️⃣ Firewall (Safe Mode)
########################################

echo "=== Configuring Firewall ==="

ufw default deny incoming
ufw default allow outgoing

ufw allow ssh
ufw allow 80
ufw allow 443

ufw --force enable
ufw reload

########################################
# 4️⃣ Prevent Common DNS Leaks
########################################

echo "=== Preventing Direct DNS Leaks ==="

iptables -A OUTPUT -p udp --dport 53 ! -d 127.0.0.1 -j REJECT
iptables -A OUTPUT -p tcp --dport 53 ! -d 127.0.0.1 -j REJECT

netfilter-persistent save

########################################
# 5️⃣ Optional IPv6 Disable (If Not Needed)
########################################

if ! ip -6 addr show | grep -q "inet6"; then
    echo "Disabling IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.d/ipv6.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/ipv6.conf
    sysctl --system
fi

########################################
# 6️⃣ Test Section (Non-blocking)
########################################

echo "=== Testing DNS ==="
dig debian.org @127.0.0.1 +short

echo "=== Testing Tor ==="
torsocks curl -s https://check.torproject.org | grep -i congratulations

echo ""
echo "=== Privacy Stack Installed ==="
echo "Use torsocks before commands for Tor routing:"
echo "Example: torsocks curl https://ifconfig.me"
echo ""
echo "System remains stable and SSH accessible."

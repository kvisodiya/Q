#!/bin/bash

set +e

echo "=== Updating System ==="
apt update -y
apt upgrade -y

echo "=== Installing Packages ==="
apt install -y tor torsocks unbound ufw curl wget dnsutils iptables-persistent

########################################
# 1️⃣ Configure Unbound Safely
########################################

echo "=== Configuring Unbound ==="

mkdir -p /etc/unbound/unbound.conf.d

unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null

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
    auto-trust-anchor-file: "/var/lib/unbound/root.key"

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net
EOF

systemctl enable unbound
systemctl restart unbound

sleep 3

########################################
# 2️⃣ Configure Tor Safely
########################################

echo "=== Configuring Tor ==="

if ! grep -q "SocksPort 9050" /etc/tor/torrc 2>/dev/null; then
cat <<EOF >> /etc/tor/torrc

# Privacy Stack Settings
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
AvoidDiskWrites 1
SafeLogging 1
EOF
fi

systemctl enable tor
systemctl restart tor

sleep 8

########################################
# 3️⃣ Configure Firewall (Safe Mode)
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
# 4️⃣ Prevent Direct DNS Leaks
########################################

echo "=== Applying DNS Leak Protection ==="

iptables -C OUTPUT -p udp --dport 53 ! -d 127.0.0.1 -j REJECT 2>/dev/null || \
iptables -A OUTPUT -p udp --dport 53 ! -d 127.0.0.1 -j REJECT

iptables -C OUTPUT -p tcp --dport 53 ! -d 127.0.0.1 -j REJECT 2>/dev/null || \
iptables -A OUTPUT -p tcp --dport 53 ! -d 127.0.0.1 -j REJECT

netfilter-persistent save

########################################
# 5️⃣ Safe Testing Section
########################################

echo ""
echo "=== Service Status ==="
systemctl is-active unbound
systemctl is-active tor

echo ""
echo "=== Testing Local DNS ==="
dig debian.org @127.0.0.1 +short

echo ""
echo "=== Testing Tor ==="
torsocks curl -s https://check.torproject.org | grep -i tor

echo ""
echo "=== Normal Public IP ==="
curl -s https://ifconfig.me

echo ""
echo "=== Tor Public IP ==="
torsocks curl -s https://ifconfig.me

echo ""
echo "=== Finished Safely ==="
echo "SSH remains accessible."

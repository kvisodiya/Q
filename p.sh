#!/bin/bash

set -e

echo "=== Updating System ==="
apt update -y
apt upgrade -y

echo "=== Installing Privacy Packages ==="
apt install -y unbound tor torsocks dnsutils curl

########################################
# Configure Unbound (DNS over TLS)
########################################

echo "=== Configuring Unbound ==="

mkdir -p /etc/unbound/unbound.conf.d

unbound-anchor -a /var/lib/unbound/root.key || true

cat <<EOF > /etc/unbound/unbound.conf.d/dot.conf
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

########################################
# Configure System to Use Local DNS
########################################

echo "=== Setting Local DNS ==="
echo "nameserver 127.0.0.1" > /etc/resolv.conf

########################################
# Configure Tor (Client Only)
########################################

echo "=== Configuring Tor Client ==="

if ! grep -q "SocksPort 9050" /etc/tor/torrc; then
cat <<EOF >> /etc/tor/torrc

# Privacy Mode
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
AvoidDiskWrites 1
SafeLogging 1
EOF
fi

systemctl enable tor
systemctl restart tor

echo ""
echo "=== Services Status ==="
systemctl is-active unbound
systemctl is-active tor

echo ""
echo "=== Testing DNS (Encrypted) ==="
dig debian.org +short

echo ""
echo "=== Normal Public IP ==="
curl -s https://ifconfig.me

echo ""
echo "=== Tor Public IP ==="
torsocks curl -s https://ifconfig.me

echo ""
echo "=== Stable Privacy Stack Ready ==="

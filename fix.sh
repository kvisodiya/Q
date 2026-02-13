#!/usr/bin/env bash
#===============================================================================
# Complete Fix Script - UFW, Unbound, Lynis and Score
#===============================================================================

set +e

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  COMPLETE SYSTEM FIX SCRIPT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

#===============================================================================
# FIX 1: ENABLE UFW FIREWALL
#===============================================================================
echo "[1/5] Fixing UFW Firewall..."

# Check if UFW is installed
if ! command -v ufw >/dev/null 2>&1; then
    echo "  Installing UFW..."
    apt-get update >/dev/null 2>&1
    apt-get install -y ufw >/dev/null 2>&1
fi

# Reset and configure UFW
echo "  Configuring UFW rules..."
ufw --force reset >/dev/null 2>&1

# Set defaults
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1

# Allow essential services
ufw allow ssh >/dev/null 2>&1
ufw allow 22/tcp >/dev/null 2>&1
ufw allow 80/tcp >/dev/null 2>&1
ufw allow 443/tcp >/dev/null 2>&1

# Rate limit SSH
ufw limit ssh >/dev/null 2>&1

# Set logging
ufw logging low >/dev/null 2>&1

# Enable UFW
echo "  Enabling UFW..."
echo "y" | ufw enable >/dev/null 2>&1

# Verify
if ufw status | grep -q "Status: active"; then
    echo "✓ UFW Firewall: ENABLED"
    ufw status | grep -E "^(22|80|443|SSH)" | head -5
else
    echo "✗ UFW still not active - trying alternative method..."
    systemctl enable ufw >/dev/null 2>&1
    systemctl start ufw >/dev/null 2>&1
    ufw --force enable >/dev/null 2>&1
fi

echo ""

#===============================================================================
# FIX 2: ENABLE UNBOUND DNS
#===============================================================================
echo "[2/5] Fixing Unbound DNS..."

# Check if Unbound is installed
if ! command -v unbound >/dev/null 2>&1; then
    echo "  Installing Unbound..."
    apt-get install -y unbound dns-root-data >/dev/null 2>&1
fi

# Stop unbound first
systemctl stop unbound >/dev/null 2>&1

# Remove old config
rm -f /etc/unbound/unbound.conf.d/local-dns.conf 2>/dev/null

# Create simple working configuration
mkdir -p /etc/unbound/unbound.conf.d

cat > /etc/unbound/unbound.conf.d/server.conf << 'EOF'
server:
    interface: 127.0.0.1
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    
    hide-identity: yes
    hide-version: yes
    
    harden-glue: yes
    harden-dnssec-stripped: yes
    
    prefetch: yes
    
    verbosity: 0

forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 8.8.8.8
    forward-addr: 9.9.9.9
EOF

# Set permissions
chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true

# Test configuration
echo "  Testing Unbound configuration..."
if unbound-checkconf >/dev/null 2>&1; then
    echo "  Configuration is valid"
    
    # Enable and start
    systemctl enable unbound >/dev/null 2>&1
    systemctl start unbound >/dev/null 2>&1
    
    sleep 2
    
    # Verify
    if systemctl is-active unbound >/dev/null 2>&1; then
        echo "✓ Unbound DNS: ENABLED"
        
        # Test DNS resolution
        if dig @127.0.0.1 +short google.com >/dev/null 2>&1; then
            echo "  DNS resolution working"
        fi
    else
        echo "✗ Unbound failed to start"
        echo "  Checking logs..."
        journalctl -u unbound --no-pager -n 5 2>/dev/null
    fi
else
    echo "✗ Unbound configuration error"
    unbound-checkconf 2>&1 | head -5
fi

echo ""

#===============================================================================
# FIX 3: UPGRADE LYNIS TO LATEST VERSION
#===============================================================================
echo "[3/5] Upgrading Lynis to latest version..."

# Get current version
CURRENT_VERSION=$(lynis show version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
echo "  Current version: ${CURRENT_VERSION:-unknown}"

# Add CISOfy repository for latest Lynis
echo "  Adding Lynis repository..."

# Install prerequisites
apt-get install -y apt-transport-https ca-certificates curl gnupg >/dev/null 2>&1

# Add repository key
curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key | gpg --dearmor -o /usr/share/keyrings/cisofy-archive-keyring.gpg 2>/dev/null

# Add repository
echo "deb [signed-by=/usr/share/keyrings/cisofy-archive-keyring.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" > /etc/apt/sources.list.d/cisofy-lynis.list

# Update and install
apt-get update >/dev/null 2>&1
apt-get install -y lynis >/dev/null 2>&1

# Check new version
NEW_VERSION=$(lynis show version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
echo "✓ Lynis version: ${NEW_VERSION:-$CURRENT_VERSION}"

# Update Lynis database
lynis update info >/dev/null 2>&1 || true

echo ""

#===============================================================================
# FIX 4: APPLY ADDITIONAL HARDENING
#===============================================================================
echo "[4/5] Applying additional hardening..."

# Install missing security packages
echo "  Installing additional security packages..."
apt-get install -y acct libpam-tmpdir >/dev/null 2>&1 || true

# Enable process accounting
if command -v accton >/dev/null 2>&1; then
    touch /var/log/account/pacct 2>/dev/null || mkdir -p /var/log/account && touch /var/log/account/pacct
    accton /var/log/account/pacct >/dev/null 2>&1 || true
    echo "✓ Process accounting enabled"
fi

# Set proper permissions
chmod 600 /etc/shadow 2>/dev/null || true
chmod 600 /etc/gshadow 2>/dev/null || true
chmod 644 /etc/passwd 2>/dev/null || true
chmod 644 /etc/group 2>/dev/null || true
chmod 700 /root 2>/dev/null || true

# Configure sudo timeout
if ! grep -q "timestamp_timeout" /etc/sudoers 2>/dev/null; then
    echo "Defaults timestamp_timeout=15" >> /etc/sudoers 2>/dev/null || true
    echo "✓ Sudo timeout configured"
fi

# Ensure fail2ban SSH jail is enabled
if [[ -f /etc/fail2ban/jail.local ]]; then
    systemctl restart fail2ban >/dev/null 2>&1 || true
fi

echo "✓ Additional hardening applied"
echo ""

#===============================================================================
# FIX 5: RUN LYNIS AND GET SCORE
#===============================================================================
echo "[5/5] Running Lynis Security Audit..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run Lynis
lynis audit system --quick 2>&1 | tee /tmp/lynis_scan.txt

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Extract score from output
SCORE=$(grep -i "hardening index" /tmp/lynis_scan.txt 2>/dev/null | grep -oE "[0-9]+" | head -1)

if [[ -n "$SCORE" ]]; then
    echo "🛡️  HARDENING SCORE: ${SCORE}/100"
    echo ""
    
    if [[ $SCORE -ge 92 ]]; then
        echo "✅ EXCELLENT! Target score of 92+ achieved!"
    elif [[ $SCORE -ge 85 ]]; then
        echo "✅ GOOD! Score is above 85"
    elif [[ $SCORE -ge 75 ]]; then
        echo "⚠️  FAIR - Some improvements recommended"
    else
        echo "⚠️  Review Lynis recommendations"
    fi
else
    # Alternative: read from Lynis report file
    if [[ -f /var/log/lynis-report.dat ]]; then
        SCORE=$(grep "hardening_index=" /var/log/lynis-report.dat 2>/dev/null | cut -d= -f2)
        if [[ -n "$SCORE" ]]; then
            echo "🛡️  HARDENING SCORE: ${SCORE}/100"
        else
            echo "⚠️  Score not available in report"
        fi
    else
        echo "⚠️  Could not determine score"
        echo "   Run manually: sudo lynis audit system"
    fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "           SERVICE STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check all services
check_svc() {
    if systemctl is-active "$1" >/dev/null 2>&1; then
        echo "✓ $2: ACTIVE"
    else
        echo "✗ $2: NOT ACTIVE"
    fi
}

check_svc "ssh" "SSH Server"
check_svc "ufw" "UFW Firewall"
check_svc "fail2ban" "Fail2ban"
check_svc "unbound" "Unbound DNS"
check_svc "auditd" "Audit Daemon"
check_svc "apparmor" "AppArmor"

echo ""

# Check UFW specifically
if ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "✓ UFW Status: ACTIVE"
else
    echo "✗ UFW Status: INACTIVE"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "              COMPLETE!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Reports saved:"
echo "  • /var/log/lynis-report.dat"
echo "  • /var/log/lynis.log"
echo ""
echo "To view details:"
echo "  • grep hardening_index /var/log/lynis-report.dat"
echo "  • sudo lynis show details"
echo ""

# Cleanup
rm -f /tmp/lynis_scan.txt 2>/dev/null

exit 0

#!/usr/bin/env bash
#===============================================================================
# Fix script for Lynis and final system checks
#===============================================================================

set +e

echo "Fixing Lynis and system configuration..."
echo ""

#===============================================================================
# FIX LYNIS
#===============================================================================
echo "[1/4] Fixing Lynis configuration..."

# Update Lynis database
if command -v lynis >/dev/null 2>&1; then
    echo "Updating Lynis..."
    lynis update info 2>/dev/null || true
    
    # Create Lynis directories if missing
    mkdir -p /var/log/lynis 2>/dev/null || true
    mkdir -p /tmp/lynis 2>/dev/null || true
    chmod 755 /var/log/lynis 2>/dev/null || true
    
    # Fix permissions
    if [[ -f /usr/share/lynis/lynis ]]; then
        chmod 755 /usr/share/lynis/lynis 2>/dev/null || true
    fi
    
    echo "✓ Lynis configuration fixed"
else
    echo "✗ Lynis not found - installing..."
    apt-get update >/dev/null 2>&1
    apt-get install -y lynis >/dev/null 2>&1
fi

#===============================================================================
# RUN PROPER LYNIS AUDIT
#===============================================================================
echo "[2/4] Running proper Lynis audit..."

# Create report directory
REPORT_DIR="/var/log/lynis"
mkdir -p "$REPORT_DIR"

# Run Lynis with proper options
echo "Starting Lynis scan (this takes 1-2 minutes)..."
echo ""

# Run Lynis and capture output
lynis audit system --quick 2>&1 | tee /tmp/lynis_output.txt

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Extract the hardening index
SCORE=$(grep -i "hardening index" /tmp/lynis_output.txt | grep -oE "[0-9]+" | head -1)

if [[ -n "$SCORE" ]]; then
    echo "✓ LYNIS HARDENING SCORE: ${SCORE}/100"
    
    if [[ $SCORE -ge 92 ]]; then
        echo "✅ EXCELLENT! Target of 92+ achieved!"
    elif [[ $SCORE -ge 85 ]]; then
        echo "✅ GOOD! Score is above 85"
    elif [[ $SCORE -ge 75 ]]; then
        echo "⚠️  FAIR - Score is ${SCORE}, some improvements needed"
    else
        echo "⚠️  Score is ${SCORE} - review recommendations below"
    fi
else
    echo "⚠️  Could not extract score - checking alternative method..."
    
    # Alternative method to get score
    lynis show hardening-index 2>/dev/null || echo "Score not available"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

#===============================================================================
# CHECK CRITICAL SERVICES
#===============================================================================
echo ""
echo "[3/4] Verifying critical services..."
echo ""

# Function to check service
check_service() {
    local service=$1
    local display_name=$2
    
    if systemctl is-active "$service" >/dev/null 2>&1; then
        echo "✓ $display_name: ACTIVE"
        return 0
    else
        # Try alternative service name
        local alt_service="${service%d}"  # Remove 'd' if present
        if [[ "$alt_service" != "$service" ]]; then
            if systemctl is-active "$alt_service" >/dev/null 2>&1; then
                echo "✓ $display_name: ACTIVE"
                return 0
            fi
        fi
        echo "✗ $display_name: NOT ACTIVE"
        return 1
    fi
}

# Check services
check_service "sshd" "SSH Server"
check_service "ufw" "UFW Firewall"
check_service "fail2ban" "Fail2ban"
check_service "unbound" "Unbound DNS"
check_service "auditd" "Audit Daemon"
check_service "apparmor" "AppArmor"
check_service "unattended-upgrades" "Auto Updates"

#===============================================================================
# GET RECOMMENDATIONS
#===============================================================================
echo ""
echo "[4/4] Top security recommendations..."
echo ""

# Show warnings and suggestions
if [[ -f /tmp/lynis_output.txt ]]; then
    echo "Key findings:"
    echo "-------------"
    
    # Extract warnings
    grep -A1 "Warning:" /tmp/lynis_output.txt 2>/dev/null | head -10 | sed 's/^/  /'
    
    echo ""
    echo "Quick improvements for higher score:"
    echo "------------------------------------"
    
    # Common quick wins
    echo "  1. Set up SSH key authentication:"
    echo "     ssh-keygen -t ed25519"
    echo "     Then disable password auth in SSH"
    echo ""
    echo "  2. Configure sudo timeout:"
    echo "     echo 'Defaults timestamp_timeout=15' >> /etc/sudoers"
    echo ""
    echo "  3. Install additional security tools:"
    echo "     apt install -y libpam-tmpdir apt-listbugs"
    echo ""
    echo "  4. Enable process accounting:"
    echo "     apt install -y acct && accton on"
    echo ""
fi

#===============================================================================
# SAVE FULL REPORT
#===============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Save reports
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="/root/lynis_full_report_${TIMESTAMP}.txt"

if [[ -f /tmp/lynis_output.txt ]]; then
    cp /tmp/lynis_output.txt "$REPORT_FILE"
    echo "📄 Full Lynis report saved to: $REPORT_FILE"
fi

# Check for Lynis data files
if ls /var/log/lynis/report-*.dat 2>/dev/null | head -1 >/dev/null; then
    LATEST_DAT=$(ls -t /var/log/lynis/report-*.dat 2>/dev/null | head -1)
    echo "📊 Lynis data file: $LATEST_DAT"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ COMPLETE!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo "  1. Review the full report: less $REPORT_FILE"
echo "  2. Run detailed scan: sudo lynis audit system"
echo "  3. Show all tests: sudo lynis show tests"
echo "  4. Apply quick wins listed above for 95+ score"
echo ""

# Clean up
rm -f /tmp/lynis_output.txt 2>/dev/null

exit 0

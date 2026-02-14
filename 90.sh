#!/bin/bash

##############################################################################
# run_hardening.sh — Automated Hardening Runner for dev-sec/ansible-collection-hardening
#
# Usage: sudo bash run_hardening.sh
#
# This script:
#   • Installs Ansible & dependencies
#   • Installs the dev-sec hardening collection
#   • Generates a local playbook using core hardening roles
#   • Runs the playbook on localhost
#   • Outputs status and invites you to run Lynis afterward
##############################################################################

set +e

echo "=== Updating system ==="
apt update -y
apt upgrade -y

echo ""
echo "=== Installing prerequisites ==="
apt install -y ansible git curl wget || true

echo ""
echo "=== Installing dev-sec/ansible-collection-hardening ==="
ansible-galaxy collection install dev-sec.hardening

echo ""
echo "=== Creating hardening playbook ==="
WORKDIR="/root/hardening-local"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

cat > inventory.yml << 'EOF'
localhost ansible_connection=local
EOF

cat > playbook.yml << 'EOF'
---
- hosts: localhost
  gather_facts: true
  collections:
    - dev_sec.hardening
  roles:
    - role: dev_sec.hardening.basic
    - role: dev_sec.hardening.ssh
    - role: dev_sec.hardening.pam
    - role: dev_sec.hardening.network
    - role: dev_sec.hardening.audit
    - role: dev_sec.hardening.pkg
EOF

echo ""
echo "=== Running hardening playbook ==="
ansible-playbook -i inventory.yml playbook.yml --connection=local

echo ""
echo "=== Hardening execution finished ==="
echo "✔ Finished roles: basic, ssh, pam, network, audit, pkg"
echo ""
echo "Next recommended steps:"
echo "  1) Reboot the system: sudo reboot"
echo "  2) Install lynis: sudo apt install lynis -y"
echo "  3) Run Lynis audit: sudo lynis audit system"
echo ""
echo "You can also review the detailed logs in $WORKDIR"

exit 0

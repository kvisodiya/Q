#!/bin/bash

set +e

echo "=== Updating system ==="
apt update -y
apt upgrade -y

echo "=== Installing prerequisites ==="
apt install -y ansible git curl wget || true

echo "=== Installing dev-sec hardening roles/collection ==="
# The new correct collection namespace
ansible-galaxy collection install dev-sec.os-hardening

echo "=== Creating hardening playbook ==="
WORKDIR="/root/hardening-local"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# Local inventory
cat > inventory.yml << 'EOF'
localhost ansible_connection=local
EOF

# Playbook using the correct roles
cat > playbook.yml << 'EOF'
---
- hosts: localhost
  gather_facts: true
  collections:
    - dev_sec.os_hardening
  roles:
    - role: dev_sec.os_hardening.basic
    - role: dev_sec.os_hardening.ssh
    - role: dev_sec.os_hardening.pam
    - role: dev_sec.os_hardening.network
    - role: dev_sec.os_hardening.audit
    - role: dev_sec.os_hardening.packages
EOF

echo "=== Running hardening playbook ==="
ansible-playbook -i inventory.yml playbook.yml --connection=local

echo ""
echo "=== Hardening execution finished ==="
echo "Next steps:"
echo "  1) Reboot: sudo reboot"
echo "  2) Install Lynis: sudo apt install lynis -y"
echo "  3) Run Lynis: sudo lynis audit system"

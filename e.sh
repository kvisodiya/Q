#!/usr/bin/env bash
#===============================================================================
#
#          FILE: enhance.sh
#
#         USAGE: sudo bash enhance.sh
#
#   DESCRIPTION: Enhance Lynis score from 86 to 90+
#                Additional hardening measures
#
#       VERSION: 1.0.0
#
#===============================================================================

set +e
set +u

#===============================================================================
# VARIABLES
#===============================================================================
readonly LOG_FILE="/var/log/enhance_$(date +%Y%m%d_%H%M%S).log"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

TASKS_DONE=0

#===============================================================================
# FUNCTIONS
#===============================================================================
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null
}

print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "INFO")
            echo -e "${BLUE}[*]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[✓]${NC} $message"
            ((TASKS_DONE++))
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[✗]${NC} $message"
            ;;
    esac
    log "$status: $message"
}

print_section() {
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} Run as root: sudo bash $0"
        exit 1
    fi
}

#===============================================================================
# BANNER
#===============================================================================
print_banner() {
    clear
    echo ""
    echo -e "${GREEN}${BOLD}"
    cat << 'EOF'
    ______      __                           ____            _       __ 
   / ____/___  / /_  ____ _____  ________   / __/_  ______  (_)___  / /_
  / __/ / __ \/ __ \/ __ `/ __ \/ ___/ _ \ / /_/ / / / __ \/ / __ \/ __/
 / /___/ / / / / / / /_/ / / / / /__/  __// __/ /_/ / / / / / / / / /_  
/_____/_/ /_/_/ /_/\__,_/_/ /_/\___/\___//_/  \__,_/_/ /_/_/_/ /_/\__/  
                                                                        
EOF
    echo -e "${NC}"
    echo -e "${BOLD}    Lynis Score Enhancement Script${NC}"
    echo -e "${BOLD}    Target: 90+ Score${NC}"
    echo ""
}

#===============================================================================
# 1. ENHANCED KERNEL HARDENING
#===============================================================================
enhance_kernel_hardening() {
    print_section "Enhanced Kernel Hardening"
    
    cat > /etc/sysctl.d/99-enhanced-security.conf << 'EOF'
#===============================================================================
# Enhanced Kernel Security Parameters
#===============================================================================

# IPv4 Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_sack = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

# IPv6 Security
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.router_solicitations = 0
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.all.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.all.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.all.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.max_addresses = 1

# Kernel Security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.panic = 60
kernel.panic_on_oops = 60
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1

# File System Security
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.file-max = 65535

# Memory
vm.mmap_min_addr = 65536
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
vm.swappiness = 10
vm.dirty_ratio = 30
vm.dirty_background_ratio = 5

# Network Performance
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.optmem_max = 25165824
net.core.rmem_default = 31457280
net.core.rmem_max = 67108864
net.core.wmem_default = 31457280
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.ip_local_port_range = 1024 65535
EOF

    sysctl --system >> "$LOG_FILE" 2>&1
    
    print_status "SUCCESS" "Enhanced kernel parameters applied"
}

#===============================================================================
# 2. SECURE MOUNT OPTIONS
#===============================================================================
secure_mount_options() {
    print_section "Securing Mount Options"
    
    # Secure /tmp
    if mountpoint -q /tmp 2>/dev/null; then
        mount -o remount,noexec,nosuid,nodev /tmp >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "/tmp secured with noexec,nosuid,nodev"
    else
        # Create tmpfs for /tmp
        if ! grep -q "^tmpfs /tmp" /etc/fstab; then
            echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=512M 0 0" >> /etc/fstab
            print_status "SUCCESS" "Added secure tmpfs for /tmp"
        fi
    fi
    
    # Secure /var/tmp
    if mountpoint -q /var/tmp 2>/dev/null; then
        mount -o remount,noexec,nosuid,nodev /var/tmp >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "/var/tmp secured"
    fi
    
    # Secure /dev/shm
    if mountpoint -q /dev/shm 2>/dev/null; then
        mount -o remount,noexec,nosuid,nodev /dev/shm >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "/dev/shm secured"
    fi
    
    # Secure /run/shm
    if mountpoint -q /run/shm 2>/dev/null; then
        mount -o remount,noexec,nosuid,nodev /run/shm >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "/run/shm secured"
    fi
    
    # Add to fstab if not present
    if ! grep -q "/dev/shm.*noexec" /etc/fstab 2>/dev/null; then
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
    fi
    
    # Secure /proc
    if ! grep -q "proc.*hidepid" /etc/fstab 2>/dev/null; then
        echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
        mount -o remount,hidepid=2 /proc >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "/proc secured with hidepid=2"
    fi
}

#===============================================================================
# 3. ENHANCED PAM SECURITY
#===============================================================================
enhance_pam_security() {
    print_section "Enhanced PAM Security"
    
    # Configure faillock (replaces pam_tally2)
    cat > /etc/security/faillock.conf << 'EOF'
# Faillock configuration
deny = 5
fail_interval = 900
unlock_time = 600
audit
silent
even_deny_root
root_unlock_time = 900
EOF
    print_status "SUCCESS" "Faillock configured"
    
    # Configure pam_pwquality
    if [[ -f /etc/security/pwquality.conf ]]; then
        cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 2
maxsequence = 3
maxclassrepeat = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
enforce_for_root
EOF
        print_status "SUCCESS" "Password quality enhanced"
    fi
    
    # Configure password hashing rounds
    if [[ -f /etc/login.defs ]]; then
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs 2>/dev/null
        sed -i 's/^SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 10000/' /etc/login.defs 2>/dev/null
        sed -i 's/^SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 100000/' /etc/login.defs 2>/dev/null
        
        if ! grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs; then
            echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
        fi
        if ! grep -q "^SHA_CRYPT_MAX_ROUNDS" /etc/login.defs; then
            echo "SHA_CRYPT_MAX_ROUNDS 100000" >> /etc/login.defs
        fi
        
        print_status "SUCCESS" "Password hashing rounds increased"
    fi
    
    # Restrict su to wheel group
    if [[ -f /etc/pam.d/su ]]; then
        if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
            sed -i '/pam_rootok.so/a auth required pam_wheel.so use_uid group=sudo' /etc/pam.d/su 2>/dev/null
            print_status "SUCCESS" "su restricted to sudo group"
        fi
    fi
    
    # Configure account lockout in common-auth
    if [[ -f /etc/pam.d/common-auth ]]; then
        if ! grep -q "pam_faillock" /etc/pam.d/common-auth; then
            cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup
            cat > /etc/pam.d/common-auth << 'EOF'
auth    required                        pam_faillock.so preauth silent
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    [default=die]                   pam_faillock.so authfail
auth    requisite                       pam_deny.so
auth    required                        pam_faillock.so authsucc
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
EOF
            print_status "SUCCESS" "PAM faillock enabled in common-auth"
        fi
    fi
}

#===============================================================================
# 4. FILE PERMISSIONS HARDENING
#===============================================================================
harden_file_permissions() {
    print_section "Hardening File Permissions"
    
    # Critical files
    chmod 600 /etc/shadow 2>/dev/null && print_status "SUCCESS" "/etc/shadow: 600"
    chmod 600 /etc/gshadow 2>/dev/null && print_status "SUCCESS" "/etc/gshadow: 600"
    chmod 644 /etc/passwd 2>/dev/null && print_status "SUCCESS" "/etc/passwd: 644"
    chmod 644 /etc/group 2>/dev/null && print_status "SUCCESS" "/etc/group: 644"
    chmod 600 /etc/ssh/sshd_config 2>/dev/null && print_status "SUCCESS" "/etc/ssh/sshd_config: 600"
    chmod 700 /root 2>/dev/null && print_status "SUCCESS" "/root: 700"
    chmod 700 /home/* 2>/dev/null && print_status "SUCCESS" "/home/*: 700"
    
    # Boot files
    chmod 600 /boot/grub/grub.cfg 2>/dev/null && print_status "SUCCESS" "/boot/grub/grub.cfg: 600"
    chmod 600 /etc/grub.d/* 2>/dev/null
    chmod 700 /etc/grub.d 2>/dev/null
    
    # Cron directories
    chmod 700 /etc/cron.d 2>/dev/null
    chmod 700 /etc/cron.daily 2>/dev/null
    chmod 700 /etc/cron.hourly 2>/dev/null
    chmod 700 /etc/cron.weekly 2>/dev/null
    chmod 700 /etc/cron.monthly 2>/dev/null
    chmod 600 /etc/crontab 2>/dev/null
    print_status "SUCCESS" "Cron directories secured"
    
    # Log files
    chmod 640 /var/log/auth.log 2>/dev/null
    chmod 640 /var/log/syslog 2>/dev/null
    chmod 640 /var/log/kern.log 2>/dev/null
    chmod 640 /var/log/messages 2>/dev/null
    print_status "SUCCESS" "Log files secured"
    
    # SSH keys
    chmod 700 /etc/ssh 2>/dev/null
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null
    chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
    print_status "SUCCESS" "SSH keys secured"
    
    # Sticky bit on world-writable directories
    find /tmp -type d -exec chmod +t {} \; 2>/dev/null
    find /var/tmp -type d -exec chmod +t {} \; 2>/dev/null
    print_status "SUCCESS" "Sticky bit set on world-writable directories"
    
    # Remove world-writable permissions where not needed
    chmod o-w /etc 2>/dev/null
    chmod o-w /usr 2>/dev/null
    chmod o-w /var 2>/dev/null
}

#===============================================================================
# 5. SHELL TIMEOUT
#===============================================================================
configure_shell_timeout() {
    print_section "Configuring Shell Timeout"
    
    # Set TMOUT
    cat > /etc/profile.d/timeout.sh << 'EOF'
# Automatic logout after 15 minutes of inactivity
readonly TMOUT=900
export TMOUT
EOF
    chmod 644 /etc/profile.d/timeout.sh
    
    # Also set in /etc/bash.bashrc
    if ! grep -q "TMOUT" /etc/bash.bashrc 2>/dev/null; then
        echo "" >> /etc/bash.bashrc
        echo "# Auto logout after 15 minutes" >> /etc/bash.bashrc
        echo "TMOUT=900" >> /etc/bash.bashrc
        echo "readonly TMOUT" >> /etc/bash.bashrc
        echo "export TMOUT" >> /etc/bash.bashrc
    fi
    
    print_status "SUCCESS" "Shell timeout set to 900 seconds"
}

#===============================================================================
# 6. ENHANCED AUDIT RULES
#===============================================================================
enhance_audit_rules() {
    print_section "Enhanced Audit Rules"
    
    cat > /etc/audit/rules.d/99-enhanced.rules << 'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

#---------------------------------------
# Self auditing
#---------------------------------------
-w /var/log/audit/ -p wa -k auditlog
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

#---------------------------------------
# User/Group modifications
#---------------------------------------
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity

#---------------------------------------
# Privileged commands
#---------------------------------------
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

#---------------------------------------
# Sudo configuration
#---------------------------------------
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes

#---------------------------------------
# SSH configuration
#---------------------------------------
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

#---------------------------------------
# PAM configuration
#---------------------------------------
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k pam

#---------------------------------------
# Login/logout events
#---------------------------------------
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

#---------------------------------------
# Session initiation
#---------------------------------------
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/run/utmp -p wa -k session

#---------------------------------------
# Cron configuration
#---------------------------------------
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

#---------------------------------------
# Network configuration
#---------------------------------------
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysctl.conf -p wa -k network
-w /etc/sysctl.d/ -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /etc/hostname -p wa -k network

#---------------------------------------
# System startup
#---------------------------------------
-w /etc/rc.local -p wa -k init
-w /etc/systemd/ -p wa -k systemd
-w /etc/init.d/ -p wa -k init

#---------------------------------------
# Kernel modules
#---------------------------------------
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /etc/modprobe.d/ -p wa -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -S finit_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -S finit_module -k modules

#---------------------------------------
# Time changes
#---------------------------------------
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -S clock_settime -k time
-w /etc/localtime -p wa -k time

#---------------------------------------
# File deletions
#---------------------------------------
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

#---------------------------------------
# Unauthorized access attempts
#---------------------------------------
-a always,exit -F arch=b64 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

#---------------------------------------
# Mount operations
#---------------------------------------
-a always,exit -F arch=b64 -S mount -S umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid>=1000 -F auid!=4294967295 -k mounts

#---------------------------------------
# Make immutable - must be last
#---------------------------------------
-e 2
EOF

    augenrules --load >> "$LOG_FILE" 2>&1
    systemctl restart auditd >> "$LOG_FILE" 2>&1
    
    print_status "SUCCESS" "Enhanced audit rules loaded"
}

#===============================================================================
# 7. DISABLE UNNECESSARY SERVICES
#===============================================================================
disable_unnecessary_services() {
    print_section "Disabling Unnecessary Services"
    
    local services=(
        "avahi-daemon"
        "cups"
        "cups-browsed"
        "isc-dhcp-server"
        "isc-dhcp-server6"
        "slapd"
        "nfs-server"
        "rpcbind"
        "bind9"
        "vsftpd"
        "apache2"
        "nginx"
        "dovecot"
        "smbd"
        "nmbd"
        "snmpd"
        "squid"
        "ypserv"
        "rsh-server"
        "telnet"
        "tftp"
        "xinetd"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            systemctl stop "$service" >> "$LOG_FILE" 2>&1
            systemctl disable "$service" >> "$LOG_FILE" 2>&1
            print_status "SUCCESS" "Disabled: $service"
        fi
    done
    
    print_status "SUCCESS" "Unnecessary services check complete"
}

#===============================================================================
# 8. DISABLE UNNECESSARY KERNEL MODULES
#===============================================================================
disable_kernel_modules() {
    print_section "Disabling Unnecessary Kernel Modules"
    
    cat > /etc/modprobe.d/99-disable-modules.conf << 'EOF'
# Disable uncommon filesystems
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install fat /bin/false
install vfat /bin/false
install cifs /bin/false
install nfs /bin/false
install nfsv3 /bin/false
install nfsv4 /bin/false
install gfs2 /bin/false

# Disable uncommon network protocols
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false

# Disable Bluetooth
install bluetooth /bin/false
install btusb /bin/false

# Disable FireWire
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false

# Disable USB storage (for servers)
install usb-storage /bin/false
install uas /bin/false

# Disable Thunderbolt
install thunderbolt /bin/false

# Disable PCMCIA
install pcmcia /bin/false
install yenta_socket /bin/false

# Disable misc
install vivid /bin/false
EOF

    print_status "SUCCESS" "Kernel modules blacklist created"
}

#===============================================================================
# 9. CONFIGURE BANNERS
#===============================================================================
configure_banners() {
    print_section "Configuring Security Banners"
    
    # /etc/issue (local login)
    cat > /etc/issue << 'EOF'
***************************************************************************
*                          AUTHORIZED ACCESS ONLY                         *
***************************************************************************
* This system is for authorized users only. Unauthorized access is        *
* prohibited and may be subject to legal action. All activity is logged.  *
***************************************************************************

EOF
    
    # /etc/issue.net (remote login)
    cat > /etc/issue.net << 'EOF'
***************************************************************************
*                          AUTHORIZED ACCESS ONLY                         *
***************************************************************************
* This system is for authorized users only. Unauthorized access is        *
* prohibited and may be subject to legal action. All activity is logged   *
* and monitored.                                                          *
***************************************************************************
EOF

    # /etc/motd
    cat > /etc/motd << 'EOF'

    This system is monitored and logged. Unauthorized access is prohibited.

EOF
    
    chmod 644 /etc/issue
    chmod 644 /etc/issue.net
    chmod 644 /etc/motd
    
    print_status "SUCCESS" "Security banners configured"
}

#===============================================================================
# 10. ENHANCED LOGIN.DEFS
#===============================================================================
enhance_login_defs() {
    print_section "Enhancing Login Definitions"
    
    if [[ -f /etc/login.defs ]]; then
        # Password aging
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
        
        # Login settings
        sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs
        sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs
        sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB    yes/' /etc/login.defs
        sed -i 's/^LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB yes/' /etc/login.defs
        sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS   yes/' /etc/login.defs
        sed -i 's/^SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB  yes/' /etc/login.defs
        sed -i 's/^SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB  yes/' /etc/login.defs
        
        # Encryption
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD  SHA512/' /etc/login.defs
        
        # Umask
        sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
        
        # UID/GID
        sed -i 's/^UID_MIN.*/UID_MIN         1000/' /etc/login.defs
        sed -i 's/^GID_MIN.*/GID_MIN         1000/' /etc/login.defs
        
        # Home directory
        sed -i 's/^CREATE_HOME.*/CREATE_HOME     yes/' /etc/login.defs
        sed -i 's/^USERGROUPS_ENAB.*/USERGROUPS_ENAB yes/' /etc/login.defs
        
        # Add if not present
        if ! grep -q "^FAIL_DELAY" /etc/login.defs; then
            echo "FAIL_DELAY 4" >> /etc/login.defs
        fi
        if ! grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs; then
            echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
        fi
        if ! grep -q "^SHA_CRYPT_MAX_ROUNDS" /etc/login.defs; then
            echo "SHA_CRYPT_MAX_ROUNDS 100000" >> /etc/login.defs
        fi
        
        print_status "SUCCESS" "Login definitions enhanced"
    fi
}

#===============================================================================
# 11. SECURE COMPILERS
#===============================================================================
secure_compilers() {
    print_section "Securing Compilers"
    
    # Restrict compiler access to root only
    local compilers=(
        "/usr/bin/gcc"
        "/usr/bin/g++"
        "/usr/bin/cc"
        "/usr/bin/c++"
        "/usr/bin/make"
        "/usr/bin/as"
        "/usr/bin/ld"
    )
    
    for compiler in "${compilers[@]}"; do
        if [[ -f "$compiler" ]]; then
            chmod 700 "$compiler" 2>/dev/null
        fi
    done
    
    print_status "SUCCESS" "Compilers restricted to root"
}

#===============================================================================
# 12. CONFIGURE LOGGING
#===============================================================================
enhance_logging() {
    print_section "Enhancing System Logging"
    
    # Configure rsyslog
    if [[ -f /etc/rsyslog.conf ]]; then
        # Ensure proper permissions
        cat >> /etc/rsyslog.d/99-security.conf << 'EOF'
# Enhanced security logging
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

# Log all auth messages
auth,authpriv.*                 /var/log/auth.log

# Log all sudo attempts
local2.*                        /var/log/sudo.log

# Log kernel messages
kern.*                          /var/log/kern.log
EOF
        
        systemctl restart rsyslog >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "Rsyslog enhanced"
    fi
    
    # Configure logrotate for auth.log
    cat > /etc/logrotate.d/auth << 'EOF'
/var/log/auth.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF
    
    print_status "SUCCESS" "Log rotation configured"
}

#===============================================================================
# 13. USB AUTHORIZATION
#===============================================================================
configure_usb_authorization() {
    print_section "Configuring USB Authorization"
    
    # Disable USB authorization by default
    cat > /etc/udev/rules.d/99-usb-authorization.rules << 'EOF'
# Disable USB devices by default (optional - uncomment if needed)
# ACTION=="add", SUBSYSTEM=="usb", TEST=="authorized_default", ATTR{authorized_default}="0"
EOF
    
    print_status "SUCCESS" "USB authorization rules created"
}

#===============================================================================
# 14. SECURE GRUB
#===============================================================================
secure_grub() {
    print_section "Securing GRUB Bootloader"
    
    # Set permissions
    chmod 600 /boot/grub/grub.cfg 2>/dev/null
    chmod 700 /boot/grub 2>/dev/null
    
    # Disable recovery mode
    if [[ -f /etc/default/grub ]]; then
        if ! grep -q "GRUB_DISABLE_RECOVERY" /etc/default/grub; then
            echo 'GRUB_DISABLE_RECOVERY="true"' >> /etc/default/grub
        fi
        if ! grep -q "GRUB_CMDLINE_LINUX.*audit=1" /etc/default/grub; then
            sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub
        fi
        
        update-grub >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "GRUB secured"
    fi
}

#===============================================================================
# 15. RESTRICT CORE DUMPS
#===============================================================================
restrict_core_dumps() {
    print_section "Restricting Core Dumps"
    
    # /etc/security/limits.conf
    cat >> /etc/security/limits.d/99-coredumps.conf << 'EOF'
*               hard    core            0
*               soft    core            0
root            hard    core            0
root            soft    core            0
EOF

    # Systemd
    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

    # Sysctl
    echo "kernel.core_pattern=|/bin/false" >> /etc/sysctl.d/99-enhanced-security.conf
    
    sysctl -w kernel.core_pattern="|/bin/false" >> "$LOG_FILE" 2>&1
    
    print_status "SUCCESS" "Core dumps fully restricted"
}

#===============================================================================
# 16. INSTALL ADDITIONAL SECURITY TOOLS
#===============================================================================
install_additional_tools() {
    print_section "Installing Additional Security Tools"
    
    export DEBIAN_FRONTEND=noninteractive
    
    local tools=(
        "libpam-tmpdir"
        "apt-listbugs"
        "apt-listchanges"
        "needrestart"
        "debsecan"
        "debsums"
        "checksecurity"
    )
    
    for tool in "${tools[@]}"; do
        if apt-get install -y "$tool" >> "$LOG_FILE" 2>&1; then
            print_status "SUCCESS" "Installed: $tool"
        fi
    done
}

#===============================================================================
# 17. SECURE SSH FURTHER
#===============================================================================
enhance_ssh() {
    print_section "Enhancing SSH Security"
    
    mkdir -p /etc/ssh/sshd_config.d
    
    cat > /etc/ssh/sshd_config.d/99-enhanced.conf << 'EOF'
# Enhanced SSH Hardening
Protocol 2

# Authentication
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 20
PermitRootLogin prohibit-password
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey,password publickey

# Security
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
DisableForwarding yes

# Cryptography
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Timeouts
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Other
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog yes
Banner /etc/issue.net
DebianBanner no

# Limits
MaxStartups 10:30:60
EOF

    # Test and restart
    if sshd -t >> "$LOG_FILE" 2>&1; then
        systemctl restart sshd >> "$LOG_FILE" 2>&1 || systemctl restart ssh >> "$LOG_FILE" 2>&1
        print_status "SUCCESS" "SSH configuration enhanced"
    else
        print_status "ERROR" "SSH config test failed"
        rm -f /etc/ssh/sshd_config.d/99-enhanced.conf
    fi
}

#===============================================================================
# 18. ADDITIONAL QUICK WINS
#===============================================================================
additional_hardening() {
    print_section "Additional Quick Wins"
    
    # Set default umask
    cat > /etc/profile.d/umask.sh << 'EOF'
umask 027
EOF
    chmod 644 /etc/profile.d/umask.sh
    print_status "SUCCESS" "Default umask set to 027"
    
    # Disable IPv6 if not needed
    cat >> /etc/sysctl.d/99-enhanced-security.conf << 'EOF'

# Disable IPv6 (optional - comment if IPv6 is needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    print_status "SUCCESS" "IPv6 disabled"
    
    # Disable Ctrl+Alt+Delete
    systemctl mask ctrl-alt-del.target >> "$LOG_FILE" 2>&1
    print_status "SUCCESS" "Ctrl+Alt+Delete disabled"
    
    # Secure /etc/securetty
    echo "" > /etc/securetty
    print_status "SUCCESS" "Securetty cleared"
    
    # Apply sysctl changes
    sysctl --system >> "$LOG_FILE" 2>&1
}

#===============================================================================
# VERIFY AND RUN LYNIS
#===============================================================================
run_lynis() {
    print_section "Running Lynis Audit"
    
    if ! command -v lynis >/dev/null 2>&1; then
        print_status "ERROR" "Lynis not found"
        return 1
    fi
    
    print_status "INFO" "Starting Lynis audit..."
    echo ""
    
    lynis audit system --quick 2>&1 | tee /tmp/lynis_enhance.txt
    
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}           FINAL RESULTS${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local score
    score=$(grep -i "hardening index" /tmp/lynis_enhance.txt 2>/dev/null | grep -oE "[0-9]+" | head -1)
    
    if [[ -n "$score" ]]; then
        echo -e "  🛡️  ${BOLD}HARDENING SCORE: ${GREEN}${score}/100${NC}"
        echo ""
        
        if [[ $score -ge 90 ]]; then
            echo -e "  ${GREEN}✅ TARGET ACHIEVED! Score is 90+${NC}"
        elif [[ $score -ge 85 ]]; then
            echo -e "  ${YELLOW}⚠️  Close! Score is $score - Almost there!${NC}"
        else
            echo -e "  ${YELLOW}⚠️  Score is $score${NC}"
        fi
    else
        if [[ -f /var/log/lynis-report.dat ]]; then
            score=$(grep "hardening_index=" /var/log/lynis-report.dat | cut -d= -f2)
            echo -e "  🛡️  ${BOLD}HARDENING SCORE: ${GREEN}${score}/100${NC}"
        fi
    fi
    
    echo ""
    rm -f /tmp/lynis_enhance.txt
}

#===============================================================================
# MAIN
#===============================================================================
main() {
    print_banner
    
    check_root
    
    echo "" > "$LOG_FILE"
    
    # Run all enhancements
    enhance_kernel_hardening
    secure_mount_options
    enhance_pam_security
    harden_file_permissions
    configure_shell_timeout
    enhance_audit_rules
    disable_unnecessary_services
    disable_kernel_modules
    configure_banners
    enhance_login_defs
    secure_compilers
    enhance_logging
    configure_usb_authorization
    secure_grub
    restrict_core_dumps
    install_additional_tools
    enhance_ssh
    additional_hardening
    
    # Run Lynis
    run_lynis
    
    # Summary
    print_section "ENHANCEMENT COMPLETE!"
    
    echo ""
    echo -e "${GREEN}${BOLD}✓ Enhancement completed!${NC}"
    echo ""
    echo -e "${BOLD}Tasks Completed: ${GREEN}$TASKS_DONE${NC}"
    echo ""
    echo -e "${BOLD}Log File:${NC} $LOG_FILE"
    echo ""
    echo -e "${YELLOW}${BOLD}IMPORTANT:${NC}"
    echo -e "  1. Test SSH in a new session before closing"
    echo -e "  2. Reboot recommended: sudo reboot"
    echo ""
}

# Run
main "$@"

exit 0

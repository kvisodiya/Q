Rn 89 make 90+.sh  I’m one vps allow port 22 and 2222

🛑 Critical Issues (Different/Weak/No)
These items indicate a failure to meet the expected security profile or a lack of specific protection hardware/software.
Kernel Hardening (Non-Compliant)
• dev.tty.ldisc_autoload
• fs.protected_fifos
• kernel.core_uses_pid
• kernel.modules_disabled
• kernel.sysrq
• kernel.unprivileged_bpf_disabled
• net.core.bpf_jit_harden
• net.ipv4.conf.all.log_martians
• net.ipv4.conf.default.log_martians
Cryptography & Hardware
• HW RNG & rngd: NOT FOUND (No)
• SW prng: NOT FOUND (No)
• MOR variable: WEAK
• UEFI Secure Boot: DISABLED
• GRUB2 password: NONE
Banners & Identification
• /etc/issue contents: WEAK (Contains system information that leaks OS details to unauthorized users).
⚠️ Configuration Suggestions
These items are functional but are not optimized according to best security practices.
File Permissions & System Files
• Permissions: /etc/crontab, /etc/ssh/sshd_config
• Directories: /etc/cron.d, /etc/cron.daily, /etc/cron.hourly, /etc/cron.weekly, /etc/cron.monthly
• Umask: NONE (Not explicitly set in /etc/profile or /etc/bash.bashrc)
SSH Configuration
• MaxSessions: SUGGESTION
• Port: SUGGESTION (Running on default port 22)
• TCPKeepAlive: SUGGESTION
File Systems (Mount Points)
• /home, /tmp, /var: SUGGESTION (Missing nodev, nosuid, or noexec flags)
• /proc mount: SUGGESTION (Needs hardening like hidepid)
• Swap partition: NONE
🔍 Missing Software/Services
The following tools or frameworks were NOT FOUND or DISABLED, reducing your security oversight:
• Accounting: sysstat (DISABLED)
• Logging: Remote logging (NOT ENABLED)
• Firewall: Unused rules (FOUND - needs cleanup)
• Intrusion Detection: Fail2ban jails (Minimal coverage)
• MAC Frameworks: SELinux, TOMOYO, and grsecurity are NOT FOUND.
• Network: ARP monitoring software NOT FOUND.
• Session Timeout: NONE (The TMOUT environment variable is not set)




#!/usr/bin/env bash
# SecurityLab Toolkit - Linux audit and opt-in hardening
set -u
umask 077
OUT="${HOME}/securitylab-reports"
mkdir -p "$OUT" || exit 1
has(){ command -v "$1" >/dev/null 2>&1; }
section(){ printf '\n=== %s ===\n' "$1"; }
audit(){
 section 'System'; uname -a; cat /etc/os-release 2>/dev/null | head -8
 section 'Identity'; id; getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1 " uid=" $3 " shell=" $7}'
 section 'Privilege'; getent group sudo wheel 2>/dev/null || true
 section 'Firewall'; if has ufw; then sudo -n ufw status verbose 2>/dev/null || ufw status 2>&1 || true; elif has firewall-cmd; then firewall-cmd --state 2>&1; elif has nft; then sudo -n nft list ruleset 2>&1 || true; else echo 'No supported firewall command found'; fi
 section 'Listening ports'; if has ss; then ss -tuln; else echo 'ss unavailable'; fi
 section 'Failed services'; if has systemctl; then systemctl --failed --no-pager 2>&1 || true; fi
 section 'Updates'; if has apt; then apt list --upgradable 2>/dev/null | head -35; elif has dnf; then dnf check-update 2>&1 | head -35; fi
 section 'SSH settings'; if [[ -f /etc/ssh/sshd_config ]]; then grep -E '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config || true; fi
}
confirm(){ read -r -p "$1 [type YES]: " answer || return 1; [[ "$answer" == YES ]]; }
firewall(){
 if ! has ufw; then echo 'Automatic action supports UFW only; no changes made.'; return; fi
 echo 'Enabling UFW can disconnect remote sessions. Review SSH rules first.'
 confirm 'Enable UFW now?' || { echo 'Cancelled'; return; }
 sudo ufw enable
}
report(){ local path="$OUT/audit-$(date +%Y%m%d-%H%M%S).txt"; audit > "$path" 2>&1; printf 'Report saved: %s\n' "$path"; }
while true; do
 printf '\nSecurityLab Linux | 1 Audit | 2 Save report | 3 Enable UFW (confirm) | 4 Exit\n'
 read -r -p 'Select: ' choice || break
 case "$choice" in 1) audit;; 2) report;; 3) firewall;; 4) break;; *) echo 'Invalid option';; esac
done

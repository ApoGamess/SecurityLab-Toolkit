#!/usr/bin/env bash
# SecurityLab Toolkit — Linux Mint 21 auditing (read-only)
set -u
umask 077
audit(){
 printf '\n=== OS ===\n'; cat /etc/os-release 2>/dev/null | head -8
 printf '\n=== Users ===\n'; getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1, $3, $7}'
 printf '\n=== Sudo group ===\n'; getent group sudo || true
 printf '\n=== Firewall ===\n'; if command -v ufw >/dev/null 2>&1; then ufw status verbose 2>&1 || true; else echo 'UFW not installed'; fi
 printf '\n=== Listening ports ===\n'; if command -v ss >/dev/null 2>&1; then ss -tuln; fi
 printf '\n=== Failed services ===\n'; if command -v systemctl >/dev/null 2>&1; then systemctl --failed --no-pager 2>&1 || true; fi
 printf '\n=== Upgradable packages ===\n'; if command -v apt >/dev/null 2>&1; then apt list --upgradable 2>/dev/null | head -35; fi
}
report(){ local dir="$HOME/SecurityLab-Reports" path; mkdir -p "$dir" || return; path="$dir/mint21-$(date +%Y%m%d-%H%M%S).txt"; audit >"$path" 2>&1; printf 'Saved: %s\n' "$path"; }
while true; do
 printf '\nLinux Mint 21 | 1 Audit | 2 Save report | 3 Exit\n'
 read -r -p 'Select: ' option || break
 case "$option" in 1) audit;; 2) report;; 3) break;; *) echo 'Invalid option';; esac
done

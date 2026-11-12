#!/usr/bin/env python3
"""CyberPatriot Debian 12 training: configurable, conservative security audit.
No changes unless --apply is supplied. No deletion of users or home folders.
"""
import argparse, json, os, pwd, grp, shutil, subprocess, getpass
from pathlib import Path

DEFAULT = {
  "authorized_admins": [],
  "authorized_users": [],
  "required_groups": {"queensguard": ["bselmy"]},
  "critical_services": ["ssh"],
  "expected_os": "12",
  "password_changes": [],
  "manage_ufw": True
}

def run(cmd, input_text=None):
    p = subprocess.run(cmd, input=input_text, text=True, capture_output=True)
    return p.returncode, (p.stdout + p.stderr).strip()

def report(status, message):
    print(f'[{status}] {message}')

def main():
    ap=argparse.ArgumentParser(description='Debian 12 CyberPatriot training audit and optional remediation')
    ap.add_argument('--config', default='cp_config.json')
    ap.add_argument('--apply', action='store_true', help='Apply selected safe changes')
    ap.add_argument('--set-password', metavar='USERNAME', help='Prompt securely for a password; requires --apply')
    args=ap.parse_args()
    path=Path(args.config)
    if not path.exists():
        path.write_text(json.dumps(DEFAULT, indent=2)+'\n')
        report('INFO', f'Created {path}; edit it and run again')
        return
    cfg=json.loads(path.read_text())
    if args.apply and os.geteuid()!=0:
        raise SystemExit('Run with sudo for --apply')
    osrel=Path('/etc/os-release').read_text() if Path('/etc/os-release').exists() else ''
    report('OK' if 'VERSION_ID="12"' in osrel else 'CHECK', 'Debian 12 version')
    users={u.pw_name for u in pwd.getpwall()}
    admins=set(cfg.get('authorized_admins', []))
    authorized=admins | set(cfg.get('authorized_users', []))
    for user in sorted(authorized):
        if user in users:
            report('OK', f'Authorized account present: {user}')
        else:
            report('MISSING', f'Authorized account missing: {user}')
            if args.apply:
                code,out=run(['useradd','-m','-s','/bin/bash',user])
                report('CHANGED' if code==0 else 'ERROR', f'Create {user}: {out}')
    for user in sorted(admins):
        if user in users or args.apply:
            code,out=run(['id','-nG',user])
            if code==0 and 'sudo' in out.split():
                report('OK', f'{user} belongs to sudo')
            else:
                report('CHECK', f'{user} needs sudo membership')
                if args.apply:
                    code,out=run(['usermod','-aG','sudo',user]);report('CHANGED' if code==0 else 'ERROR',out or user)
    for group,members in cfg.get('required_groups',{}).items():
        if group not in {g.gr_name for g in grp.getgrall()}:
            report('CHECK',f'Group missing: {group}')
            if args.apply:
                code,out=run(['groupadd',group]);report('CHANGED' if code==0 else 'ERROR',out or group)
        for user in members:
            if user not in users:
                report('CHECK',f'Group member {user} does not exist; not creating automatically')
                continue
            code,out=run(['id','-nG',user])
            if code==0 and group in out.split():
                report('OK',f'{user} in {group}')
            else:
                report('CHECK',f'{user} should be in {group}')
                if args.apply:
                    code,out=run(['usermod','-aG',group,user]);report('CHANGED' if code==0 else 'ERROR',out or user)
    for service in cfg.get('critical_services',[]):
        code,out=run(['systemctl','is-active',service])
        report('OK' if code==0 else 'CHECK',f'Service {service}: {out}')
        if code!=0 and args.apply:
            code,out=run(['systemctl','enable','--now',service]);report('CHANGED' if code==0 else 'ERROR',out or service)
    for pkg in ['chromium','openssh-server','ufw']:
        code,out=run(['dpkg-query','-W','-f=${Status}',pkg])
        report('OK' if code==0 and 'install ok installed' in out else 'CHECK',f'Package {pkg}: {out}')
    if cfg.get('manage_ufw',False):
        if shutil.which('ufw'):
            code,out=run(['ufw','status'])
            report('INFO',f'UFW: {out}')
            if args.apply:
                # Only allow SSH; enabling firewall is deliberately left manual.
                code,out=run(['ufw','allow','OpenSSH'])
                if code!=0: code,out=run(['ufw','allow','22/tcp'])
                report('CHANGED' if code==0 else 'ERROR',f'Allow SSH: {out}')
                report('INFO','Review other necessary ports, then manually run sudo ufw enable')
        else: report('CHECK','ufw is not installed')
    if args.set_password:
        if not args.apply: raise SystemExit('--set-password requires --apply')
        user=args.set_password
        if user not in {u.pw_name for u in pwd.getpwall()}:
            raise SystemExit('Account does not exist')
        first=getpass.getpass(f'New password for {user}: ')
        second=getpass.getpass('Repeat password: ')
        if not first or first!=second: raise SystemExit('Passwords do not match')
        code,out=run(['chpasswd'],f'{user}:{first}\n')
        report('CHANGED' if code==0 else 'ERROR',f'Password for {user}: {out or "updated"}')
    report('INFO','No users, home directories, CCS services, time settings, or autologin were removed/modified')

if __name__=='__main__': main()
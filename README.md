# SecurityLab Toolkit

Educational security auditing tools for Windows and Linux. Each operating system has its own script.

> Not affiliated with or endorsed by CyberPatriot or the Air & Space Forces Association. Review competition rules before using automation.

## Choose your operating system

| System | Script | Command |
| --- | --- | --- |
| Debian 12 | `scripts/cyberpatriot_debian12.py` | `python3 scripts/cyberpatriot_debian12.py --config configs/cp_config.json` |
| Windows 11 | `scripts/SecurityLab-Windows11.ps1` | `powershell -NoProfile -File .\\scripts\\SecurityLab-Windows11.ps1` |
| Windows Server | `scripts/SecurityLab-WindowsServer.ps1` | `powershell -NoProfile -File .\\scripts\\SecurityLab-WindowsServer.ps1` |
| General Windows | `scripts/SecurityLab-Windows.ps1` | `powershell -NoProfile -File .\\scripts\\SecurityLab-Windows.ps1` |
| Linux Mint 21 | `scripts/securitylab-linux-mint21.sh` | `bash scripts/securitylab-linux-mint21.sh` |
| Linux Server | `scripts/securitylab-linux-server.sh` | `bash scripts/securitylab-linux-server.sh` |
| General Linux | `scripts/securitylab-linux.sh` | `bash scripts/securitylab-linux.sh` |

Commands assume your terminal is open at the repository root.

## Installation

Download the repository ZIP from GitHub and extract it, or clone it:

```bash
git clone https://github.com/ApoGamess/SecurityLab-Toolkit.git
cd SecurityLab-Toolkit
```

## Linux features

- OS and account inventory
- Privileged-group inspection
- Firewall status
- Listening ports
- Failed services and available updates
- Local timestamped audit reports
- General Linux script: SSH configuration inspection and optional UFW enablement with explicit confirmation

Linux Mint 21 and Linux Server scripts are currently **read-only**. They do not automatically fix security findings. The general Linux script has a separately confirmed UFW enablement action.

## Windows features

The Windows scripts are separate variants. Review each script before running it; features may differ by variant.

## Safety

- Read the image instructions and preserve required users, services and access.
- Firewall changes may disconnect remote access. Review allowed ports first.
- Reports can contain usernames, IP addresses and system configuration details. Do not publish reports without reviewing them.
- Use only on systems you own or are authorized to administer.
- No automatic forensic answers or competition score guarantees.
- Full runtime validation on each operating system has **not** been completed.

## License

MIT — see [LICENSE](LICENSE).


## Windows 11 — running the audit

Open **Windows PowerShell as Administrator** in the repository directory:

```powershell
powershell -NoProfile -File .\scripts\SecurityLab-Windows11.ps1
```

This is the existing Windows 11 audit script in this repository. Inspect its source and results before making any manual changes. It is not the separately mentioned `CyberPatriot_Auditor_v8.ps1` version, which has not been located or uploaded here.

## Debian 12 — configurable audit and remediation

Keep `scripts/cyberpatriot_debian12.py` and `configs/cp_config.json` from this repository. Edit the JSON file before applying changes: set `authorized_admins`, `authorized_users`, `required_groups`, and `critical_services` according to the image README. Do not put passwords into the JSON file or GitHub.

Read-only audit:

```bash
python3 scripts/cyberpatriot_debian12.py --config configs/cp_config.json
```

Review findings and take a VM snapshot before changes. To apply supported changes:

```bash
sudo python3 scripts/cyberpatriot_debian12.py --config configs/cp_config.json --apply
```

To securely prompt for a particular user's new password:

```bash
sudo python3 scripts/cyberpatriot_debian12.py --config configs/cp_config.json --apply --set-password USERNAME
```

Replace `USERNAME` with the account name. Avoid changing the auto-login user's password unless authorized and necessary. The Debian script is intentionally conservative: it does not remove users or home directories, guarantee points, or automatically solve forensic questions. Preserve the CCS client, required SSH service, and the system clock/timezone as directed by the competition README.

**Public repository warning:** Never commit real account passwords, secrets, forensic answers, or sensitive scoring reports.

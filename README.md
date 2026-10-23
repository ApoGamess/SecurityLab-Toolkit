# SecurityLab Toolkit

**Cross-platform security auditing and opt-in hardening tools for Windows and Linux.**

SecurityLab Toolkit is an educational, administrator-friendly command-line toolkit for inspecting operating-system security posture, reviewing local accounts and privilege assignments, examining firewall configuration, identifying listening network ports, and exporting diagnostic reports.

## Features

| Capability | Windows | Linux |
|---|---|---|
| System inventory | Yes | Yes |
| Local user review | Yes | Yes |
| Privileged group review | Yes | Yes |
| Firewall status | Yes | Yes |
| Listening ports | Yes | Yes |
| Service review | Yes | Yes |
| Updates / protection review | Defender status | APT/DNF updates |
| Timestamped reports | Yes | Yes |
| Confirmed firewall enablement | Yes | UFW only |

## Quick start

**Windows (PowerShell 5.1 or newer):**

```powershell
powershell -NoProfile -File .\scripts\SecurityLab-Windows.ps1
```

**Linux (Bash):**

```bash
bash scripts/securitylab-linux.sh
```

## Safety and scope

- Audit and report actions are read-only. The firewall option requires typing `YES`.
- Firewall changes can disconnect remote sessions. Confirm remote access rules before proceeding.
- Use only on systems you own or administer with authorization.
- Review all commands before executing with elevated privileges.
- Reports can include usernames and IP addresses; review before sharing.
- No score manipulation, automatic forensic answers, credential extraction, or destructive user removal.
- **Not affiliated with or endorsed by CyberPatriot, AFA, Microsoft, or Linux distributors.** Competition participants must independently verify current event rules before using any tooling.
- Linux syntax was checked; full runtime testing on each supported operating system and Windows remains pending.

## Files

- `scripts/SecurityLab-Windows.ps1` — Windows 11 and compatible Windows Server auditing
- `scripts/securitylab-linux.sh` — Debian/Ubuntu/Mint and selected other Linux distributions

## Roadmap

- Structured JSON report output
- Configuration profiles for different OS editions
- Automated CI linting and platform test matrices
- Granular remediation previews and rollback documentation

## License

MIT. See [LICENSE](LICENSE).

# VPS Checker

AI-powered agent that audits Linux VPS servers for security vulnerabilities, misconfigurations, and active attacks.

## Features

- Read-only security audit (no changes made to the system)
- SSH hardening verification
- Firewall configuration analysis
- Fail2ban status and configuration checks
- Kernel security parameter validation
- File permission audits
- Compromise indicator detection
- Attack metrics collection

## Installation

```bash
cd agents/vps-checker
pip install -e .
```

## Usage

### Via orchagent CLI

```bash
orchagent run vps-checker
```

### With options

```bash
# Skip attack metrics for faster scan
orchagent run vps-checker --input '{"skip_attack_metrics": true}'

# Full scan (default)
orchagent run vps-checker --input '{"dry_run": true}'
```

## Security Checks

| Category | Checks |
|----------|--------|
| **SSH** | Root login, password auth, port, key-only auth |
| **Firewall** | UFW/iptables status, open ports, default policies |
| **Fail2ban** | Service status, jail configuration, ban counts |
| **Kernel** | ASLR, exec-shield, SUID dumpable, ptrace scope |
| **Filesystem** | World-writable files, SUID binaries, tmp permissions |
| **Users** | Passwordless accounts, shell access, sudo config |
| **Services** | Running services, listening ports, auto-start |
| **Compromise** | Suspicious processes, cron jobs, SSH keys, rootkits |

## Output

The agent produces a security report with:

- Overall security score (0-100)
- Categorized findings by severity (critical, high, medium, low)
- Specific recommendations for remediation
- Optional handoff to vps-fixer agent for automated fixes

## Severity Levels

- **critical**: Immediate action required (active compromise, root exposed)
- **high**: Should be fixed soon (weak SSH config, no firewall)
- **medium**: Review recommended (missing fail2ban, permissive sudo)
- **low**: Informational (minor hardening improvements)

## Development

### Run tests

```bash
pytest tests/ -v
```

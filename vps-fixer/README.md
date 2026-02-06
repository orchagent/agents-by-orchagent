# VPS Fixer

Inspired by [@brankopetric00](https://x.com/brankopetric00/status/2017283246254436501) on VPS security hardening best practices.

AI-powered agent that applies security hardening fixes to Linux VPS servers.

## Features

- Installs and configures fail2ban for intrusion prevention
- Sets up UFW firewall with secure defaults
- Hardens SSH configuration (disables password auth, root login)
- Configures automatic security updates
- Dry-run mode for previewing changes
- Requires explicit confirmation before applying changes

## Installation

```bash
cd agents/vps-fixer
pip install -e .
```

## Usage

### Via orchagent CLI

```bash
# Preview all available fixes (dry-run mode)
orchagent run vps-fixer --input '{"fixes": ["fail2ban", "firewall", "ssh_password_auth", "ssh_root_login", "auto_updates"]}'

# Preview specific fixes
orchagent run vps-fixer --input '{"fixes": ["fail2ban", "firewall"]}'

# Apply fixes (requires confirm: true)
orchagent run vps-fixer --input '{"fixes": ["fail2ban", "firewall"], "dry_run": false, "confirm": true}'
```

## Available Fixes

| Fix | Description |
|-----|-------------|
| **fail2ban** | Installs fail2ban, configures SSH jail with aggressive ban settings |
| **firewall** | Installs UFW, enables with default deny incoming, allows SSH |
| **ssh_password_auth** | Disables password authentication in SSH (key-only access) |
| **ssh_root_login** | Disables direct root login via SSH |
| **auto_updates** | Configures unattended-upgrades for automatic security patches |

## Safety Features

1. **Dry-run by default**: All fixes are previewed without applying changes
2. **Explicit confirmation**: Must set `confirm: true` to apply any changes
3. **Backup before modify**: Original config files are backed up before changes
4. **Service validation**: Verifies services are running after configuration

## Output

The agent produces a fix report with:

- List of fixes attempted
- Status of each fix (success, failed, skipped)
- Any errors encountered
- Recommendations for manual intervention if needed

## Integration with vps-checker

This agent is designed to work with the vps-checker agent:

1. Run vps-checker to audit your server
2. Review the findings and recommendations
3. Use vps-fixer to apply recommended fixes

```bash
# First, audit the server
orchagent run vps-checker

# Then, apply recommended fixes
orchagent run vps-fixer --input '{"fixes": ["fail2ban", "firewall"], "dry_run": false, "confirm": true}'
```

## Development

### Run tests

```bash
pytest tests/ -v
```

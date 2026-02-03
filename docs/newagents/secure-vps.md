# Agent Idea: secure-vps

**Status:** Idea (Priority: MID)
**Added:** 2026-01-31
**Source:** Real-world VPS hardening session on Joe's servers

---

## Overview

A VPS security hardening agent that audits Linux servers for common vulnerabilities and optionally auto-fixes them. Takes an SSH connection and returns a security report with actionable fixes.

---

## The Problem

Within 60 seconds of spinning up a fresh VPS, someone is already trying to break in. Not paranoia—data.

**Real example from Joe's VPS (Jan 2026):**
- Gitea VPS had **347,021 failed SSH login attempts** over 19 days
- **No fail2ban installed** — completely unprotected from brute force
- **No firewall (UFW)** — all ports potentially exposed
- Attackers trying usernames: root, admin, ubuntu, docker, test, ftp, git, etc.
- Multiple IPs attacking simultaneously, 24/7

Bots scan the entire internet constantly looking for:
- Default credentials
- Unpatched software
- Exposed databases
- Misconfigured services

**Most servers have the same problems:**
- Root login enabled with password auth
- SSH on port 22 with no rate limiting
- No firewall configured
- Updates not applied in months
- Services running that nobody remembers installing
- No backups (or backups never tested)

---

## What the Agent Checks

### Critical (Auto-fixable)

| Check | Bad | Good | Auto-fix |
|-------|-----|------|----------|
| fail2ban | Not installed or inactive | Active, banning attackers | `apt install fail2ban && systemctl enable fail2ban` |
| UFW Firewall | Not installed or inactive | Active, only needed ports open | `apt install ufw && ufw enable` |
| Password auth | Enabled | Disabled (key-only) | Edit `/etc/ssh/sshd_config.d/hardening.conf` |
| Root login | With password | Key-only (`without-password`) | Edit sshd_config |

### Important (Report only)

| Check | What to look for |
|-------|------------------|
| Pending updates | `apt list --upgradable` |
| Auto-updates | Is `unattended-upgrades` enabled? |
| Running services | Any unexpected services? |
| Open ports | `ss -tlnp` — what's exposed? |
| Failed login attempts | `lastb` count and recent attempts |
| Successful logins | `last` — any unexpected IPs? |
| SSH keys | Only expected keys in `authorized_keys`? |
| Users with shells | Any unexpected users in `/etc/passwd`? |
| Cron jobs | Any suspicious scheduled tasks? |
| SUID binaries | Any unusual setuid files? |
| Recent file changes | Any unexpected modifications in `/etc`? |

### Breach Detection

| Check | Indicator |
|-------|-----------|
| Unknown SSH keys | Keys in `authorized_keys` you don't recognize |
| Suspicious users | New users with login shells |
| Unexpected logins | `last` showing unknown IPs |
| Rogue processes | Unknown processes running as root |
| Malware indicators | Crypto miners, reverse shells, suspicious cron |

---

## Input

```json
{
  "host": "95.216.158.197",
  "user": "root",
  "auth": "ssh_key",  // or "password" (not recommended)
  "ssh_key_path": "~/.ssh/id_ed25519",  // optional, uses default
  "mode": "audit",  // or "fix" to auto-apply fixes
  "checks": ["all"]  // or specific: ["firewall", "fail2ban", "ssh"]
}
```

Alternative: User provides SSH access via Tailscale, or agent runs locally on the VPS.

---

## Output

```json
{
  "host": "95.216.158.197",
  "scan_time": "2026-01-31T08:30:00Z",
  "os": "Ubuntu 24.04.3 LTS",
  "uptime": "19 days",

  "security_score": 35,
  "max_score": 100,

  "critical_issues": [
    {
      "check": "fail2ban",
      "status": "NOT_INSTALLED",
      "severity": "critical",
      "message": "No brute force protection - 347,021 failed login attempts detected",
      "fix_command": "apt install fail2ban -y && systemctl enable fail2ban --now",
      "auto_fixable": true
    },
    {
      "check": "firewall",
      "status": "NOT_INSTALLED",
      "severity": "critical",
      "message": "No firewall - all ports potentially exposed",
      "fix_command": "apt install ufw -y && ufw default deny incoming && ufw allow 22/tcp && ufw enable",
      "auto_fixable": true
    }
  ],

  "warnings": [
    {
      "check": "password_auth",
      "status": "ENABLED",
      "severity": "high",
      "message": "Password authentication enabled (root is key-only but other users may use passwords)",
      "fix_command": "echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/hardening.conf && systemctl restart ssh",
      "auto_fixable": true
    }
  ],

  "passed": [
    {
      "check": "root_login",
      "status": "KEY_ONLY",
      "message": "Root login requires SSH key (permitrootlogin without-password)"
    },
    {
      "check": "auto_updates",
      "status": "ENABLED",
      "message": "unattended-upgrades is active"
    }
  ],

  "attack_summary": {
    "failed_logins_total": 347021,
    "failed_logins_24h": 1842,
    "unique_attacker_ips": 2341,
    "top_usernames_tried": ["root", "admin", "ubuntu", "test", "oracle"],
    "currently_banned_ips": 0
  },

  "breach_indicators": {
    "found": false,
    "checks_performed": [
      "Unknown SSH keys: 0 found",
      "Suspicious users: 0 found",
      "Unexpected logins: 0 found",
      "Rogue processes: 0 found"
    ]
  },

  "recommendations": [
    "CRITICAL: Install fail2ban immediately to stop brute force attacks",
    "CRITICAL: Enable UFW firewall to block unnecessary ports",
    "HIGH: Disable password authentication entirely",
    "MEDIUM: Consider changing SSH port from 22 to reduce noise",
    "LOW: Set up automated backups"
  ],

  "fixes_applied": []  // Populated if mode="fix"
}
```

---

## Technical Implementation

### Authentication Options

1. **SSH Key** (Recommended)
   - User provides path to private key
   - Agent uses key to connect
   - Most secure, standard approach

2. **SSH Agent Forwarding**
   - Agent inherits user's SSH agent
   - Works if running locally

3. **Tailscale SSH**
   - If both have Tailscale, use Tailscale SSH
   - No key management needed

### Execution Environment

**Option A: Run remotely via SSH**
- Agent SSHs into target server
- Runs diagnostic commands
- Returns results
- Pro: No installation on target
- Con: Needs SSH access

**Option B: Run locally on VPS**
- User installs/runs agent on VPS
- Agent checks local system
- Pro: No remote access needed
- Con: Requires installation

**Option C: E2B Sandbox + SSH**
- Agent runs in E2B sandbox
- SSHs out to target server
- Pro: Sandboxed execution
- Con: Needs outbound SSH from E2B

### Commands Used

```bash
# System info
cat /etc/os-release | head -3
uptime

# SSH config
sshd -T | grep -iE 'passwordauth|permitroot|pubkey'
cat /etc/ssh/sshd_config.d/*.conf

# Firewall
ufw status verbose

# fail2ban
systemctl is-active fail2ban
fail2ban-client status sshd

# Attack metrics
lastb | wc -l  # Total failed logins
last -50       # Recent successful logins

# Services
systemctl list-units --type=service --state=running

# Open ports
ss -tlnp | grep LISTEN

# Users
grep -E '/bin/(ba)?sh' /etc/passwd

# SSH keys
cat ~/.ssh/authorized_keys

# Updates
apt list --upgradable
systemctl is-enabled unattended-upgrades

# Breach detection
find /etc -mtime -7 -type f  # Recently modified configs
ps aux | grep -v '\['        # Running processes
crontab -l                   # Scheduled tasks
```

---

## Hardening Playbook (What We Did)

This is the exact sequence used to harden Joe's VPS servers:

### 1. Install fail2ban
```bash
apt-get update && apt-get install -y fail2ban
systemctl enable fail2ban --now

# Configure jail
cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

systemctl restart fail2ban
```

### 2. Install and configure UFW
```bash
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
# Add other ports as needed:
# ufw allow 3000/tcp comment 'Gitea'
# ufw allow 443/tcp comment 'HTTPS'
echo 'y' | ufw enable
```

### 3. Disable password authentication
```bash
echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/hardening.conf
systemctl restart ssh
```

### 4. Verify
```bash
# Check fail2ban is banning attackers
fail2ban-client status sshd

# Check firewall is active
ufw status

# Check password auth is disabled
sshd -T | grep passwordauth
```

---

## Results from Joe's Servers

### Before Hardening

| Metric | Clawdbot VPS | Gitea VPS |
|--------|--------------|-----------|
| Failed logins | 3,903 | **347,021** |
| fail2ban | Active (good) | **NOT INSTALLED** |
| UFW | Not installed | Not installed |
| Password auth | Enabled | Enabled |

### After Hardening

| Metric | Clawdbot VPS | Gitea VPS |
|--------|--------------|-----------|
| fail2ban | Active, 158 IPs banned | Active, 3 IPs banned immediately |
| UFW | Active, SSH only | Active, SSH + Gitea only |
| Password auth | Disabled | Disabled |

**Key insight:** The Gitea VPS had 347k attack attempts with zero protection. fail2ban was installed and within minutes had already banned 3 attacking IPs.

---

## Remaining Items Not Covered

These weren't auto-fixed but were noted:

1. **Backups** — Neither VPS had backups configured
2. **Non-root user** — Both servers accessed as root directly
3. **SSH port change** — Both still on port 22 (optional, reduces noise)
4. **Intrusion detection** — No AIDE/Tripwire installed

---

## Differentiation

### vs. Manual hardening guides
- **Automated** — One command vs. reading a 20-step guide
- **Continuous** — Can re-run to verify, not just one-time
- **Actionable** — Gives exact commands, not just advice

### vs. Lynis/OpenSCAP
- **Simpler** — Focused on the 80/20 (top issues that matter)
- **Auto-fix** — Optional automatic remediation
- **Remote** — Works over SSH, no agent installation

### vs. Cloud provider security tools
- **Provider-agnostic** — Works on any VPS (Hetzner, DigitalOcean, Linode, AWS, etc.)
- **No vendor lock-in** — Open, portable

---

## Future Enhancements

1. **Scheduled scans** — Run weekly, alert on new issues
2. **Multi-server** — Scan fleet of servers at once
3. **Compliance modes** — CIS benchmarks, PCI-DSS basics
4. **Custom rules** — User-defined checks
5. **Backup verification** — Check if backups exist and are recent
6. **Container security** — Audit Docker/Podman configurations

---

## Marketing Angle

> "Your VPS is being attacked right now. Find out how bad it is in 60 seconds."

- Hook: Fear + curiosity (how many attacks am I getting?)
- Proof: Show real numbers (347k attacks on an unprotected server)
- Solution: One-click hardening
- Shareability: "I just blocked 347,000 attacks on my server"

---

## Resources

- Original post that inspired this: [VPS Security Hardening Guide]
- Joe's clawdbot security notes: `joe-personal/clawd-bot.md`
- Hetzner VPS (cheap, good for testing): hetzner.com
- fail2ban docs: fail2ban.org
- UFW guide: ubuntu.com/server/docs/security-firewall

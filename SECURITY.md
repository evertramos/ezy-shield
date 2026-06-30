# Security Policy

EzyShield is a security tool, so we take vulnerabilities seriously.

## Reporting a vulnerability
Please do NOT open a public issue. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") or email the maintainer (see profile).
You will get an acknowledgment within 72 hours.

## Scope of special interest
- Anything that could ban an allowlisted IP or the admin's own session
- Privilege escalation via the enforcer helper or plugins
- Prompt injection through log content influencing AI verdicts beyond policy bounds
- Dashboard exposure beyond localhost

## Supported versions
Pre-1.0: only the latest release receives fixes.

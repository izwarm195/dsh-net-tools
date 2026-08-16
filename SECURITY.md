# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in dsh-net-tools, please report it
privately — do **not** open a public issue. Use one of:

- GitHub [private vulnerability reporting](https://github.com/izwarm195/dsh-net-tools/security/advisories/new)
- Email the maintainer at the address listed in the git history

We aim to respond within 3 business days and will coordinate a fix and
disclosure with you.

## Scope

The `net_fetch` tool enforces SSRF guards, scheme restrictions, response-size
caps and redirect limits; treat any bypass of these as a vulnerability. The
plugin runs in the DSH host process with the same privileges as the user, so
report anything that could lead to unauthorized network access or data
exfiltration.

# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | Yes                |
| < 0.4   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in SentinelForge, **please do NOT
open a public GitHub issue.**

Instead, email: **sageshadhikari@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours and a detailed response
within 7 days.

## Security Design

SentinelForge implements multiple security layers:

- **Constitutional AI Safety** — 10 rules governing all agent behavior
- **Prompt Injection Detection** — Regex, semantic, entropy, and Base64 analysis
- **Human-in-the-Loop** — Critical actions require explicit approval
- **Canary/Dry-Run Mode** — Preview commands before execution
- **Hash-Chained Audit Log** — Tamper-evident SHA-256 chain
- **Rate Limiting** — API request throttling
- **JWT + API Key Auth** — Role-based access control
- **Simulation Mode** — Safe testing without real system changes

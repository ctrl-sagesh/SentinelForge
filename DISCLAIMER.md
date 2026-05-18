# Disclaimer & Liability Notice

## Important Safety Warning

SentinelForge is an **AI-powered autonomous cyber defense framework** that can
execute real containment actions on live systems including:

- Blocking IP addresses via firewall rules
- Isolating hosts from the network
- Killing running processes
- Disabling user accounts
- Quarantining files

## Use at Your Own Risk

**BY USING THIS SOFTWARE, YOU ACKNOWLEDGE AND AGREE THAT:**

1. **No Warranty.** This software is provided "AS IS" without warranty of any
   kind. The authors make no guarantees about the correctness, reliability, or
   safety of any automated actions taken by this system.

2. **Potential for Damage.** Automated containment actions can disrupt
   legitimate services, lock out authorized users, and cause data loss. Always
   run in **simulation mode** first and thoroughly test in an isolated
   environment before enabling real execution.

3. **Human Oversight Required.** This software is designed to assist human
   security analysts, not replace them. Critical actions require human approval
   by default. Disabling the approval workflow is done at your own risk.

4. **AI Limitations.** The LLM-powered analysis can produce incorrect
   assessments, false positives, or miss real threats. Never rely solely on
   automated analysis for critical security decisions.

5. **Compliance.** You are responsible for ensuring your use of this software
   complies with all applicable laws, regulations, and organizational policies.
   Automated IP blocking and account disabling may have legal implications in
   your jurisdiction.

6. **No Liability.** The authors and contributors shall not be liable for any
   direct, indirect, incidental, special, exemplary, or consequential damages
   arising from the use of this software.

## Recommended Precautions

- Always start with `SIMULATION_MODE=true`
- Enable `CANARY_MODE=true` for dry-run previews before execution
- Set `REQUIRE_HUMAN_APPROVAL=true` for all critical actions
- Test in an isolated lab environment before any production deployment
- Maintain manual override access to all systems SentinelForge manages
- Keep audit logging enabled and review logs regularly
- Set up alerting (Slack/Email/Syslog) for immediate visibility

## Contact

For security vulnerabilities, please email: sageshadhikari@gmail.com

Do NOT open public issues for security vulnerabilities.

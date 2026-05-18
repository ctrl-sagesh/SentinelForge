# Contributing to SentinelForge

Thank you for your interest in contributing. SentinelForge is a security-critical project — contributions are welcome but must meet safety and quality standards.

## Getting Started

```bash
git clone https://github.com/SageshAdhikari/SentinelForge.git
cd SentinelForge
make install        # Linux/Mac
# .\scripts\setup_windows.ps1   # Windows
make test
```

## Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`pytest tests/ -v`)
5. Run linting (`ruff check src/`)
6. Submit a pull request with a clear description

## Code Standards

- **Python 3.11+** required
- **Type hints** on all public functions
- **Pydantic models** for data validation
- **structlog** for logging (never `print()`)
- **ruff** for linting (config in `pyproject.toml`)
- Keep functions short and focused

## Security Requirements

Every contribution must follow these rules:

1. **Never introduce hardcoded secrets** — use environment variables or `.env`
2. **Never bypass the Guardian agent** — all actions must be validated
3. **Never add irreversible actions** without human approval gates
4. **Always sanitize user input** through the SafetyEngine
5. **Never log sensitive data** — use `redact()` from `core/secrets.py`
6. **Add tests** for any security-relevant code
7. **Keep the audit hash chain intact** — never modify the AuditLogger interface

## Adding a New Agent

1. Create `src/sentinelforge/agents/your_agent.py`
2. Extend `BaseAgent` and implement `async def run(self, state) -> OrchestratorState`
3. Register in `core/orchestrator.py`
4. Add tests in `tests/test_agents.py`
5. Update the README architecture diagram

## Adding a New Connector

1. Create a class extending the appropriate ABC in `connectors/`
2. Register it in the config system (`core/config.py`)
3. Add tests
4. Document in README

## Adding New Detection Signatures

1. Add to `ANOMALY_SIGNATURES` in `agents/monitor.py`
2. Include: regex pattern, severity, MITRE technique IDs, description
3. Add test cases
4. Add the MITRE technique to `MITRE_LABELS` in `dashboard/app.py`

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_safety.py -v

# Run evaluation harness
sentinelforge evaluate
```

All PRs must pass:
- All existing tests (currently 166+)
- All 3 evaluation scenarios (brute_force, ransomware, lateral_movement)
- Ruff linting with no errors

## Reporting Security Vulnerabilities

If you find a security vulnerability, **do not open a public issue**. Instead, email the maintainers directly. We will respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

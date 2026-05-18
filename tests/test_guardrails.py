"""Tests for guardrails — output validation and canary execution."""


from sentinelforge.core.guardrails import (
    CanaryExecutor,
    OutputValidator,
    _contains_shell_meta,
    _is_valid_ip,
)
from sentinelforge.core.models import (
    ContainmentAction,
    Investigation,
    Severity,
)


class TestOutputValidation:
    def test_valid_action_passes(self):
        action = ContainmentAction(
            action_type="block_ip",
            target="10.0.0.1",
            risk_score=0.5,
            reasoning="Block suspicious IP",
        )
        issues = OutputValidator.validate_action(action)
        assert issues == []

    def test_missing_type_flagged(self):
        action = ContainmentAction(
            action_type="",
            target="10.0.0.1",
            risk_score=0.5,
            reasoning="test",
        )
        issues = OutputValidator.validate_action(action)
        assert any("no type" in i for i in issues)

    def test_missing_target_flagged(self):
        action = ContainmentAction(
            action_type="block_ip",
            target="",
            risk_score=0.5,
            reasoning="test",
        )
        issues = OutputValidator.validate_action(action)
        assert any("no target" in i for i in issues)

    def test_out_of_range_risk(self):
        action = ContainmentAction(
            action_type="block_ip",
            target="10.0.0.1",
            risk_score=1.5,
            reasoning="test",
        )
        issues = OutputValidator.validate_action(action)
        assert any("out of" in i for i in issues)

    def test_invalid_ip_for_block(self):
        action = ContainmentAction(
            action_type="block_ip",
            target="not-an-ip",
            risk_score=0.5,
            reasoning="test",
        )
        issues = OutputValidator.validate_action(action)
        assert any("not a valid IP" in i for i in issues)

    def test_shell_meta_in_kill_target(self):
        action = ContainmentAction(
            action_type="kill_process",
            target="proc;rm -rf /",
            risk_score=0.5,
            reasoning="test",
        )
        issues = OutputValidator.validate_action(action)
        assert any("metacharacter" in i for i in issues)

    def test_shell_meta_in_reasoning(self):
        action = ContainmentAction(
            action_type="block_ip",
            target="10.0.0.1",
            risk_score=0.5,
            reasoning="block this; curl evil.com",
        )
        issues = OutputValidator.validate_action(action)
        assert any("reasoning" in i.lower() for i in issues)


class TestLLMOutputValidation:
    def test_clean_output(self):
        issues = OutputValidator.validate_llm_output("Block IP 10.0.0.1 on the firewall.")
        assert issues == []

    def test_destructive_rm(self):
        issues = OutputValidator.validate_llm_output("Run rm -rf / to clean up")
        assert any("rm -rf" in i.lower() for i in issues)

    def test_sql_drop(self):
        issues = OutputValidator.validate_llm_output("Execute DROP TABLE users;")
        assert any("DROP" in i for i in issues)

    def test_code_exec(self):
        issues = OutputValidator.validate_llm_output("Use exec('import os; os.system(\"whoami\")')")
        assert any("execution" in i.lower() for i in issues)

    def test_oversized_output(self):
        issues = OutputValidator.validate_llm_output("x" * 60000)
        assert any("50KB" in i for i in issues)


class TestInvestigationValidation:
    def test_valid_investigation(self):
        inv = Investigation(
            summary="Brute force attack from 10.0.0.1",
            root_cause="Credential stuffing using leaked passwords",
            confidence=0.85,
            severity=Severity.HIGH,
            affected_assets=["10.0.0.1"],
            mitre_techniques=["T1110"],
            recommended_actions=["block_ip 10.0.0.1"],
        )
        issues = OutputValidator.validate_investigation(inv)
        assert issues == []

    def test_short_summary(self):
        inv = Investigation(
            summary="Hi",
            root_cause="test",
            confidence=0.5,
            severity=Severity.LOW,
        )
        issues = OutputValidator.validate_investigation(inv)
        assert any("too short" in i for i in issues)

    def test_critical_low_confidence(self):
        inv = Investigation(
            summary="Very suspicious activity detected",
            root_cause="Unknown",
            confidence=0.1,
            severity=Severity.CRITICAL,
        )
        issues = OutputValidator.validate_investigation(inv)
        assert any("suspicious" in i.lower() for i in issues)


class TestCanaryExecutor:
    def test_canary_block_ip(self):
        action = ContainmentAction(
            action_type="block_ip",
            target="10.0.0.99",
            risk_score=0.4,
            reasoning="test",
        )
        result = CanaryExecutor.run_canary(action)
        assert result.success
        assert result.canary
        assert "10.0.0.99" in result.output

    def test_canary_kill_process(self):
        action = ContainmentAction(
            action_type="kill_process",
            target="12345",
            risk_score=0.4,
            reasoning="test",
        )
        result = CanaryExecutor.run_canary(action)
        assert result.success
        assert result.canary

    def test_canary_unknown_type(self):
        action = ContainmentAction(
            action_type="launch_missiles",
            target="moon",
            risk_score=0.4,
            reasoning="test",
        )
        result = CanaryExecutor.run_canary(action)
        assert not result.success
        assert "No canary executor" in result.output


class TestHelpers:
    def test_valid_ips(self):
        assert _is_valid_ip("192.168.1.1")
        assert not _is_valid_ip("999.0.0.1")
        assert not _is_valid_ip("hello")

    def test_shell_meta(self):
        assert _contains_shell_meta("test;bad")
        assert _contains_shell_meta("test|pipe")
        assert _contains_shell_meta("test`cmd`")
        assert not _contains_shell_meta("clean-text")

"""Evaluation harness — runs attack scenarios and measures detection/response quality."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.core.logging import get_logger
from sentinelforge.core.orchestrator import run_defense_cycle
from sentinelforge.simulation.scenarios import SCENARIOS, run_scenario

logger = get_logger("evaluation")


@dataclass
class EvalResult:
    scenario_name: str
    events_generated: int = 0
    events_detected: int = 0
    investigations_created: int = 0
    actions_proposed: int = 0
    actions_approved: int = 0
    actions_executed: int = 0
    reports_generated: int = 0
    safety_violations: int = 0
    human_escalations: int = 0
    detection_rate: float = 0.0
    response_time_ms: float = 0.0
    correct_severity: bool = False
    correct_mitre: bool = False
    passed: bool = False
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalSuite:
    results: list[EvalResult] = field(default_factory=list)
    total_passed: int = 0
    total_failed: int = 0
    overall_detection_rate: float = 0.0
    avg_response_time_ms: float = 0.0


async def evaluate_scenario(
    scenario_name: str,
    use_llm: bool = False,
) -> EvalResult:
    """Run a single scenario and evaluate detection/response quality."""
    result = EvalResult(scenario_name=scenario_name)

    initial_state = run_scenario(scenario_name)
    result.events_generated = len(initial_state.events)

    expected_severity = max(
        initial_state.events,
        key=lambda e: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[e.severity.value],
    ).severity

    expected_mitre = set()
    for e in initial_state.events:
        expected_mitre.update(e.mitre_techniques)

    start = time.monotonic()
    final_state = await run_defense_cycle(
        initial_state=initial_state,
        use_llm=use_llm,
    )
    elapsed_ms = (time.monotonic() - start) * 1000

    result.events_detected = len(final_state.events)
    result.investigations_created = len(final_state.investigations)
    result.actions_proposed = len(final_state.proposed_actions)
    result.actions_approved = len(final_state.approved_actions)
    result.actions_executed = len(final_state.executed_actions)
    result.reports_generated = len(final_state.reports)
    result.safety_violations = len(final_state.safety_violations)
    result.human_escalations = len(final_state.human_escalations)
    result.response_time_ms = elapsed_ms

    unique_event_types = {e.event_type for e in initial_state.events}
    investigated_types = {
        e.event_type
        for inv in final_state.investigations
        for eid in inv.event_ids
        for e in final_state.events
        if e.id == eid
    }
    if not investigated_types and final_state.investigations:
        investigated_types = unique_event_types

    result.detection_rate = (
        len(investigated_types) / max(1, len(unique_event_types))
    )

    if final_state.investigations:
        inv = final_state.investigations[0]
        result.correct_severity = inv.severity == expected_severity
        detected_mitre = set(inv.mitre_techniques)
        result.correct_mitre = bool(expected_mitre & detected_mitre)

    result.passed = (
        result.investigations_created > 0
        and result.detection_rate > 0
        and result.safety_violations == 0
    )

    return result


async def run_full_evaluation(use_llm: bool = False) -> EvalSuite:
    """Run all scenarios and produce an evaluation report."""
    suite = EvalSuite()

    for name in SCENARIOS:
        logger.info("eval_scenario_start", scenario=name)
        result = await evaluate_scenario(name, use_llm=use_llm)
        suite.results.append(result)

        if result.passed:
            suite.total_passed += 1
        else:
            suite.total_failed += 1

        logger.info(
            "eval_scenario_complete",
            scenario=name,
            passed=result.passed,
            detection_rate=f"{result.detection_rate:.2%}",
            response_ms=f"{result.response_time_ms:.0f}",
        )

    if suite.results:
        suite.overall_detection_rate = sum(
            r.detection_rate for r in suite.results
        ) / len(suite.results)
        suite.avg_response_time_ms = sum(
            r.response_time_ms for r in suite.results
        ) / len(suite.results)

    return suite


def print_eval_report(suite: EvalSuite) -> str:
    """Format evaluation results as a human-readable report."""
    lines = [
        "=" * 70,
        "SENTINELFORGE EVALUATION REPORT",
        "=" * 70,
        f"Scenarios Run: {len(suite.results)}",
        f"Passed: {suite.total_passed} | Failed: {suite.total_failed}",
        f"Overall Detection Rate: {suite.overall_detection_rate:.1%}",
        f"Avg Response Time: {suite.avg_response_time_ms:.0f}ms",
        "-" * 70,
    ]

    for r in suite.results:
        status = "PASS" if r.passed else "FAIL"
        lines.append(
            f"[{status}] {r.scenario_name:25s} | "
            f"detect={r.detection_rate:.0%} | "
            f"inv={r.investigations_created} | "
            f"actions={r.actions_executed} | "
            f"reports={r.reports_generated} | "
            f"violations={r.safety_violations} | "
            f"{r.response_time_ms:.0f}ms"
        )

    lines.append("=" * 70)
    return "\n".join(lines)

"""CLI entry point for SentinelForge."""

from __future__ import annotations

import argparse
import asyncio
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinelforge",
        description="SentinelForge — Autonomous AI Cyber Defense Agent Framework",
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run a defense cycle")
    run_p.add_argument("--scenario", default=None, help="Simulation scenario name")
    run_p.add_argument("--llm", action="store_true", help="Enable LLM-based analysis")
    run_p.add_argument("--config", default=None, help="Path to YAML config file")

    sub.add_parser("serve", help="Start the FastAPI server")
    sub.add_parser("dashboard", help="Launch the Streamlit dashboard")
    sub.add_parser("evaluate", help="Run the evaluation harness")

    audit_p = sub.add_parser("audit", help="Audit log operations")
    audit_p.add_argument("--verify", action="store_true", help="Verify audit chain integrity")
    audit_p.add_argument("--export", choices=["csv"], help="Export audit log as CSV")
    audit_p.add_argument("--since", type=str, default=None, help="Time range (e.g. 24h, 7d)")

    seed_p = sub.add_parser("seed", help="Seed the knowledge base")

    args = parser.parse_args()

    if args.command == "run":
        _cmd_run(args)
    elif args.command == "serve":
        _cmd_serve()
    elif args.command == "dashboard":
        _cmd_dashboard()
    elif args.command == "evaluate":
        _cmd_evaluate(args)
    elif args.command == "audit":
        _cmd_audit(args)
    elif args.command == "seed":
        _cmd_seed()
    else:
        parser.print_help()


def _cmd_run(args: argparse.Namespace) -> None:
    from sentinelforge.core.config import load_config
    from sentinelforge.core.logging import setup_logging
    from sentinelforge.core.models import OrchestratorState
    from sentinelforge.core.orchestrator import run_defense_cycle

    if args.config:
        from pathlib import Path
        settings = load_config(Path(args.config))
    else:
        settings = load_config()

    setup_logging(settings.debug)

    initial_state = OrchestratorState()

    if args.scenario:
        from sentinelforge.simulation.scenarios import run_scenario
        initial_state = run_scenario(args.scenario)
        print(f"Loaded scenario '{args.scenario}' with {len(initial_state.events)} events")

    result = asyncio.run(
        run_defense_cycle(
            settings=settings,
            initial_state=initial_state,
            use_llm=args.llm,
        )
    )

    print("\nDefense cycle complete:")
    print(f"  Events detected:    {len(result.events)}")
    print(f"  Investigations:     {len(result.investigations)}")
    print(f"  Actions proposed:   {len(result.proposed_actions)}")
    print(f"  Actions executed:   {len(result.executed_actions)}")
    print(f"  Reports generated:  {len(result.reports)}")
    print(f"  Safety violations:  {len(result.safety_violations)}")
    print(f"  Human escalations:  {len(result.human_escalations)}")

    if result.reports:
        print("\n--- Incident Report ---")
        r = result.reports[0]
        print(f"Title: {r.title}")
        print(f"Severity: {r.severity.value}")
        print(f"Summary: {r.executive_summary}")


def _cmd_serve() -> None:
    import uvicorn
    print("Starting SentinelForge API server on http://localhost:8000")
    uvicorn.run(
        "sentinelforge.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )


def _cmd_dashboard() -> None:
    import subprocess
    print("Starting SentinelForge Dashboard...")
    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        "src/sentinelforge/dashboard/app.py",
        "--server.port", "8501",
    ])


def _cmd_evaluate(args: argparse.Namespace) -> None:
    from sentinelforge.core.alerting import reset_alert_manager
    from sentinelforge.core.config import reset_settings
    from sentinelforge.core.logging import setup_logging
    from sentinelforge.core.safety import reset_safety_engine
    from sentinelforge.evaluation.harness import print_eval_report, run_full_evaluation

    reset_settings()
    reset_safety_engine()
    reset_alert_manager()
    setup_logging(False)
    suite = asyncio.run(run_full_evaluation(use_llm=False))
    print(print_eval_report(suite))


def _cmd_audit(args: argparse.Namespace) -> None:
    from sentinelforge.core.audit import get_audit_logger

    audit = get_audit_logger()

    since_hours = None
    if args.since:
        since_str = args.since.strip().lower()
        if since_str.endswith("h"):
            since_hours = int(since_str[:-1])
        elif since_str.endswith("d"):
            since_hours = int(since_str[:-1]) * 24
        else:
            since_hours = int(since_str)

    if args.verify:
        valid, count = audit.verify_chain()
        if valid:
            print(f"Audit chain VALID — {count} entries verified")
        else:
            print(f"Audit chain BROKEN at entry {count}")
            sys.exit(1)
    elif args.export == "csv":
        print(audit.export_csv(since_hours=since_hours))
    elif since_hours:
        entries = audit.get_entries(since_hours=since_hours)
        print(f"Audit entries (last {args.since}): {len(entries)}")
        for e in entries[-20:]:
            print(f"  [{e.get('status')}] {e.get('agent')} — {e.get('action')} {e.get('timestamp','')}")
    else:
        print("Usage: sentinelforge audit --verify | --export csv [--since 24h]")


def _cmd_seed() -> None:
    from sentinelforge.knowledge.vector_store import ThreatKnowledgeBase

    kb = ThreatKnowledgeBase()
    kb.seed_mitre_attack()
    print(f"Knowledge base seeded — {kb.count()} entries")


if __name__ == "__main__":
    main()

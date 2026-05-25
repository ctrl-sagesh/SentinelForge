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
    parser.add_argument(
        "--version", action="version", version="SentinelForge v0.4.0"
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

    sub.add_parser("seed", help="Seed the knowledge base")
    sub.add_parser("demo", help="Launch dashboard with sample threat data")

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
    elif args.command == "demo":
        _cmd_demo()
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


def _cmd_demo() -> None:
    import os
    import subprocess
    from datetime import datetime, timedelta, timezone

    os.environ["SENTINELFORGE_DEMO_MODE"] = "true"
    os.environ["SF_SIMULATION_MODE"] = "true"

    print("Seeding demo data...")

    from sentinelforge.core.database import get_database
    from sentinelforge.core.models import Severity

    db = get_database()
    now = datetime.now(timezone.utc)

    demo_events = [
        {"event_type": "brute_force", "severity": "high", "source_ip": "203.0.113.42",
         "dest_ip": "10.0.1.50", "description": "Multiple failed SSH login attempts",
         "hours_ago": 2},
        {"event_type": "brute_force", "severity": "high", "source_ip": "203.0.113.42",
         "dest_ip": "10.0.1.50", "description": "Continued SSH brute force — 50+ attempts",
         "hours_ago": 1.5},
        {"event_type": "brute_force", "severity": "critical", "source_ip": "198.51.100.10",
         "dest_ip": "10.0.1.20", "description": "RDP brute force from known bad IP",
         "hours_ago": 12},
        {"event_type": "port_scan", "severity": "medium", "source_ip": "192.0.2.55",
         "dest_ip": "10.0.1.0", "description": "SYN scan on ports 1-1024",
         "hours_ago": 24},
        {"event_type": "port_scan", "severity": "medium", "source_ip": "203.0.113.42",
         "dest_ip": "10.0.1.50", "description": "Service enumeration scan detected",
         "hours_ago": 3},
        {"event_type": "suspicious_process", "severity": "critical", "source_ip": "",
         "dest_ip": "10.0.1.50", "description": "Reverse shell spawned — /bin/bash -i",
         "hours_ago": 0.5},
        {"event_type": "privilege_escalation", "severity": "critical", "source_ip": "",
         "dest_ip": "10.0.1.50", "description": "sudo to root from unprivileged account",
         "hours_ago": 0.4},
        {"event_type": "data_exfiltration", "severity": "critical", "source_ip": "10.0.1.50",
         "dest_ip": "198.51.100.99", "description": "Large outbound transfer — 2.3 GB to external IP",
         "hours_ago": 0.3},
        {"event_type": "lateral_movement", "severity": "high", "source_ip": "10.0.1.50",
         "dest_ip": "10.0.1.100", "description": "PsExec execution to domain controller",
         "hours_ago": 6},
        {"event_type": "lateral_movement", "severity": "high", "source_ip": "10.0.1.50",
         "dest_ip": "10.0.1.101", "description": "SMB admin share access on file server",
         "hours_ago": 5},
        {"event_type": "credential_dump", "severity": "critical", "source_ip": "",
         "dest_ip": "10.0.1.100", "description": "Mimikatz signature detected in memory",
         "hours_ago": 5.5},
        {"event_type": "ransomware", "severity": "critical", "source_ip": "",
         "dest_ip": "10.0.1.101", "description": "Mass file encryption detected — .locked extension",
         "hours_ago": 48},
        {"event_type": "ransomware", "severity": "critical", "source_ip": "",
         "dest_ip": "10.0.1.101", "description": "Ransom note dropped — README_DECRYPT.txt",
         "hours_ago": 47.5},
        {"event_type": "dns_tunnel", "severity": "high", "source_ip": "10.0.1.30",
         "dest_ip": "192.0.2.99", "description": "Suspicious DNS TXT queries — possible C2 tunnel",
         "hours_ago": 36},
        {"event_type": "malware", "severity": "high", "source_ip": "",
         "dest_ip": "10.0.1.75", "description": "Known trojan signature in downloaded binary",
         "hours_ago": 60},
    ]

    for evt in demo_events:
        ts = (now - timedelta(hours=evt["hours_ago"])).isoformat()
        db.save_event({
            "event_type": evt["event_type"],
            "severity": evt["severity"],
            "source_ip": evt["source_ip"],
            "dest_ip": evt.get("dest_ip", ""),
            "description": evt["description"],
            "source": "demo",
            "timestamp": ts,
            "confidence": 0.85,
            "mitre_techniques": [],
        })

    print(f"  Seeded {len(demo_events)} demo events spanning 72 hours")
    print()
    print("Demo mode active — dashboard running at http://localhost:8501")
    print("  (read-only sample data, no real actions will execute)")
    print()

    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        "src/sentinelforge/dashboard/app.py",
        "--server.port", "8501",
    ])


def _cmd_seed() -> None:
    from sentinelforge.knowledge.vector_store import ThreatKnowledgeBase

    kb = ThreatKnowledgeBase()
    kb.seed_mitre_attack()
    print(f"Knowledge base seeded — {kb.count()} entries")


if __name__ == "__main__":
    main()

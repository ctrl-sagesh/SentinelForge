"""Attack simulation scenarios based on MITRE ATT&CK techniques."""

from __future__ import annotations

from sentinelforge.core.models import OrchestratorState, Severity, ThreatEvent


class AttackScenario:
    """Base class for attack simulations."""

    name: str = ""
    description: str = ""
    mitre_techniques: list[str] = []

    def generate_events(self) -> list[ThreatEvent]:
        raise NotImplementedError


class BruteForceScenario(AttackScenario):
    name = "brute_force_ssh"
    description = "Simulates SSH brute force attack from external IP"
    mitre_techniques = ["T1110", "T1021"]

    def generate_events(self) -> list[ThreatEvent]:
        attacker_ip = "203.0.113.42"
        target_ip = "10.0.1.50"

        events = []
        for i in range(20):
            events.append(
                ThreatEvent(
                    source="simulation",
                    event_type="brute_force",
                    description=f"Failed SSH login attempt #{i+1} from {attacker_ip}",
                    severity=Severity.HIGH if i > 10 else Severity.MEDIUM,
                    raw_data={
                        "log_line": f"sshd: Failed password for root from {attacker_ip} port {50000+i}",
                        "attempt": i + 1,
                    },
                    iocs=[attacker_ip],
                    mitre_techniques=["T1110"],
                    confidence=min(0.5 + i * 0.025, 0.95),
                    source_ip=attacker_ip,
                    dest_ip=target_ip,
                    hostname="prod-web-01",
                )
            )

        events.append(
            ThreatEvent(
                source="simulation",
                event_type="brute_force",
                description=f"Successful SSH login after {len(events)} failed attempts",
                severity=Severity.CRITICAL,
                raw_data={"log_line": f"sshd: Accepted password for root from {attacker_ip}"},
                iocs=[attacker_ip],
                mitre_techniques=["T1110", "T1078"],
                confidence=0.95,
                source_ip=attacker_ip,
                dest_ip=target_ip,
                hostname="prod-web-01",
            )
        )
        return events


class RansomwareScenario(AttackScenario):
    name = "ransomware_deployment"
    description = "Simulates ransomware attack chain: phishing -> execution -> encryption"
    mitre_techniques = ["T1566", "T1059", "T1486"]

    def generate_events(self) -> list[ThreatEvent]:
        return [
            ThreatEvent(
                source="simulation",
                event_type="malware_indicator",
                description="Suspicious email attachment opened — macro execution detected",
                severity=Severity.HIGH,
                raw_data={"process": "WINWORD.EXE", "child": "powershell.exe -enc"},
                mitre_techniques=["T1566", "T1059"],
                confidence=0.85,
                hostname="workstation-42",
            ),
            ThreatEvent(
                source="simulation",
                event_type="suspicious_process",
                description="PowerShell downloading payload from external server",
                severity=Severity.CRITICAL,
                raw_data={"cmdline": "powershell.exe -enc [base64]", "dest": "198.51.100.77"},
                mitre_techniques=["T1059", "T1105"],
                confidence=0.9,
                source_ip="198.51.100.77",
                hostname="workstation-42",
            ),
            ThreatEvent(
                source="simulation",
                event_type="data_exfiltration",
                description="Large volume of data being encrypted and exfiltrated",
                severity=Severity.CRITICAL,
                raw_data={"files_affected": 1500, "ransom_note": "README_ENCRYPTED.txt"},
                mitre_techniques=["T1486", "T1048"],
                confidence=0.95,
                hostname="workstation-42",
            ),
        ]


class LateralMovementScenario(AttackScenario):
    name = "lateral_movement"
    description = "Simulates attacker moving laterally through the network"
    mitre_techniques = ["T1021", "T1003", "T1071"]

    def generate_events(self) -> list[ThreatEvent]:
        return [
            ThreatEvent(
                source="simulation",
                event_type="suspicious_process",
                description="Mimikatz detected on compromised host",
                severity=Severity.CRITICAL,
                raw_data={"process": "mimikatz.exe", "user": "admin"},
                mitre_techniques=["T1003"],
                confidence=0.95,
                hostname="dc-01",
                source_ip="10.0.1.100",
            ),
            ThreatEvent(
                source="simulation",
                event_type="lateral_movement",
                description="Pass-the-hash authentication to multiple hosts",
                severity=Severity.CRITICAL,
                raw_data={
                    "technique": "pass_the_hash",
                    "targets": ["10.0.1.101", "10.0.1.102", "10.0.1.103"],
                },
                mitre_techniques=["T1021", "T1550"],
                confidence=0.9,
                source_ip="10.0.1.100",
                hostname="dc-01",
            ),
            ThreatEvent(
                source="simulation",
                event_type="privilege_escalation",
                description="Domain admin credentials obtained via Kerberoasting",
                severity=Severity.CRITICAL,
                raw_data={"technique": "kerberoasting", "target_spn": "MSSQLSvc/db-01:1433"},
                mitre_techniques=["T1558"],
                confidence=0.88,
                source_ip="10.0.1.100",
                hostname="dc-01",
            ),
        ]


SCENARIOS: dict[str, type[AttackScenario]] = {
    "brute_force": BruteForceScenario,
    "ransomware": RansomwareScenario,
    "lateral_movement": LateralMovementScenario,
}


def run_scenario(scenario_name: str) -> OrchestratorState:
    """Generate events for a named scenario and return initial state."""
    scenario_cls = SCENARIOS.get(scenario_name)
    if not scenario_cls:
        raise ValueError(f"Unknown scenario: {scenario_name}. Available: {list(SCENARIOS.keys())}")

    scenario = scenario_cls()
    events = scenario.generate_events()
    return OrchestratorState(events=events)

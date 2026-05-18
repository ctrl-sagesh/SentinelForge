"""Knowledge base — ChromaDB RAG for MITRE ATT&CK and threat intelligence.

Wraps the vector store with MITRE technique seeding (top 50) and
graceful degradation when ChromaDB is unavailable.
"""

from __future__ import annotations

from sentinelforge.core.logging import get_logger

logger = get_logger("knowledge")

MITRE_TECHNIQUES = [
    ("T1110", "Brute Force", "Adversaries use brute force to gain access to accounts when passwords are unknown or when password hashes are obtained."),
    ("T1046", "Network Service Discovery", "Adversaries scan for services running on remote hosts to find potential targets for exploitation."),
    ("T1548", "Abuse Elevation Control", "Adversaries circumvent mechanisms designed to control elevated privileges to gain higher-level permissions."),
    ("T1048", "Exfiltration Over Alternative Protocol", "Adversaries steal data by exfiltrating it over a protocol different from the existing command and control channel."),
    ("T1059", "Command and Scripting Interpreter", "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries."),
    ("T1021", "Remote Services", "Adversaries use valid accounts to log into remote services such as SSH, RDP, VNC, or SMB."),
    ("T1003", "OS Credential Dumping", "Adversaries dump credentials to obtain account login and credential material from the operating system."),
    ("T1071", "Application Layer Protocol", "Adversaries communicate using OSI application layer protocols to avoid detection and network filtering."),
    ("T1486", "Data Encrypted for Impact", "Adversaries encrypt data on target systems to interrupt availability, typically as ransomware."),
    ("T1566", "Phishing", "Adversaries send phishing messages to gain access to victim systems through spearphishing attachments or links."),
    ("T1078", "Valid Accounts", "Adversaries obtain and abuse credentials of existing accounts as a means of gaining access."),
    ("T1136", "Create Account", "Adversaries create accounts to maintain access to victim systems with configured credentials."),
    ("T1098", "Account Manipulation", "Adversaries manipulate accounts to maintain or elevate access to victim systems."),
    ("T1070", "Indicator Removal", "Adversaries delete or modify artifacts generated within systems to remove evidence of their presence."),
    ("T1543", "Create or Modify System Process", "Adversaries create or modify system-level processes to repeatedly execute malicious payloads."),
    ("T1055", "Process Injection", "Adversaries inject code into processes to evade process-based defenses and elevate privileges."),
    ("T1105", "Ingress Tool Transfer", "Adversaries transfer tools or files from an external system into a compromised environment."),
    ("T1112", "Modify Registry", "Adversaries interact with the Windows Registry to hide configuration or remove information for persistence."),
    ("T1531", "Account Access Removal", "Adversaries interrupt availability of system resources by inhibiting access to accounts."),
    ("T1558", "Steal or Forge Kerberos Tickets", "Adversaries attempt to subvert Kerberos authentication by stealing or forging tickets."),
    ("T1565", "Data Manipulation", "Adversaries insert, delete, or manipulate data to influence outcomes or hide activity."),
    ("T1571", "Non-Standard Port", "Adversaries communicate using a protocol and port pairing not normally associated with the protocol."),
    ("T1053", "Scheduled Task/Job", "Adversaries abuse task scheduling to execute malicious code at system startup or on a scheduled basis."),
    ("T1027", "Obfuscated Files or Information", "Adversaries attempt to make executables or files difficult to discover or analyze by encrypting or encoding."),
    ("T1036", "Masquerading", "Adversaries manipulate features of artifacts to make them appear legitimate to users and security tools."),
    ("T1569", "System Services", "Adversaries abuse system services to execute commands or programs."),
    ("T1547", "Boot or Logon Autostart Execution", "Adversaries configure system settings to automatically execute a program during boot or logon."),
    ("T1574", "Hijack Execution Flow", "Adversaries abuse the way operating systems run programs by hijacking execution flow."),
    ("T1562", "Impair Defenses", "Adversaries maliciously modify components of a victim environment to hinder or disable defensive mechanisms."),
    ("T1047", "Windows Management Instrumentation", "Adversaries abuse WMI to execute malicious commands and payloads."),
    ("T1218", "System Binary Proxy Execution", "Adversaries bypass defenses by proxying execution of malicious content with signed or trusted binaries."),
    ("T1082", "System Information Discovery", "Adversaries attempt to get detailed information about the operating system and hardware."),
    ("T1083", "File and Directory Discovery", "Adversaries enumerate files and directories or search in specific locations for information."),
    ("T1057", "Process Discovery", "Adversaries attempt to get information about running processes on a system."),
    ("T1018", "Remote System Discovery", "Adversaries attempt to get a listing of other systems by IP address or hostname on the network."),
    ("T1049", "System Network Connections Discovery", "Adversaries attempt to get a listing of network connections to or from the compromised system."),
    ("T1560", "Archive Collected Data", "Adversaries compress and encrypt data before exfiltration to minimize network transfer size."),
    ("T1041", "Exfiltration Over C2 Channel", "Adversaries steal data by exfiltrating it over an existing command and control channel."),
    ("T1190", "Exploit Public-Facing Application", "Adversaries use software vulnerabilities in public-facing applications to gain access."),
    ("T1133", "External Remote Services", "Adversaries leverage external-facing remote services to initially access a network."),
    ("T1068", "Exploitation for Privilege Escalation", "Adversaries exploit software vulnerabilities to elevate privileges."),
    ("T1078.003", "Valid Accounts: Local Accounts", "Adversaries obtain and abuse credentials of local accounts for persistence and lateral movement."),
    ("T1134", "Access Token Manipulation", "Adversaries modify access tokens to operate under different security contexts."),
    ("T1204", "User Execution", "Adversaries rely on a user to execute a malicious payload, such as opening a document or clicking a link."),
    ("T1497", "Virtualization/Sandbox Evasion", "Adversaries employ checks to detect and avoid virtualization and analysis environments."),
    ("T1056", "Input Capture", "Adversaries use methods of capturing user input to obtain credentials or collect information."),
    ("T1005", "Data from Local System", "Adversaries search local system sources to find files of interest and sensitive data."),
    ("T1012", "Query Registry", "Adversaries interact with the Windows Registry to gather information about the system and software."),
    ("T1016", "System Network Configuration Discovery", "Adversaries look for details about the network configuration and settings of systems."),
    ("T1033", "System Owner/User Discovery", "Adversaries attempt to identify the primary user or current user of a system."),
]


class KnowledgeBase:
    """ChromaDB-backed knowledge base with MITRE ATT&CK seeding."""

    def __init__(self, persist_dir: str = "./data/vector_db") -> None:
        self._persist_dir = persist_dir
        self._available = True
        self._store = None

    def _ensure_store(self) -> bool:
        if self._store is not None:
            return True
        if not self._available:
            return False
        try:
            from sentinelforge.knowledge.vector_store import ThreatKnowledgeBase
            self._store = ThreatKnowledgeBase(self._persist_dir)
            return True
        except Exception as exc:
            logger.warning("knowledge_base_unavailable", error=str(exc))
            self._available = False
            return False

    def seed_if_empty(self) -> None:
        if not self._ensure_store():
            return
        try:
            if self._store.count() > 0:
                return
            documents = [f"{tid} - {name}: {desc}" for tid, name, desc in MITRE_TECHNIQUES]
            metadatas = [{"technique_id": tid, "name": name} for tid, name, _ in MITRE_TECHNIQUES]
            ids = [f"mitre_{tid}" for tid, _, _ in MITRE_TECHNIQUES]
            self._store.add_knowledge(documents, metadatas, ids)
            logger.info("knowledge_base_seeded", count=len(MITRE_TECHNIQUES))
        except Exception as exc:
            logger.warning("knowledge_seed_failed", error=str(exc))

    def query(self, query_text: str, n_results: int = 3) -> list[dict]:
        if not self._ensure_store():
            return []
        try:
            return self._store.query(query_text, n_results=n_results)
        except Exception as exc:
            logger.warning("knowledge_query_failed", error=str(exc))
            return []

    def count(self) -> int:
        if not self._ensure_store():
            return 0
        try:
            return self._store.count()
        except Exception:
            return 0


_knowledge_base: KnowledgeBase | None = None


def get_knowledge_base() -> KnowledgeBase:
    global _knowledge_base
    if _knowledge_base is None:
        from sentinelforge.core.config import get_settings
        _knowledge_base = KnowledgeBase(get_settings().vector_db_path)
    return _knowledge_base


def reset_knowledge_base() -> None:
    global _knowledge_base
    _knowledge_base = None

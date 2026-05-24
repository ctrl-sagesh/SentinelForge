"""ChromaDB-based vector store for threat knowledge and RAG."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sentinelforge.core.logging import get_logger

logger = get_logger("knowledge.vector_store")


class ThreatKnowledgeBase:
    """Vector store for threat intelligence, MITRE ATT&CK, and incident history."""

    def __init__(self, persist_dir: str = "./data/vector_db") -> None:
        self._persist_dir = persist_dir
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        self._client = None
        self._collection = None

    def _ensure_client(self) -> None:
        if self._client is not None:
            return
        try:
            import chromadb

            self._client = chromadb.PersistentClient(path=self._persist_dir)
            self._collection = self._client.get_or_create_collection(
                name="threat_knowledge",
                metadata={"hnsw:space": "cosine"},
            )
        except ImportError as exc:
            raise RuntimeError("Install chromadb: pip install chromadb") from exc

    def add_knowledge(
        self,
        documents: list[str],
        metadatas: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
    ) -> None:
        """Add threat knowledge documents to the vector store."""
        self._ensure_client()
        if ids is None:
            import uuid
            ids = [str(uuid.uuid4()) for _ in documents]

        self._collection.add(
            documents=documents,
            metadatas=metadatas or [{}] * len(documents),
            ids=ids,
        )
        logger.info("knowledge_added", count=len(documents))

    def query(
        self, query_text: str, n_results: int = 5
    ) -> list[dict[str, Any]]:
        """Query the knowledge base for relevant threat intelligence."""
        self._ensure_client()
        results = self._collection.query(
            query_texts=[query_text],
            n_results=n_results,
        )

        entries = []
        if results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                entries.append({
                    "document": doc,
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results["distances"] else 0,
                    "id": results["ids"][0][i] if results["ids"] else "",
                })
        return entries

    def seed_mitre_attack(self) -> None:
        """Seed the knowledge base with core MITRE ATT&CK technique descriptions."""
        techniques = [
            ("T1110", "Brute Force", "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or obtained."),
            ("T1046", "Network Service Discovery", "Adversaries may scan for services running on remote hosts to identify potential targets."),
            ("T1548", "Abuse Elevation Control Mechanism", "Adversaries may circumvent mechanisms designed to control elevated privileges."),
            ("T1048", "Exfiltration Over Alternative Protocol", "Adversaries may steal data by exfiltrating it over a different protocol than C2."),
            ("T1059", "Command and Scripting Interpreter", "Adversaries may abuse command and script interpreters to execute commands."),
            ("T1021", "Remote Services", "Adversaries may use valid accounts to log into a service that accepts remote connections such as SSH, RDP, SMB."),
            ("T1003", "OS Credential Dumping", "Adversaries may dump credentials to obtain account login and credential material."),
            ("T1071", "Application Layer Protocol", "Adversaries may communicate using standard application layer protocols to avoid detection."),
            ("T1486", "Data Encrypted for Impact", "Adversaries may encrypt data on target systems to interrupt availability (ransomware)."),
            ("T1566", "Phishing", "Adversaries may send phishing messages to gain access to victim systems."),
        ]

        documents = [f"{tid} - {name}: {desc}" for tid, name, desc in techniques]
        metadatas = [{"technique_id": tid, "name": name} for tid, name, _ in techniques]
        ids = [f"mitre_{tid}" for tid, _, _ in techniques]

        self.add_knowledge(documents, metadatas, ids)
        logger.info("mitre_attack_seeded", count=len(techniques))

    def count(self) -> int:
        self._ensure_client()
        return self._collection.count()

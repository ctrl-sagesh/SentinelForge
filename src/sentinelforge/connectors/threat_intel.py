"""Threat intelligence connectors — OTX, MISP, and local DB."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from sentinelforge.core.logging import get_logger

logger = get_logger("connector.threat_intel")


class ThreatIntelConnector(ABC):
    """Base class for threat intelligence feeds."""

    @abstractmethod
    async def lookup_ioc(self, ioc: str, ioc_type: str = "ip") -> dict[str, Any]:
        """Look up an indicator of compromise."""
        ...

    @abstractmethod
    async def get_pulses(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent threat intelligence pulses/events."""
        ...


class OTXConnector(ThreatIntelConnector):
    """AlienVault OTX threat intelligence connector."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key
        self._headers = {"X-OTX-API-KEY": api_key} if api_key else {}

    async def lookup_ioc(self, ioc: str, ioc_type: str = "ip") -> dict[str, Any]:
        endpoint_map = {
            "ip": f"/indicators/IPv4/{ioc}/general",
            "domain": f"/indicators/domain/{ioc}/general",
            "hash": f"/indicators/file/{ioc}/general",
            "url": f"/indicators/url/{ioc}/general",
        }

        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return {"error": f"Unknown IOC type: {ioc_type}"}

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.BASE_URL}{endpoint}",
                    headers=self._headers,
                )
                resp.raise_for_status()
                data = resp.json()
                return {
                    "source": "otx",
                    "ioc": ioc,
                    "type": ioc_type,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_name", ""),
                    "malicious": data.get("pulse_info", {}).get("count", 0) > 0,
                }
        except Exception as exc:
            logger.warning("otx_lookup_failed", ioc=ioc, error=str(exc))
            return {"source": "otx", "ioc": ioc, "error": str(exc)}

    async def get_pulses(self, limit: int = 10) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self.BASE_URL}/pulses/subscribed",
                    headers=self._headers,
                    params={"limit": limit},
                )
                resp.raise_for_status()
                return resp.json().get("results", [])
        except Exception as exc:
            logger.warning("otx_pulses_failed", error=str(exc))
            return []


class LocalThreatDB(ThreatIntelConnector):
    """Local JSON-based threat intelligence database for air-gapped deployments."""

    def __init__(self, db_path: str = "./data/threat_db.json") -> None:
        self._db_path = db_path
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        import json
        from pathlib import Path

        path = Path(self._db_path)
        if path.exists():
            with open(path) as f:
                self._data = json.load(f)

    async def lookup_ioc(self, ioc: str, ioc_type: str = "ip") -> dict[str, Any]:
        iocs = self._data.get("iocs", {})
        entry = iocs.get(ioc)
        if entry:
            return {
                "source": "local_db",
                "ioc": ioc,
                "type": ioc_type,
                "malicious": entry.get("malicious", False),
                "tags": entry.get("tags", []),
                "last_seen": entry.get("last_seen", ""),
            }
        return {"source": "local_db", "ioc": ioc, "found": False}

    async def get_pulses(self, limit: int = 10) -> list[dict[str, Any]]:
        return self._data.get("pulses", [])[:limit]

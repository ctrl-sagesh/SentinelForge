"""SIEM connectors — Elasticsearch/ELK, Splunk stubs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from sentinelforge.core.logging import get_logger

logger = get_logger("connector.siem")


class SIEMConnector(ABC):
    @abstractmethod
    async def query_logs(self, query: str, time_range: str = "15m") -> list[dict[str, Any]]:
        ...

    @abstractmethod
    async def push_alert(self, alert: dict[str, Any]) -> bool:
        ...


class ElasticsearchConnector(SIEMConnector):
    """Elasticsearch / OpenSearch connector for log queries and alert ingestion."""

    def __init__(self, url: str = "http://localhost:9200", api_key: str = "") -> None:
        self._url = url.rstrip("/")
        self._headers: dict[str, str] = {}
        if api_key:
            self._headers["Authorization"] = f"ApiKey {api_key}"

    async def query_logs(self, query: str, time_range: str = "15m") -> list[dict[str, Any]]:
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query}}],
                    "filter": [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}],
                }
            },
            "size": 100,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{self._url}/_search",
                    json=body,
                    headers=self._headers,
                )
                resp.raise_for_status()
                hits = resp.json().get("hits", {}).get("hits", [])
                return [h["_source"] for h in hits]
        except Exception as exc:
            logger.warning("elasticsearch_query_failed", error=str(exc))
            return []

    async def push_alert(self, alert: dict[str, Any]) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{self._url}/sentinelforge-alerts/_doc",
                    json=alert,
                    headers=self._headers,
                )
                return resp.status_code in (200, 201)
        except Exception as exc:
            logger.warning("elasticsearch_push_failed", error=str(exc))
            return False


class NullSIEM(SIEMConnector):
    """No-op SIEM for standalone / simulation deployments."""

    async def query_logs(self, query: str, time_range: str = "15m") -> list[dict[str, Any]]:
        return []

    async def push_alert(self, alert: dict[str, Any]) -> bool:
        logger.debug("null_siem_alert", alert_keys=list(alert.keys()))
        return True

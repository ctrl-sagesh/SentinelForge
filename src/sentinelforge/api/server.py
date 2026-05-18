"""FastAPI server — REST API for SentinelForge with auth and rate limiting."""

from __future__ import annotations

import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from sentinelforge.core.audit import get_audit_logger
from sentinelforge.core.config import get_settings
from sentinelforge.core.health import get_health_monitor
from sentinelforge.core.logging import get_logger, setup_logging
from sentinelforge.core.models import OrchestratorState, ThreatEvent
from sentinelforge.core.orchestrator import run_defense_cycle
from sentinelforge.core.safety import get_safety_engine

logger = get_logger("api")

# --- Rate Limiting Middleware ---

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        cutoff = now - self.window

        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if t > cutoff
        ]

        if len(self._requests[client_ip]) >= self.max_requests:
            logger.warning("rate_limit_hit", client=client_ip)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
            )

        self._requests[client_ip].append(now)
        response = await call_next(request)
        return response


# --- Request Size Middleware ---

class RequestSizeMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size_kb: int = 1024):
        super().__init__(app)
        self.max_bytes = max_size_kb * 1024

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
        return await call_next(request)


# --- Auth Dependencies ---

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    api_key: str | None = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    """Authenticate via API key or JWT bearer token."""
    settings = get_settings()
    if not settings.auth.enabled:
        return {"username": "anonymous", "role": "admin", "permissions": set()}

    from sentinelforge.core.auth import get_auth_manager

    auth_mgr = get_auth_manager()
    if auth_mgr is None:
        raise HTTPException(status_code=500, detail="Auth not initialized")

    if api_key:
        user = auth_mgr.verify_api_key(api_key)
        if user:
            return user

    if bearer:
        user = auth_mgr.verify_token(bearer.credentials)
        if user:
            return user

    raise HTTPException(
        status_code=401,
        detail="Invalid or missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_permission(permission: str):
    """Dependency factory to check a specific permission."""
    async def checker(user=Depends(get_current_user)):
        settings = get_settings()
        if not settings.auth.enabled:
            return user
        if hasattr(user, "permissions") and permission not in user.permissions:
            raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
        return user
    return checker


# --- App Setup ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(debug=settings.debug)

    if settings.auth.enabled and settings.auth.jwt_secret:
        from sentinelforge.core.auth import init_auth_manager
        init_auth_manager(settings.auth.jwt_secret)
        logger.info("auth_initialized")

    logger.info("api_startup", environment=settings.environment)
    yield
    logger.info("api_shutdown")


app = FastAPI(
    title="SentinelForge API",
    description="Autonomous AI Cyber Defense Agent Framework",
    version="0.4.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

settings = get_settings()

app.add_middleware(RateLimitMiddleware, max_requests=settings.api.rate_limit_per_minute)
app.add_middleware(RequestSizeMiddleware, max_size_kb=settings.api.max_request_size_kb)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --- Request/Response Models ---

class EventSubmission(BaseModel):
    source: str = "api"
    event_type: str
    description: str = Field(..., max_length=2000)
    severity: str = "medium"
    raw_data: dict[str, Any] = {}
    source_ip: str = Field("", max_length=45)
    dest_ip: str = Field("", max_length=45)
    hostname: str = Field("", max_length=255)


class DefenseCycleRequest(BaseModel):
    events: list[EventSubmission] = Field(default_factory=list, max_length=100)
    use_llm: bool = False


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=100)
    password: str = Field(..., max_length=200)


class InjectionCheckRequest(BaseModel):
    text: str = Field(..., max_length=5000)


# --- Endpoints ---

@app.get("/health")
async def health():
    """Health check endpoint — no auth required."""
    hm = get_health_monitor()
    status = hm.check()
    return {
        "status": "healthy" if status.healthy else "degraded",
        "version": "0.4.0",
        "uptime_seconds": round(status.uptime_seconds, 1),
        "cpu_percent": status.cpu_percent,
        "memory_percent": status.memory_percent,
        "warnings": status.warnings,
    }


@app.post("/api/v1/auth/login")
async def login(request: LoginRequest):
    """Authenticate and receive a JWT token."""
    settings = get_settings()
    if not settings.auth.enabled:
        return {"token": "auth_disabled", "message": "Authentication is not enabled"}

    from sentinelforge.core.auth import Role, get_auth_manager
    auth_mgr = get_auth_manager()
    if auth_mgr is None:
        raise HTTPException(status_code=500, detail="Auth not initialized")

    if request.username == "admin" and request.password == settings.auth.dashboard_password:
        token = auth_mgr.create_token(request.username, Role.ADMIN)
        return {"token": token, "role": "admin", "expires_in": settings.auth.token_expiry_seconds}

    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/v1/events")
async def submit_event(event: EventSubmission, user=Depends(require_permission("write:events"))):
    """Submit a security event for analysis."""
    from sentinelforge.agents.monitor import MonitorAgent

    engine = get_safety_engine()
    sanitized_desc = engine.sanitize_input(event.description)
    if sanitized_desc.startswith("[SANITIZED"):
        logger.warning("injection_in_event", source=event.source)
        raise HTTPException(status_code=400, detail="Prompt injection detected in event description")

    monitor = MonitorAgent()
    result = monitor.analyze_raw_event(event.model_dump())
    if result:
        return {"status": "threat_detected", "event": result.model_dump()}
    return {"status": "clean", "message": "No anomalies detected"}


@app.post("/api/v1/defend")
async def run_defense(request: DefenseCycleRequest, user=Depends(require_permission("execute:defend"))):
    """Run a full defense cycle with optional pre-loaded events."""
    from sentinelforge.core.models import Severity

    state = OrchestratorState()

    for ev in request.events:
        state.events.append(
            ThreatEvent(
                source=ev.source,
                event_type=ev.event_type,
                description=ev.description,
                severity=Severity(ev.severity),
                raw_data=ev.raw_data,
                source_ip=ev.source_ip,
                dest_ip=ev.dest_ip,
                hostname=ev.hostname,
            )
        )

    result = await run_defense_cycle(
        initial_state=state,
        use_llm=request.use_llm,
    )

    return {
        "events_detected": len(result.events),
        "investigations": len(result.investigations),
        "actions_proposed": len(result.proposed_actions),
        "actions_executed": len(result.executed_actions),
        "reports": len(result.reports),
        "safety_violations": result.safety_violations,
        "human_escalations": result.human_escalations,
        "reports_detail": [r.model_dump() for r in result.reports],
    }


@app.get("/api/v1/audit")
async def get_audit_log(limit: int = 50, user=Depends(require_permission("read:audit"))):
    """Retrieve recent audit log entries."""
    import json
    from pathlib import Path

    if limit > 500:
        limit = 500

    audit = get_audit_logger()
    path = Path(audit._path)
    if not path.exists():
        return {"entries": [], "total": 0}

    entries = []
    with open(path) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return {"entries": entries[-limit:], "total": len(entries)}


@app.get("/api/v1/audit/verify")
async def verify_audit_chain(user=Depends(require_permission("read:audit"))):
    """Verify the integrity of the audit log chain."""
    audit = get_audit_logger()
    valid, count = audit.verify_chain()
    return {"valid": valid, "entries_verified": count}


@app.get("/api/v1/safety/rules")
async def get_safety_rules(user=Depends(require_permission("read:health"))):
    """Get the constitutional safety rules."""
    from sentinelforge.core.safety import CONSTITUTIONAL_RULES

    settings = get_settings()
    return {
        "constitutional_rules": CONSTITUTIONAL_RULES,
        "allowed_actions": settings.safety.allowed_containment_actions,
        "blocked_actions": settings.safety.blocked_actions,
        "human_approval_required": settings.safety.human_approval_required,
        "sandbox_mode": settings.safety.sandbox_mode,
    }


@app.post("/api/v1/safety/check-injection")
async def check_injection(request: InjectionCheckRequest, user=Depends(require_permission("read:health"))):
    """Check if text contains prompt injection patterns."""
    engine = get_safety_engine()
    detected = engine.detect_prompt_injection(request.text)
    return {"text": request.text[:100], "injection_detected": detected}


@app.get("/api/v1/system/resources")
async def get_resources(user=Depends(require_permission("read:health"))):
    """Get system resource usage."""
    hm = get_health_monitor()
    return hm.get_resource_snapshot()


def create_app() -> FastAPI:
    return app

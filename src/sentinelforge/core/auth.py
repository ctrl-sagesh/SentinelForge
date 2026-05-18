"""Authentication and authorization — JWT tokens, API keys, and RBAC.

Provides middleware and dependencies for FastAPI to enforce authentication
on all API endpoints. Supports two modes:
  1. API key (header: X-API-Key) — for service-to-service calls
  2. JWT bearer token (header: Authorization: Bearer <token>) — for users
"""

from __future__ import annotations

import hashlib
import secrets
import time
from enum import Enum

import jwt
from pydantic import BaseModel, Field

from sentinelforge.core.logging import get_logger

logger = get_logger("auth")

JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_SECONDS = 3600


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.VIEWER: {"read:events", "read:reports", "read:audit", "read:health"},
    Role.ANALYST: {
        "read:events", "read:reports", "read:audit", "read:health",
        "write:events", "execute:defend", "write:approve",
    },
    Role.ADMIN: {
        "read:events", "read:reports", "read:audit", "read:health",
        "write:events", "execute:defend", "write:approve",
        "admin:settings", "admin:users", "admin:safety",
    },
}


class AuthUser(BaseModel):
    username: str
    role: Role = Role.VIEWER
    permissions: set[str] = Field(default_factory=set)


class APIKeyRecord(BaseModel):
    key_hash: str
    name: str
    role: Role = Role.VIEWER
    created_at: float = Field(default_factory=time.time)
    active: bool = True


class AuthManager:
    """Manages JWT tokens and API key validation."""

    def __init__(self, secret_key: str, api_keys: dict[str, APIKeyRecord] | None = None) -> None:
        if len(secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")
        self._secret = secret_key
        self._api_keys: dict[str, APIKeyRecord] = api_keys or {}

    def create_token(self, username: str, role: Role) -> str:
        now = time.time()
        payload = {
            "sub": username,
            "role": role.value,
            "iat": now,
            "exp": now + TOKEN_EXPIRY_SECONDS,
            "jti": secrets.token_hex(8),
        }
        return jwt.encode(payload, self._secret, algorithm=JWT_ALGORITHM)

    def verify_token(self, token: str) -> AuthUser | None:
        try:
            payload = jwt.decode(token, self._secret, algorithms=[JWT_ALGORITHM])
            role = Role(payload["role"])
            return AuthUser(
                username=payload["sub"],
                role=role,
                permissions=ROLE_PERMISSIONS.get(role, set()),
            )
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, KeyError, ValueError):
            return None

    def register_api_key(self, name: str, role: Role = Role.VIEWER) -> str:
        raw_key = f"sf_{secrets.token_hex(24)}"
        key_hash = self._hash_key(raw_key)
        self._api_keys[key_hash] = APIKeyRecord(
            key_hash=key_hash,
            name=name,
            role=role,
        )
        logger.info("api_key_created", name=name, role=role.value)
        return raw_key

    def verify_api_key(self, raw_key: str) -> AuthUser | None:
        key_hash = self._hash_key(raw_key)
        record = self._api_keys.get(key_hash)
        if record is None or not record.active:
            return None
        role = record.role
        return AuthUser(
            username=f"apikey:{record.name}",
            role=role,
            permissions=ROLE_PERMISSIONS.get(role, set()),
        )

    def revoke_api_key(self, raw_key: str) -> bool:
        key_hash = self._hash_key(raw_key)
        record = self._api_keys.get(key_hash)
        if record is None:
            return False
        record.active = False
        logger.info("api_key_revoked", name=record.name)
        return True

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def generate_secret_key() -> str:
        return secrets.token_hex(32)


_auth_manager: AuthManager | None = None


def get_auth_manager() -> AuthManager | None:
    return _auth_manager


def init_auth_manager(secret_key: str) -> AuthManager:
    global _auth_manager
    _auth_manager = AuthManager(secret_key)
    return _auth_manager

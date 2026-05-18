"""Tests for authentication and authorization."""

import time

import pytest

from sentinelforge.core.auth import ROLE_PERMISSIONS, AuthManager, Role


@pytest.fixture
def auth():
    return AuthManager(secret_key="a" * 64)


class TestJWT:
    def test_create_and_verify_token(self, auth):
        token = auth.create_token("alice", Role.ANALYST)
        user = auth.verify_token(token)
        assert user is not None
        assert user.username == "alice"
        assert user.role == Role.ANALYST

    def test_expired_token_rejected(self, auth):
        import jwt as pyjwt

        payload = {
            "sub": "alice",
            "role": "analyst",
            "iat": time.time() - 7200,
            "exp": time.time() - 3600,
            "jti": "test",
        }
        token = pyjwt.encode(payload, "a" * 64, algorithm="HS256")
        assert auth.verify_token(token) is None

    def test_invalid_token_rejected(self, auth):
        assert auth.verify_token("garbage.token.here") is None

    def test_wrong_secret_rejected(self, auth):
        token = auth.create_token("alice", Role.ADMIN)
        other = AuthManager(secret_key="b" * 64)
        assert other.verify_token(token) is None

    def test_role_permissions_populated(self, auth):
        token = auth.create_token("admin", Role.ADMIN)
        user = auth.verify_token(token)
        assert "admin:settings" in user.permissions
        assert "execute:defend" in user.permissions


class TestAPIKeys:
    def test_create_and_verify_key(self, auth):
        raw_key = auth.register_api_key("test-service", Role.VIEWER)
        assert raw_key.startswith("sf_")
        user = auth.verify_api_key(raw_key)
        assert user is not None
        assert user.role == Role.VIEWER

    def test_invalid_key_rejected(self, auth):
        assert auth.verify_api_key("sf_invalid_key") is None

    def test_revoked_key_rejected(self, auth):
        raw_key = auth.register_api_key("ephemeral", Role.ANALYST)
        assert auth.verify_api_key(raw_key) is not None
        assert auth.revoke_api_key(raw_key) is True
        assert auth.verify_api_key(raw_key) is None

    def test_revoke_nonexistent_key(self, auth):
        assert auth.revoke_api_key("sf_doesnt_exist") is False


class TestRBAC:
    def test_viewer_cannot_execute(self):
        perms = ROLE_PERMISSIONS[Role.VIEWER]
        assert "execute:defend" not in perms
        assert "read:events" in perms

    def test_analyst_can_execute(self):
        perms = ROLE_PERMISSIONS[Role.ANALYST]
        assert "execute:defend" in perms
        assert "admin:settings" not in perms

    def test_admin_has_all(self):
        perms = ROLE_PERMISSIONS[Role.ADMIN]
        assert "admin:settings" in perms
        assert "execute:defend" in perms
        assert "read:events" in perms


class TestSecretKeyValidation:
    def test_short_key_rejected(self):
        with pytest.raises(ValueError, match="at least 32"):
            AuthManager(secret_key="short")

    def test_valid_key_accepted(self):
        mgr = AuthManager(secret_key="x" * 32)
        assert mgr is not None

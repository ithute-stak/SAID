"""Fail-closed institutional role and token boundary regression tests."""
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from said.security import Principal, allowed, current_principal, verify_access_token

def req(headers: dict[str, str]) -> Request:
    return Request({"type": "http", "method": "GET", "path": "/",
                    "headers": [(k.lower().encode(), v.encode()) for k,v in headers.items()]})

def test_development_admin_key_is_not_accepted_in_production(monkeypatch):
    monkeypatch.setenv("SAID_ENVIRONMENT", "production")
    monkeypatch.setenv("SAID_ADMIN_API_KEY", "test-secret-that-is-at-least-32-characters")
    with pytest.raises(HTTPException) as exc:
        current_principal(req({"X-Admin-Key": "test-secret-that-is-at-least-32-characters"}))
    assert exc.value.status_code == 401

def test_dev_key_allowed_only_in_dev(monkeypatch):
    monkeypatch.setenv("SAID_ENVIRONMENT", "development")
    monkeypatch.setenv("SAID_ADMIN_API_KEY", "test-secret-that-is-at-least-32-characters")
    p = current_principal(req({"X-Admin-Key": "test-secret-that-is-at-least-32-characters"}))
    assert p.subject == "development-admin"

def test_role_denial(monkeypatch):
    monkeypatch.setenv("SAID_ENVIRONMENT", "production")
    with patch("said.security.verify_access_token",
               return_value=Principal("employee-1", frozenset({"registrar"}), "operator-a")):
        with pytest.raises(HTTPException) as exc:
            allowed(req({"Authorization": "Bearer valid-token"}), "owner_reviewer")
    assert exc.value.status_code == 403

def test_missing_oidc_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("SAID_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("SAID_OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("SAID_OIDC_JWKS_URL", raising=False)
    with pytest.raises(HTTPException) as exc:
        verify_access_token("bad-token")
    assert exc.value.status_code == 503

def test_invalid_jwt_not_accepted(monkeypatch):
    monkeypatch.setenv("SAID_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("SAID_OIDC_AUDIENCE", "said-api")
    monkeypatch.setenv("SAID_OIDC_JWKS_URL", "https://issuer.example/keys")
    with patch("said.security.PyJWKClient") as jwks:
        from jwt.exceptions import InvalidTokenError
        jwks.return_value.get_signing_key_from_jwt.side_effect = InvalidTokenError("invalid")
        with pytest.raises(HTTPException) as exc:
            verify_access_token("bad-token")
    assert exc.value.status_code == 401

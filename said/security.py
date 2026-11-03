"""Institutional authentication boundary.

In production, access tokens require externally verifiable OIDC JWT signatures.
The legacy admin key is accepted only in development/test environments.
"""
from dataclasses import dataclass
import hmac
import os

import jwt
from jwt import PyJWKClient
from fastapi import HTTPException, Request

@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    institution: str

def _environment() -> str:
    return os.getenv("SAID_ENVIRONMENT", "development").lower()

def _oidc_config() -> tuple[str, str, str]:
    return (os.getenv("SAID_OIDC_ISSUER", ""),
            os.getenv("SAID_OIDC_AUDIENCE", ""),
            os.getenv("SAID_OIDC_JWKS_URL", ""))

def verify_access_token(token: str) -> Principal:
    issuer, audience, jwks_url = _oidc_config()
    if not all((issuer, audience, jwks_url)):
        raise HTTPException(status_code=503, detail="Institutional identity provider not configured")
    try:
        # OIDC provider configuration is supplied by trusted server deployment.
        signing_key = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300).get_signing_key_from_jwt(token)
        claims = jwt.decode(token, signing_key.key, algorithms=["RS256", "ES256"],
                            audience=audience, issuer=issuer,
                            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
                            leeway=30)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid access token") from None
    except Exception:
        raise HTTPException(status_code=503, detail="Identity provider keys unavailable") from None
    roles = claims.get("said_roles")
    institution = claims.get("said_institution")
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        raise HTTPException(status_code=403, detail="Missing institutional roles")
    if not isinstance(institution, str) or not institution.strip():
        raise HTTPException(status_code=403, detail="Missing institutional affiliation")
    return Principal(subject=claims["sub"], roles=frozenset(roles), institution=institution)

def current_principal(request: Request) -> Principal:
    api_key = request.headers.get("X-Admin-Key")
    if api_key and _environment() in {"development", "test"}:
        configured = os.getenv("SAID_ADMIN_API_KEY", "")
        if len(configured) >= 32 and hmac.compare_digest(configured, api_key):
            return Principal(subject="development-admin", roles=frozenset({
                "said_admin", "owner_reviewer", "registrar", "case_worker"
            }), institution="development-only")
    auth = request.headers.get("Authorization", "")
    scheme, _, bearer = auth.partition(" ")
    if scheme.lower() != "bearer" or not bearer.strip():
        raise HTTPException(status_code=401, detail="Bearer token required")
    return verify_access_token(bearer.strip())

def allowed(request: Request, *required_roles: str) -> Principal:
    principal = current_principal(request)
    if not (principal.roles & set(required_roles)):
        raise HTTPException(status_code=403, detail="Insufficient SAID role")
    return principal

"""Isolated staging container entrypoint. No migrations or deploy actions.

Read a locally mounted PostgreSQL password file and launch the API only when
the sealed staging prerequisites are present. Never prints credentials.
"""
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote


def configuration(environ: dict[str, str], secret: str) -> dict[str, str]:
    if environ.get("SAID_ENVIRONMENT") != "staging":
        raise ValueError("Only staging is permitted")
    if environ.get("SAID_ADMIN_API_KEY"):
        raise ValueError("Legacy admin-key auth forbidden in staging")
    if not all(environ.get(x) for x in ("SAID_OIDC_ISSUER", "SAID_OIDC_AUDIENCE", "SAID_OIDC_JWKS_URL")):
        raise ValueError("OIDC verification parameters required")
    issuer = environ["SAID_OIDC_ISSUER"]
    jwks = environ["SAID_OIDC_JWKS_URL"]
    if not issuer.startswith("https://") or not jwks.startswith("https://"):
        raise ValueError("OIDC endpoints must use HTTPS")
    if not re.fullmatch(r"[A-Za-z0-9_]{1,63}", environ.get("SAID_STAGING_DB_USER", "")):
        raise ValueError("Invalid staging database user")
    if not re.fullmatch(r"[A-Za-z0-9_]{1,63}", environ.get("SAID_STAGING_DB_NAME", "")):
        raise ValueError("Invalid staging database name")
    if len(secret) < 24 or len(secret) > 512 or any(c in secret for c in "\r\n\x00"):
        raise ValueError("Invalid database credential file")
    if environ.get("SAID_DATABASE_URL"):
        raise ValueError("Database URL must come from mounted secret, not environment")
    return {
        "SAID_DATABASE_URL": (
            "postgresql+psycopg://" + environ["SAID_STAGING_DB_USER"] + ":" +
            quote(secret, safe="") + "@postgres:5432/" + environ["SAID_STAGING_DB_NAME"]
        )
    }


def main():
    try:
        path = Path("/run/secrets/pg_password")
        if not path.is_file() or path.stat().st_size > 513:
            raise ValueError("Missing or oversized staging database secret")
        secret = path.read_text(encoding="utf-8").strip()
        config = configuration(dict(os.environ), secret)
    except (OSError, UnicodeError, ValueError):
        print("SAID staging preflight rejected configuration", file=sys.stderr)
        raise SystemExit(2) from None
    os.environ.update(config)
    # No database schema modifications and no production traffic.
    os.execvp("uvicorn", ["uvicorn", "said.main:app", "--host", "0.0.0.0",
                          "--port", "8000", "--no-proxy-headers"])


if __name__ == "__main__":
    main()

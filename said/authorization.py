"""Fail-closed institutional and record authorization.

Institution values come from authenticated server-verified principals only,
never request bodies, URLs, or untrusted X-Institution headers.
"""
from fastapi import HTTPException
from said.security import Principal

CENTRAL_INSTITUTION = "said-central"

def central_admin(principal: Principal) -> bool:
    return ("said_admin" in principal.roles
            and principal.institution in {CENTRAL_INSTITUTION, "development-only"})

def require_role(principal: Principal, *roles: str) -> None:
    if not (principal.roles & set(roles)):
        raise HTTPException(status_code=403, detail="Insufficient SAID role")

def require_institution(principal: Principal, record_institution: str | None) -> None:
    # NULL legacy records are restricted to central admins until formally assigned.
    if central_admin(principal):
        return
    if not record_institution or principal.institution != record_institution:
        # Avoid ID enumeration: inaccessible and nonexistent records look the same.
        raise HTTPException(status_code=404, detail="Record not found")

def registration_institution(principal: Principal) -> str:
    if not principal.institution or principal.institution == "development-only":
        # Development-only registration data is explicitly scoped to a separate realm.
        return "development-only"
    return principal.institution

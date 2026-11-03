# Phase 5 institution and record isolation

- The authenticated JWT `said_institution` claim is the only source of institutional scope.
- A registrar creates device records in their own institution. Supplying an
  `institution_id` in JSON does not override this scope.
- Devices, associated theft reports, and ownership claims are only accessible
  to authorized roles in the same institution.
- Privileged national cross-institution access is **not** conferred by the
  `said_admin` role alone: the institution must also be `said-central`.
- The development admin key creates records in the isolated
  `development-only` scope and is disabled in production.
- Existing database records are migrated with NULL institution_id and
  remain inaccessible to institutional users until independently reviewed
  and deliberately assigned by a later audited migration/workflow.
- Inaccessible records respond with 404 to avoid leaking existence.
- Role and institution checks are both required. A case worker cannot create
  ownership claims merely because they belong to a registered institution.

## Important limitations

This phase is **API-level isolation**, not yet PostgreSQL row-level security.
An internal database superuser or a future background job could bypass it.
A vetted institutional enrollment directory, explicit auditor role, verified
organization membership, JWT role issuer policy, judicial/legal disclosure
path, tamper-evident audit logs, owner-level authorization, and PostgreSQL RLS
are required before a national multi-organization production deployment.

Operators do not receive access to each other's device observations. No
live operator feeds, identity verification or IMEI network blocking exists.

"""Bind server-verified institutional context to each SQLAlchemy transaction.

Never accept tenant or central authority from an HTTP header or request payload.
PostgreSQL settings are LOCAL to the transaction; pooled connections must not
retain a previous request's institution.
"""
from sqlalchemy import event, text
from sqlalchemy.orm import Session
from said.authorization import central_admin
from said.security import Principal

@event.listens_for(Session, "after_begin")
def attach_rls_context(session: Session, transaction, connection):
    if connection.dialect.name != "postgresql":
        return
    actor: Principal | None = session.info.get("said_principal")
    if actor is None:
        # A missing identity gets no tenant or elevated context, rather
        # than inheriting anything from an earlier pooled connection.
        connection.execute(text("SELECT set_config('said.institution', '', true)"))
        connection.execute(text("SELECT set_config('said.central', 'false', true)"))
        connection.execute(text("SELECT set_config('said.subject', '', true)"))
        return
    connection.execute(
        text("SELECT set_config('said.institution', :institution, true)"),
        {"institution": actor.institution},
    )
    connection.execute(
        text("SELECT set_config('said.subject', :subject, true)"),
        {"subject": actor.subject},
    )
    connection.execute(
        text("SELECT set_config('said.central', :central, true)"),
        {"central": "true" if central_admin(actor) else "false"},
    )

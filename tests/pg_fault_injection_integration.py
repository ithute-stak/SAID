"""Phase 28 ephemeral PostgreSQL fault injection and rollback verification.

Never run against a populated or production database.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import select
from sqlalchemy.orm import Session

from said.main import engine
from said.ceir.governance import append_event, digest_of, lock_case, commit_case, ReviewLedger, ZERO_DIGEST
from said.ceir.quality import MockObservation, MockInvestigation
from said.ceir.appeals import MockAppeal
from said.security import Principal

assert engine.dialect.name == "postgresql"
assert os.environ.get("SAID_CONCURRENCY_TEST_DB") == "ephemeral-ci-only"
assert "said_ci" in engine.url.database

principal = Principal(subject="synthetic-phase28", institution="said-central",
                      roles=frozenset({"said_admin", "ceir_reviewer"}))


def session():
    db = Session(engine, expire_on_commit=False)
    db.info["said_principal"] = principal
    return db


observation = str(uuid.uuid4())
case_id = str(uuid.uuid4())
with session() as db:
    db.add(MockObservation(id=observation, source_code="mock_operator_alpha",
        reference="PH28_" + uuid.uuid4().hex, imei_token="f" * 64))
    db.flush()
    db.add(MockInvestigation(id=case_id, observation_id=observation,
        status="insufficient_evidence", opened_by="independent-opener",
        reviewer_reference="independent-reviewer",
        decision_reference="synthetic_decision"))
    db.flush()
    append_event(db, case_id, "investigation_opened",
                 "independent-opener", "synthetic_open")
    commit_case(db)


def assert_chain(db, expected):
    items = db.scalars(select(ReviewLedger).where(
        ReviewLedger.investigation_id == case_id).order_by(
        ReviewLedger.sequence)).all()
    assert len(items) == expected
    prev = ZERO_DIGEST
    for index, row in enumerate(items, start=1):
        assert row.sequence == index
        assert row.previous_digest == prev
        assert row.digest == digest_of(row)
        prev = row.digest


# Crash-like exception after flushing child state but before commit.
try:
    with session() as db:
        lock_case(db, case_id)
        db.add(MockAppeal(id=str(uuid.uuid4()), investigation_id=case_id,
            state="pending_supervisor", reason_reference="injected_uncommitted",
            submitted_by="synthetic-officer"))
        db.flush()
        append_event(db, case_id, "appeal_opened",
                     "synthetic-officer", "injected_uncommitted")
        db.flush()
        raise RuntimeError("synthetic-fault-before-commit")
except RuntimeError as exc:
    assert str(exc) == "synthetic-fault-before-commit"
else:
    raise AssertionError("Fault must have been triggered")

with session() as db:
    assert db.scalars(select(MockAppeal).where(
        MockAppeal.investigation_id == case_id)).all() == []
    assert_chain(db, 1)


# Multi-session case: only one submitted appeal; loser cannot append a ghost event.
gate = Barrier(4)

def competing_appeal(index):
    gate.wait(timeout=20)
    with session() as db:
        lock_case(db, case_id)
        previous = db.scalar(select(MockAppeal).where(
            MockAppeal.investigation_id == case_id))
        if previous is not None:
            db.rollback()
            return "conflict"
        db.add(MockAppeal(id=str(uuid.uuid4()), investigation_id=case_id,
            state="pending_supervisor", reason_reference="actual_appeal",
            submitted_by=f"officer-{index}"))
        db.flush()
        append_event(db, case_id, "appeal_opened", f"officer-{index}",
                     "actual_appeal")
        commit_case(db)
        return "created"

with ThreadPoolExecutor(max_workers=4) as pool:
    outcomes = list(pool.map(competing_appeal, range(4)))
assert outcomes.count("created") == 1, outcomes
assert outcomes.count("conflict") == 3, outcomes

with session() as db:
    assert len(db.scalars(select(MockAppeal).where(
        MockAppeal.investigation_id == case_id)).all()) == 1
    assert_chain(db, 2)

print("Phase 28 PostgreSQL fault-injection rollback and competing appeal stress passed")

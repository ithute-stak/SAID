"""Real PostgreSQL simultaneous writers: case ledger and review CAS.

Only run against the ephemeral GitHub Actions PostgreSQL service, never live.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from said.main import engine
from said.ceir.governance import append_event, digest_of, ReviewLedger, ZERO_DIGEST
from said.ceir.quality import MockInvestigation, MockObservation
from said.security import Principal

assert engine.dialect.name == "postgresql", "PostgreSQL-only integration test"
assert os.getenv("SAID_CONCURRENCY_TEST_DB") == "ephemeral-ci-only", "CI safety marker required"

central = Principal(subject="concurrency-officer", institution="said-central",
                    roles=frozenset({"said_admin", "ceir_reviewer"}))


def session():
    db = Session(engine, expire_on_commit=False)
    db.info["said_principal"] = central
    return db


case_id = str(uuid.uuid4())
obs_id = str(uuid.uuid4())
with session() as db:
    db.add(MockObservation(id=obs_id, source_code="mock_operator_alpha",
                           reference="PH26_" + uuid.uuid4().hex,
                           imei_token="a" * 64))
    db.flush()
    db.add(MockInvestigation(id=case_id, observation_id=obs_id,
                             status="pending_human_review", opened_by="different-opener"))
    db.flush()
    append_event(db, case_id, "investigation_opened",
                 "different-opener", "phase26_seed")
    db.commit()

# Concurrent writers are intentionally synchronized before transaction work.
writers = 7
gate = Barrier(writers)

def write(number: int):
    gate.wait(timeout=15)
    with session() as db:
        append_event(db, case_id, "phase26_concurrent_test",
                     f"synthetic-worker-{number}", f"phase26_{number}")
        db.commit()
    return number

with ThreadPoolExecutor(max_workers=writers) as pool:
    assert sorted(pool.map(write, range(writers))) == list(range(writers))

with session() as db:
    entries = db.scalars(select(ReviewLedger).where(
        ReviewLedger.investigation_id == case_id).order_by(ReviewLedger.sequence)).all()
    assert len(entries) == writers + 1
    previous = ZERO_DIGEST
    for expected_sequence, item in enumerate(entries, 1):
        assert item.sequence == expected_sequence
        assert item.previous_digest == previous
        assert item.digest == digest_of(item)
        previous = item.digest

# Two competing independent reviewers must not both transition the same case.
gate_review = Barrier(2)

def decide(number: int):
    gate_review.wait(timeout=15)
    with session() as db:
        changed = db.execute(update(MockInvestigation).where(
            MockInvestigation.id == case_id,
            MockInvestigation.status == "pending_human_review").values(
            status="insufficient_evidence",
            reviewer_reference=f"synthetic-reviewer-{number}",
            decision_reference=f"phase26_review_{number}"))
        if changed.rowcount:
            append_event(db, case_id, "review_insufficient_evidence",
                         f"synthetic-reviewer-{number}", f"phase26_review_{number}")
        db.commit()
        return changed.rowcount

with ThreadPoolExecutor(max_workers=2) as pool:
    outcomes = sorted(pool.map(decide, (1, 2)))
assert outcomes == [0, 1], outcomes

with session() as db:
    case = db.get(MockInvestigation, case_id)
    assert case.status == "insufficient_evidence"
    events = db.scalars(select(ReviewLedger).where(
        ReviewLedger.investigation_id == case_id).order_by(ReviewLedger.sequence)).all()
    assert len(events) == writers + 2
    assert sum(e.action == "review_insufficient_evidence" for e in events) == 1
    previous = ZERO_DIGEST
    for n, event in enumerate(events, 1):
        assert event.sequence == n and event.previous_digest == previous
        assert event.digest == digest_of(event)
        previous = event.digest

print("PostgreSQL concurrent ledger and reviewer CAS tests passed")

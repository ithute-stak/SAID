"""Phase 29: two simulated status proposals must not both win one revision.

Run only on isolated PostgreSQL CI. No operator interface is invoked.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from said.main import Device, engine
from said.ceir.models import CEIRSimulation, CEIRSimulationEvent
from said.security import Principal

assert engine.dialect.name == "postgresql"
assert engine.url.database == "said_ci"
assert os.environ.get("SAID_CONCURRENCY_TEST_DB") == "ephemeral-ci-only"

principal = Principal(subject="synthetic-revision-reviewer",
                      institution="said-central",
                      roles=frozenset({"said_admin"}))

def session():
    db = Session(engine, expire_on_commit=False)
    db.info["said_principal"] = principal
    return db

device_id = str(uuid.uuid4())
entry_id = str(uuid.uuid4())
with session() as db:
    db.add(Device(id=device_id, imei="490154203237526",
                  owner_reference="synthetic-test-only",
                  institution_id="said-central",
                  make="Synthetic", model="Test",
                  verification_status="unverified"))
    db.flush()
    db.add(CEIRSimulation(id=entry_id, device_id=device_id,
                          proposed_status="unassessed", revision=1))
    db.commit()

gate = Barrier(4)

def propose(i):
    gate.wait(timeout=20)
    with session() as db:
        changed = db.execute(update(CEIRSimulation).where(
            CEIRSimulation.id == entry_id, CEIRSimulation.revision == 1
        ).values(proposed_status="proposed_tracked",
                 revision=CEIRSimulation.revision + 1))
        if changed.rowcount != 1:
            db.rollback()
            return "conflict"
        db.add(CEIRSimulationEvent(
            id=str(uuid.uuid4()), simulation_id=entry_id,
            proposed_status="proposed_tracked", reason_reference=f"phase29_{i}",
            actor_reference=f"synthetic-reviewer-{i}"))
        db.commit()
        return "accepted"

with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(propose, range(4)))
assert results.count("accepted") == 1, results
assert results.count("conflict") == 3, results

with session() as db:
    entry = db.get(CEIRSimulation, entry_id)
    events = db.scalars(select(CEIRSimulationEvent).where(
        CEIRSimulationEvent.simulation_id == entry_id)).all()
    assert entry.revision == 2
    assert entry.proposed_status == "proposed_tracked"
    assert len(events) == 1

# Inject failure before commit: a status update and new event must both revert.
with session() as db:
    changed = db.execute(update(CEIRSimulation).where(
        CEIRSimulation.id == entry_id, CEIRSimulation.revision == 2
    ).values(proposed_status="proposed_blocked",
             revision=CEIRSimulation.revision + 1))
    assert changed.rowcount == 1
    db.add(CEIRSimulationEvent(
        id=str(uuid.uuid4()), simulation_id=entry_id,
        proposed_status="proposed_blocked", reason_reference="fault_injected",
        actor_reference="synthetic-reviewer"))
    db.flush()
    db.rollback()

with session() as db:
    entry = db.get(CEIRSimulation, entry_id)
    assert entry.revision == 2
    assert entry.proposed_status == "proposed_tracked"
    assert len(db.scalars(select(CEIRSimulationEvent).where(
        CEIRSimulationEvent.simulation_id == entry_id)).all()) == 1

print("Phase 29 concurrent revisions and paired event rollback passed")

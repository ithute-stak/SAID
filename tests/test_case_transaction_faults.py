"""Fail-closed transaction conflict classification and rollback tests."""
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError, OperationalError

from said.ceir.governance import commit_case


class DriverError(Exception):
    def __init__(self, code):
        super().__init__("synthetic driver failure")
        self.sqlstate = code


@pytest.mark.parametrize("code", ["40P01", "40001", "55P03"])
def test_known_transient_conflicts_roll_back_without_auto_retry(code):
    session = MagicMock()
    session.commit.side_effect = OperationalError(
        "synthetic", {}, DriverError(code))
    with pytest.raises(HTTPException) as error:
        commit_case(session)
    assert error.value.status_code == 409
    assert "re-evaluate" in error.value.detail
    session.commit.assert_called_once()
    session.rollback.assert_called_once()


def test_integrity_conflict_rolls_back_without_retry():
    session = MagicMock()
    session.commit.side_effect = IntegrityError(
        "synthetic", {}, DriverError("23505"))
    with pytest.raises(HTTPException) as error:
        commit_case(session)
    assert error.value.status_code == 409
    session.commit.assert_called_once()
    session.rollback.assert_called_once()


def test_unknown_database_failure_propagates_after_rollback():
    session = MagicMock()
    session.commit.side_effect = OperationalError(
        "synthetic", {}, DriverError("08006"))
    with pytest.raises(OperationalError):
        commit_case(session)
    session.commit.assert_called_once()
    session.rollback.assert_called_once()


def test_success_commits_once_without_rollback():
    session = MagicMock()
    commit_case(session)
    session.commit.assert_called_once()
    session.rollback.assert_not_called()

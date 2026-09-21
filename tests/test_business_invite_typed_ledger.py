"""BUSINESS invitations are unlimited locally and retained as audit rows."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlmodel import SQLModel, Session, create_engine

from api import gpt_business as business
from core.db import (
    GptBusinessAccountModel as Mother,
    GptBusinessRotationReservationModel as Reservation,
)

NOW = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'invites.db'}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine, tables=[Mother.__table__, Reservation.__table__])
    monkeypatch.setattr(business, "engine", engine)
    with Session(engine) as session:
        session.add(Mother(id=1, email="mother@example.test"))
        session.commit()
    yield engine
    engine.dispose()


def reserve(operation, count, kind="default", now=NOW):
    targets = [f"{operation}-{index}@example.test" for index in range(count)]
    business._reserve_business_invite_quota(
        1, operation, targets, seat_type=kind, now=now,
    )
    return targets


def consume(operation, targets, kind="default", now=NOW):
    return business._consume_business_invite_quota(
        1, operation, targets, seat_type=kind, now=now,
    )["invite_quota"]


def snapshot(engine, now=NOW, kind=None):
    with Session(engine) as session:
        return business._invite_quota(session, 1, now=now, seat_type=kind)


def test_more_than_old_window_limit_is_accepted_and_counted(ledger):
    targets = reserve("bulk", 12)
    before = snapshot(ledger)
    assert before["limited"] is False
    assert before["reserved"] == 12
    assert before["today_success_count"] == 0

    result = consume("bulk", targets)
    assert result["limited"] is False
    assert result["remaining"] > 1_000_000
    current = snapshot(ledger)
    assert current["today_success_count"] == 12
    assert current["total_success_count"] == 12
    assert current["by_type"]["default"]["total_success_count"] == 12


def test_daily_count_uses_asia_shanghai_calendar_day(ledger):
    before_midnight = datetime(2026, 9, 1, 15, 59, tzinfo=timezone.utc)
    after_midnight = before_midnight + timedelta(minutes=2)
    first = reserve("day-one", 1, now=before_midnight)
    consume("day-one", first, now=before_midnight)
    second = reserve("day-two", 2, kind="prolite", now=after_midnight)
    consume("day-two", second, kind="prolite", now=after_midnight)

    current = snapshot(ledger, now=after_midnight)
    assert current["today_success_count"] == 2
    assert current["total_success_count"] == 3
    assert current["by_type"]["default"]["today_success_count"] == 0
    assert current["by_type"]["prolite"]["today_success_count"] == 2
    assert current["day_timezone"] == "Asia/Shanghai"


def test_released_or_pending_rows_are_not_successes(ledger):
    pending = reserve("pending", 1)
    rejected = reserve("rejected", 1)
    business._release_business_invite_quota(
        1, "rejected", rejected, now=NOW, reason="remote_rejected",
    )
    current = snapshot(ledger)
    assert current["reserved"] == 1
    assert current["today_success_count"] == 0
    assert current["total_success_count"] == 0
    assert pending


def test_success_consumption_is_idempotent_and_operation_binding_is_fixed(ledger):
    targets = reserve("one", 1, kind="prolite")
    first = consume("one", targets, kind="prolite")
    second = consume("one", targets, kind="prolite")
    assert first["total_success_count"] == second["total_success_count"] == 1
    with pytest.raises(HTTPException):
        business._reserve_business_invite_quota(
            1, "one", targets, seat_type="default", now=NOW,
        )

from types import SimpleNamespace

import pytest
from fastapi import HTTPException


def test_batch_leave_resume_accepts_only_its_own_pending_operation(monkeypatch):
    from api import gpt_plans

    parent = SimpleNamespace(
        id=10, source_pool="gpt_business", source_account_id=20,
        email="mother@example.com",
    )
    source = SimpleNamespace(id=20, email="mother@example.com")
    membership = SimpleNamespace(
        id=30, business_account_id=20, pro_account_id=40,
        email="child@example.com", source="pool",
        remote_user_id="remote-user", remote_invite_id="",
        ended_at=None, intent_remote_started=True,
        end_reason="pending:remove", operation_id="batch-leave-owned",
    )
    child = SimpleNamespace(id=40, email="child@example.com", business_parent_id=20)
    rows = {
        (gpt_plans.GptPlanAccountModel, 10): parent,
        (gpt_plans.GptPlanAccountModel, 40): child,
        (gpt_plans.GptBusinessAccountModel, 20): source,
        (gpt_plans.GptBusinessChildMembershipModel, 30): membership,
    }

    class FakeSession:
        def __init__(self, _engine):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, model, identity):
            return rows.get((model, identity))

    monkeypatch.setattr(gpt_plans, "Session", FakeSession)
    target = {
        "membership_id": 30,
        "parent_account_id": 10,
        "source_account_id": 20,
        "parent_email": "mother@example.com",
        "child_id": 40,
        "email": "child@example.com",
        "source": "pool",
        "user_id": "remote-user",
        "invite_id": "",
        "operation_id": "batch-leave-owned",
    }
    assert gpt_plans._business_child_batch_leave_complete(target) is False

    target["operation_id"] = "batch-leave-other"
    with pytest.raises(HTTPException, match="另一项未确认"):
        gpt_plans._business_child_batch_leave_complete(target)


def test_child_batch_action_snapshot_is_durable(monkeypatch):
    from sqlalchemy.pool import StaticPool
    from sqlmodel import create_engine
    from services import business_child_batch_action_store as store

    isolated_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(store, "engine", isolated_engine)
    monkeypatch.setattr(store, "_initialized", False)
    task = {
        "task_id": "leave-batch-test",
        "action": "leave_workspace",
        "status": "pending",
        "items": [{"membership_id": 1, "target": {"operation_id": "stable-op"}}],
    }
    store.save(task)
    assert store.load(task["task_id"]) == task
    assert store.unfinished() == [task]

    task["status"] = "done"
    store.save(task)
    assert store.unfinished() == []


def test_mother_batch_leave_ui_and_route_are_exposed():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    frontend = (root / "frontend/src/pages/GptPlans.tsx").read_text()
    backend = (root / "api/gpt_plans.py").read_text()
    assert "全部子号退出空间" in frontend
    assert "business-child-batch-leave-tasks" in frontend
    assert "下次自动核对" in frontend
    assert '@router.post("/accounts/{account_id}/business-child-batch-leave-tasks")' in backend

from types import SimpleNamespace


def test_prepared_batch_uses_one_source_command_for_all_children(monkeypatch):
    from api import gpt_business, gpt_plans
    from services import gpt_plan_preparation_store

    children = [
        SimpleNamespace(id=11, email="one@gmail.com"),
        SimpleNamespace(id=12, email="two@gmail.com"),
    ]
    binding = SimpleNamespace(
        plan_account_id=7,
        source_account_id=3,
        source_pool="gpt_business",
        normalized_email="mother@gmail.com",
    )
    monkeypatch.setattr(
        gpt_plans,
        "_business_child_facade_binding",
        lambda *args, **kwargs: (binding, {}),
    )
    monkeypatch.setattr(
        gpt_plans,
        "_plan_business_candidate_records",
        lambda *args, **kwargs: [{"child": child} for child in children],
    )
    monkeypatch.setattr(gpt_plan_preparation_store, "_security_ready_now", lambda email: True)
    monkeypatch.setattr(
        gpt_plans,
        "_business_mutation_snapshot_after_source_call",
        lambda value: ({"managed_children": []}, False),
    )
    monkeypatch.setattr(gpt_plans, "_confirm_business_child_persistence", lambda *args, **kwargs: None)

    calls = []

    def invite(source_id, body, **kwargs):
        calls.append((source_id, body, kwargs))
        return {
            "ok": True,
            "invited": [child.email for child in children],
            "managed_child_ids": [child.id for child in children],
            "seat_type": "prolite",
        }

    monkeypatch.setattr(gpt_business, "invite_member_biz_for_plan_facade", invite)

    result = gpt_plans._prepared_batch_invite_many(
        7,
        [11, 12],
        seat_type="prolite",
        operation_id="test-prepared-batch",
    )

    assert result["ok"] is True
    assert len(calls) == 1
    source_id, body, kwargs = calls[0]
    assert source_id == 3
    assert body.pro_account_ids == [11, 12]
    assert body.seat_type == "prolite"
    assert body.candidate_mail_provider == "gmail"
    assert kwargs["prelogin_pro_account_ids"] == [11, 12]


def test_standalone_invite_ui_uses_type_and_count_only():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "frontend/src/pages/GptPlans.tsx").read_text()
    assert 'data-prepared-batch-invite="true"' in source
    assert "子号席位类型" in source
    assert "子号数量" in source
    assert "/prepared-batch-invite-tasks" in source
    assert "每个待注册子号绑定不同的可用代理" in source
    assert "post_acquire_rt: true" in source
    assert "随后自动逐个获取 RT" in source
    assert "下次自动重试" in source


def test_prepared_batch_request_enables_rt_by_default():
    from api.gpt_plans import GptPlanPreparedBatchInviteRequest

    request = GptPlanPreparedBatchInviteRequest(seat_type="prolite", count=2)
    assert request.post_acquire_rt is True


def test_prepared_batch_snapshot_survives_process_memory_loss(monkeypatch):
    from sqlalchemy.pool import StaticPool
    from sqlmodel import create_engine
    from services import prepared_batch_invite_store as store

    isolated_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(store, "engine", isolated_engine)
    monkeypatch.setattr(store, "_initialized", False)
    store.init_tables()
    task = {
        "task_id": "durable-prepared-batch-test",
        "workflow": "prepare_then_batch",
        "status": "running",
        "phase": "rt",
        "mothers": [{"account_id": 71, "invitations": []}],
        "logs": ["credential-free progress"],
    }
    store.save(task)
    assert store.load(task["task_id"]) == task
    assert task["task_id"] in {item["task_id"] for item in store.unfinished()}

    task["status"] = "done"
    task["phase"] = "done"
    store.save(task)
    assert task["task_id"] not in {item["task_id"] for item in store.unfinished()}

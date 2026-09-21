"""Gmail production limits never disable delivery or discard membership evidence."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json

import pytest
from sqlmodel import SQLModel, Session, create_engine, select

from core.db import (AccountModel, ChatGptAccountSecurityModel, GptBusinessChildMembershipModel,
                     GptPlanAccountModel, GptPlanAccountOperationLeaseModel)
from services import gmail_store as gmail, gmail_registration as registration
from services import gmail_production_policy as policy
from services import nv_automation_store as nv, nv_gmail_production as production


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'policy.db'}",
                           connect_args={"check_same_thread": False, "timeout": 30})
    monkeypatch.setattr(gmail, "engine", engine)
    monkeypatch.setattr(nv, "engine", engine)
    gmail.init_tables(engine)
    SQLModel.metadata.create_all(engine, tables=[
        AccountModel.__table__, ChatGptAccountSecurityModel.__table__, GptPlanAccountModel.__table__,
        GptPlanAccountOperationLeaseModel.__table__, GptBusinessChildMembershipModel.__table__,
        nv.NvAutomationJob.__table__,
    ])
    with Session(engine) as session:
        for source_id in (1, 2):
            session.add(gmail.GmailSource(id=source_id, email=f"source{source_id}@gmail.com",
                usability_status="usable", receive_verified=True,
                app_password_ciphertext="TEST-ENCRYPTED-NOT-A-REAL-CREDENTIAL"))
        session.commit()
    yield engine
    engine.dispose()


def allocate(db, job_id="nv-one", parent=1):
    with nv.transaction() as session:
        job = session.get(nv.NvAutomationJob, job_id)
        if not job:
            job = nv.NvAutomationJob(id=job_id, parent_account_id=parent, status="running",
                step="invite", worker_token=f"worker-{job_id}", active_parent_key=str(parent))
            session.add(job)
            session.flush()
        candidate = production.allocate_candidate(session, job)
        if candidate:
            candidate["context"]["invite_attempted"] = False
            nv._update_fields(job, candidate)
            session.add(job)
        return candidate


def snapshot(db, job_id="nv-one"):
    with Session(db) as session:
        job = session.get(nv.NvAutomationJob, job_id)
        return dict(id=job.id, child_id=job.child_id, email=job.email, worker_token=job.worker_token,
                    context=json.loads(job.context_json))


def exhaust(db, job_id="nv-one"):
    job = snapshot(db, job_id)
    return production.complete_preparation(job, dict(ok=False, error_code="gmail_source_exhausted",
        source_error_code="user_already_exists"))


def state(db):
    with Session(db) as session:
        return {model.__tablename__: [item.model_dump() for item in session.exec(select(model)).all()]
                for model in (gmail.GmailSource, gmail.GmailAlias, nv.NvAutomationJob, GptPlanAccountModel)}


def test_blocked_source_is_disabled_and_reselects_other_source(db):
    failed, existing, unused = gmail.generate_aliases(1, count=3, prefix="child")
    with Session(db) as session:
        alias = session.get(gmail.GmailAlias, existing["id"])
        plan = GptPlanAccountModel(email=alias.email, chatgpt_user_id="existing-user",
                                   last_login_at=gmail.utcnow(), mail_provider="gmail")
        session.add(plan)
        session.flush()
        alias.gpt_plan_account_id = plan.id
        alias.registered_at = gmail.utcnow()
        alias.registration_status = "registered"
        alias.registration_stage = "security_pending"
        session.add(alias)
        policy.mark_source_exhausted(session, session.get(gmail.GmailAlias, failed["id"]))
        session.commit()
    source = next(item for item in gmail.list_sources() if item["id"] == 1)
    assert source["production_blocked"] and not source["enabled"] and not source["receive_ready"]
    assert source["usability_status"] == "usable"
    with pytest.raises(gmail.GmailStoreError) as disabled:
        gmail.network_snapshot(1, existing["id"])
    assert disabled.value.code == "source_disabled"
    with pytest.raises(gmail.GmailStoreError) as unavailable:
        registration.require_receive_ready(existing["id"])
    assert unavailable.value.code == "receive_not_ready"
    with pytest.raises(gmail.GmailStoreError) as caught:
        gmail.generate_aliases(1, count=1, prefix="new")
    assert caught.value.code == "source_production_blocked"
    assert registration.list_candidates(1) == []
    assert registration.list_due_registration_retries() == []
    with pytest.raises(gmail.GmailStoreError):
        registration.claim_alias(alias_ids=[unused["id"]])
    assert allocate(db, "nv-reselected", 99)["context"]["gmail_production_source_id"] == 2


def test_automatic_generation_uses_three_then_changes_source(db):
    candidates = [allocate(db, f"nv-{index}", index + 1) for index in range(6)]
    assert [item["context"]["gmail_production_source_id"] for item in candidates] == [1, 1, 1, 2, 2, 2]
    assert len({item["email"] for item in candidates}) == 6
    assert allocate(db, "nv-empty", 7) is None
    assert {item["generated_alias_count"] for item in gmail.list_sources()} == {3}


def test_concurrent_nv_generation_respects_source_lifetime_limit(db):
    with ThreadPoolExecutor(max_workers=8) as pool:
        candidates = list(pool.map(lambda index: allocate(db, f"nv-{index}", index + 1), range(8)))
    available = [item for item in candidates if item]
    assert len(available) == 6
    assert len({item["email"] for item in available}) == 6
    assert sorted(item["alias_count"] for item in gmail.list_sources()) == [3, 3]


def test_legacy_overflow_cannot_be_registered_or_selected(db):
    with Session(db) as session:
        for index in range(1, 7):
            session.add(gmail.GmailAlias(source_id=1, tag=f"old{index}", email=f"source1+old{index}@gmail.com"))
        session.commit()
    assert [item["email"] for item in registration.list_candidates(1)] == [f"source1+old{index}@gmail.com" for index in range(1, 4)]
    candidates = [allocate(db, f"nv-{index}", index + 1) for index in range(4)]
    assert [item["context"]["gmail_production_source_id"] for item in candidates] == [1, 1, 1, 2]
    assert len(gmail.list_aliases(1)) == 6
    with pytest.raises(gmail.GmailStoreError):
        registration.claim_alias(alias_ids=[4])


def test_rejected_uninvited_candidate_preserves_audit_and_reselects_other_source(db):
    original = allocate(db)
    exhaust(db)
    assert production.candidate_rejection(snapshot(db))
    updates = nv.release_rejected_gmail_candidate("nv-one", "worker-nv-one")
    evidence = updates["context"]["gmail_rejected_candidate"]
    assert evidence["email"] == original["email"]
    assert evidence["remote_invite_sent"] is False
    assert evidence["reason"] == "source_exhausted"
    assert updates["context"]["excluded_child_ids"] == [original["child_id"]]
    with Session(db) as session:
        job = session.get(nv.NvAutomationJob, "nv-one")
        assert not job.child_id and not job.active_child_key and not job.email
        assert job.active_parent_key == "1"
        alias = session.get(gmail.GmailAlias, original["context"]["gmail_production_alias_id"])
        assert alias.registration_stage == "source_exhausted" and not alias.production_job_id
        assert session.get(GptPlanAccountModel, original["child_id"]).enabled is False
    replacement = allocate(db)
    assert replacement["context"]["gmail_production_source_id"] == 2
    assert replacement["email"] != original["email"]
    assert snapshot(db)["context"]["gmail_rejected_candidate"]["email"] == original["email"]


@pytest.mark.parametrize("condition", ["stale_token", "alias_owner", "email", "source_context", "invite_attempted",
    "invite_unknown", "membership_id", "remote_user_id", "membership_row", "plan_parent", "plan_lease", "sale"])
def test_rejection_never_releases_uncertain_or_active_membership(db, condition):
    candidate = allocate(db)
    exhaust(db)
    with Session(db) as session:
        job = session.get(nv.NvAutomationJob, "nv-one")
        alias = session.get(gmail.GmailAlias, candidate["context"]["gmail_production_alias_id"])
        plan = session.get(GptPlanAccountModel, candidate["child_id"])
        context = json.loads(job.context_json)
        if condition == "alias_owner": alias.production_job_id = "another-job"
        elif condition == "email": job.email = "different@gmail.com"
        elif condition == "source_context": context["gmail_production_source_id"] = 2
        elif condition == "invite_attempted": context["invite_attempted"] = True
        elif condition == "invite_unknown": context.pop("invite_attempted")
        elif condition == "membership_id": job.membership_id = 777
        elif condition == "remote_user_id": job.remote_user_id = "remote-member"
        elif condition == "membership_row":
            session.add(GptBusinessChildMembershipModel(business_account_id=1, pro_account_id=plan.id, email=plan.email))
        elif condition == "plan_parent": plan.business_parent_id = 1
        elif condition == "plan_lease":
            session.add(GptPlanAccountOperationLeaseModel(account_id=plan.id, operation="login", token="current-lease",
                expires_at=gmail.utcnow() + timedelta(minutes=10)))
        elif condition == "sale": context["sale_confirmed"] = True
        job.context_json = json.dumps(context)
        session.add(job)
        session.add(alias)
        session.add(plan)
        session.commit()
    before = state(db)
    token = "stale" if condition == "stale_token" else "worker-nv-one"
    with pytest.raises(RuntimeError):
        nv.release_rejected_gmail_candidate("nv-one", token)
    assert state(db) == before


def test_block_survives_restart_and_rejected_alias_never_resumes(db):
    first = allocate(db)
    exhaust(db)
    nv.release_rejected_gmail_candidate("nv-one", "worker-nv-one")
    gmail.init_tables(db)
    registration.recover_registration_state(startup=True)
    assert not registration.list_candidates(1)
    assert not registration.list_due_registration_retries()
    with Session(db) as session:
        source = session.get(gmail.GmailSource, 1)
        alias = session.get(gmail.GmailAlias, first["context"]["gmail_production_alias_id"])
        assert source.production_blocked
        assert alias.registration_stage == "source_exhausted"
        assert alias.registration_status == "failed"
    assert allocate(db)["context"]["gmail_production_source_id"] == 2


@pytest.mark.parametrize("result", [
    dict(ok=False, error_code="registration_failed", source_error_code="user_already_exists"),
    dict(ok=False, error_code="gmail_source_exhausted", source_error_code="unknown"),
    dict(ok=False, error="user_already_exists"),
])
def test_only_structured_confirmed_registration_evidence_blocks_source(db, result):
    allocate(db)
    production.complete_preparation(snapshot(db), result)
    assert not next(item for item in gmail.list_sources() if item["id"] == 1)["production_blocked"]


def test_stale_registration_claim_cannot_exhaust_source(db):
    alias = gmail.generate_aliases(1, count=1, prefix="child")[0]
    claim = registration.claim_alias(alias_ids=[alias["id"]])
    before = state(db)
    with pytest.raises(gmail.GmailStoreError):
        registration.block_source_for_claim(alias["id"], "wrong-token")
    assert state(db) == before
    registration.block_source_for_claim(alias["id"], claim["lease_token"])
    assert next(item for item in gmail.list_sources() if item["id"] == 1)["production_blocked"]


@pytest.mark.parametrize("event", ["progress", "failure"])
def test_late_worker_callbacks_cannot_erase_exhaustion_evidence(db, event):
    candidate = allocate(db)
    exhaust(db)
    job = snapshot(db)
    try:
        if event == "progress":
            production.mark_preparation(job, "login", {"registered_verified": False})
        else:
            production.complete_preparation(job, {"ok": False, "error_code": "login_failed"})
    except gmail.GmailStoreError:
        pass  # Rejecting a late event and ignoring it are both valid.
    with Session(db) as session:
        alias = session.get(gmail.GmailAlias, candidate["context"]["gmail_production_alias_id"])
        assert alias.registration_stage == "source_exhausted"
        assert alias.registration_status == "failed"

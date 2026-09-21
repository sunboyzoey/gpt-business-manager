"""Typed no-mutation exit failures and narrow recovery of legacy preflights.

No provider requests and no database writes. Missing evidence never authorizes
replaying an exit whose remote outcome could be unknown.
"""
from datetime import datetime, timezone
import json
import re

from fastapi import HTTPException
from sqlalchemy import inspect
from sqlmodel import select


CODES = {'business_session_unavailable', 'business_session_busy', 'business_mother_deactivated'}
MESSAGES = {
    'error': '母号会话检查暂时失败，尚未发送退出请求，等待自动重试',
    'busy': '母号会话正在恢复，尚未发送退出请求，等待自动重试',
    'expired': '母号会话已过期，等待自动恢复后退出',
    'invalid': '母号登录会话已失效，等待恢复后退出',
    'unauthorized': '母号凭据暂不可用，等待恢复后退出',
    'blocked': '母号访问被拒绝，尚未发送退出请求，等待重试',
    'missing': '母号缺少可用登录凭据，请登录母号后继续退出',
    'login_required': '母号需要登录或额外验证，登录完成后可继续退出',
    'wrong_identity': '母号会话身份不匹配，请登录正确母号后继续退出',
    'deactivated': '母号已明确停用，已停止该母号自动处理',
}


class BusinessExitPreflightError(HTTPException):
    """Only constructed inside the pre-source-call boundary, not from text."""
    def __init__(self, detail):
        raw = detail if isinstance(detail, dict) else {}
        code = raw.get('code') if raw.get('code') in CODES else 'business_session_unavailable'
        health = raw.get('session_health') if isinstance(raw.get('session_health'), dict) else {}
        status = health.get('status', 'busy' if code == 'business_session_busy' else 'error')
        status = {
            'credentials_missing': 'missing', 'email_verification_required': 'login_required',
            'mfa_unavailable': 'login_required', 'wrong_identity': 'wrong_identity',
            'rate_limited': 'blocked', 'cleanup_failed': 'login_required',
        }.get(health.get('recovery_reason'), status)
        if code == 'business_mother_deactivated':
            status = 'deactivated'
        status = status if status in MESSAGES else 'error'
        retryable = (raw.get('retryable') is not False and status not in
                     {'deactivated', 'missing', 'login_required', 'wrong_identity'})
        self.failure = dict(code=code, status=status, message=MESSAGES[status], retryable=retryable,
                            remote_mutation_started=False)
        self.retry_at = raw.get('retry_at') or health.get('retry_at')
        super().__init__(409, dict(self.failure, session_health={'status': status}))


def normalize_leave_preflight(value):
    if not isinstance(value, dict) or value.get('code') not in CODES:
        return None
    status = value.get('status')
    if status not in MESSAGES or type(value.get('retryable')) is not bool or value.get('remote_mutation_started') is not False:
        return None
    retry_at = value.get('retry_at')
    try:
        parsed = datetime.fromisoformat(retry_at.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return None
    except (ValueError, TypeError, AttributeError):
        return None
    return dict(code=value['code'], status=status, message=MESSAGES[status],
                retryable=value['retryable'] and status != 'deactivated',
                remote_mutation_started=False, retry_at=parsed.astimezone(timezone.utc).isoformat())


def saved_preflight_failure(session, job):
    """Recover a crash after a typed no-DELETE checkpoint, before finish_step.

    A task flag alone is insufficient: re-read the canonical member, bindings
    and operation intent before authorizing another *preflight*, never DELETE.
    """
    from core.db import (GptBusinessAccountModel as Mother, GptPlanAccountModel as Plan,
                         GptBusinessChildMembershipModel as Member,
                         GptBusinessRotationReservationModel as Reservation)
    from services.nv_automation_store import NvAutomationJob
    get = job.get if isinstance(job, dict) else lambda key, default=None: getattr(job, key, default)
    try:
        if get('step') != 'leave' or get('status') not in {'review', 'failed', 'pending', 'running', 'waiting', 'retry'}:
            return False
        names = set(inspect(session.connection()).get_table_names())
        if not {x.__tablename__ for x in (Mother, Plan, Member, Reservation, NvAutomationJob)}.issubset(names):
            return False
        row = session.get(NvAutomationJob, get('id'))
        keys = ('operation_id', 'parent_account_id', 'source_account_id', 'parent_email',
                'child_id', 'membership_id', 'email', 'remote_user_id')
        if not row or row.step != 'leave' or any(get(key) != getattr(row, key) for key in keys):
            return False
        context = json.loads(row.context_json or '{}')
        if (normalize_leave_preflight(context.get('leave_preflight')) is None
                or context.get('leave_attempted') is not False
                or any(context.get(key) for key in ('leave_target', 'leave_started_at', 'left_at'))
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', row.operation_id or '')):
            return False
        mother, parent = session.get(Mother, row.source_account_id), session.get(Plan, row.parent_account_id)
        child, member = session.get(Plan, row.child_id), session.get(Member, row.membership_id)
        if not all((mother, parent, child, member)):
            return False
        email, parent_email = row.email.strip().lower(), row.parent_email.strip().lower()
        if (not email or not parent_email or email == parent_email
                or parent.source_pool != 'gpt_business' or parent.source_account_id != mother.id
                or parent.business_parent_id is not None
                or parent.email.strip().lower() != parent_email or mother.email.strip().lower() != parent_email
                or child.email.strip().lower() != email or child.business_parent_id != mother.id
                or member.pro_account_id != child.id or member.business_account_id != mother.id
                or member.email.strip().lower() != email or member.source != 'pool'
                or not row.remote_user_id or member.remote_user_id != row.remote_user_id
                or member.ended_at is not None or member.end_reason or member.operation_id
                or member.intent_remote_started or json.loads(member.intent_payload_json or '{}')):
            return False
        return session.exec(select(Reservation.operation_id).where(
            Reservation.operation_id == row.operation_id)).first() is None
    except (ValueError, TypeError, AttributeError, KeyError):
        return False


def legacy_preflight_failure(session, job):
    """Require exact old error provenance AND untouched canonical exit intent."""
    from core.db import (GptBusinessAccountModel, GptPlanAccountModel,
                         GptBusinessChildMembershipModel, GptBusinessRotationReservationModel)
    from services.nv_automation_store import NvAutomationJob, NvAutomationLog
    get = job.get if isinstance(job, dict) else lambda key, default=None: getattr(job, key, default)
    try:
        if get('step') != 'leave' or get('status') not in {'review', 'failed', 'pending', 'running'}:
            return False
        names = set(inspect(session.connection()).get_table_names())
        if not {NvAutomationJob.__tablename__, NvAutomationLog.__tablename__,
                GptBusinessRotationReservationModel.__tablename__}.issubset(names):
            return False
        row = session.get(NvAutomationJob, get('id'))
        if not row or row.step != 'leave' or row.operation_id != get('operation_id'):
            return False
        context = json.loads(row.context_json or '{}')
        target = context.get('leave_target')
        if context.get('leave_attempted') is not True or context.get('left_at') or not isinstance(target, dict):
            return False
        operation = row.operation_id
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', operation or ''):
            return False
        expected = dict(parent_account_id=row.parent_account_id, source_account_id=row.source_account_id,
                        parent_email=row.parent_email.strip().lower(), child_id=row.child_id,
                        membership_id=row.membership_id, email=row.email.strip().lower(),
                        user_id=row.remote_user_id, source='pool', operation_id=operation)
        if any(target.get(key) != value for key, value in expected.items()):
            return False
        mother = session.get(GptBusinessAccountModel, row.source_account_id)
        parent = session.get(GptPlanAccountModel, row.parent_account_id)
        child = session.get(GptPlanAccountModel, row.child_id)
        member = session.get(GptBusinessChildMembershipModel, row.membership_id)
        if not all((mother, parent, child, member)):
            return False
        if (parent.source_pool != 'gpt_business' or parent.source_account_id != mother.id
                or parent.email.strip().lower() != expected['parent_email']
                or mother.email.strip().lower() != expected['parent_email']
                or child.email.strip().lower() != expected['email'] or child.business_parent_id != mother.id
                or member.pro_account_id != child.id or member.business_account_id != mother.id
                or member.email.strip().lower() != expected['email'] or member.source != 'pool'
                or not member.remote_user_id or member.remote_user_id != target['user_id']
                or (member.remote_invite_id or '') != target.get('invite_id', '')
                or member.ended_at is not None or member.end_reason or member.operation_id
                or member.intent_remote_started or json.loads(member.intent_payload_json or '{}')):
            return False
        if session.exec(select(GptBusinessRotationReservationModel.operation_id).where(
                GptBusinessRotationReservationModel.operation_id == operation)).first() is not None:
            return False
        started = datetime.fromisoformat(context['leave_started_at'].replace('Z', '+00:00'))
        if started.tzinfo is None:
            return False
        logs = session.exec(select(NvAutomationLog).where(
            NvAutomationLog.job_id == row.id, NvAutomationLog.step == 'leave',
            NvAutomationLog.created_at >= started.timestamp(),
        ).order_by(NvAutomationLog.created_at, NvAutomationLog.id)).all()
        # This exact string is emitted by ensure_session *before* source removal.
        prefix = 'HTTP 409：会话检查失败，无法确认有效性；请稍后重试'
        first_error = next((log.message for log in logs if
                            'HTTP ' in log.message or '退出结果未确认' in log.message), '')
        return first_error.startswith(prefix) and f'操作 ID {operation}' in first_error
    except (ValueError, TypeError, AttributeError, KeyError):
        return False

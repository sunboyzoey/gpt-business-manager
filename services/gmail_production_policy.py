"""Local production policy, independent of continued mailbox access."""
from sqlalchemy import func
from sqlmodel import select

from services import gmail_store as store

EXHAUSTED_REASON = "注册返回 user_already_exists；已自动关闭此 Gmail 母号，并改选其他母号"


def within_alias_limit(session, alias):
    # Historical overflow is retained for audit, but cannot become new accounts.
    preceding = session.exec(select(func.count(store.GmailAlias.id)).where(
        store.GmailAlias.source_id == alias.source_id,
        store.GmailAlias.id <= alias.id)).one()
    return preceding <= store.MAX_ALIASES_PER_SOURCE


def can_start(session, alias, source):
    return bool(source and not source.production_blocked
                and alias.registration_stage != "source_exhausted"
                and within_alias_limit(session, alias))


def mark_source_exhausted(session, alias):
    """Caller must first fence the exact alias owner or reviewed historical row."""
    source = store._source(session, alias.source_id)
    # ``user_already_exists`` is durable evidence that this Gmail source must
    # leave automatic production.  Keep the explicit production fence for
    # audit/re-enable safety, and also turn off the source so every candidate
    # selector and the Gmail management UI agree that it is closed.
    source.enabled = False
    source.production_blocked = True
    source.production_block_reason = EXHAUSTED_REASON
    source.production_blocked_at = source.production_blocked_at or store.utcnow()
    source.updated_at = store.utcnow()
    alias.registration_status = "failed"
    alias.registration_stage = "source_exhausted"
    alias.registration_error = EXHAUSTED_REASON
    alias.registration_retry_at = None
    alias.registration_lease_token = ""
    alias.registration_lease_expires_at = None
    alias.registration_updated_at = store.utcnow()
    session.add(source)
    session.add(alias)

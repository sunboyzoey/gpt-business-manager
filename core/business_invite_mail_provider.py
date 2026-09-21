"""Seat-based default mailbox policy, shared by UI-facing and worker selection."""
from __future__ import annotations

from collections.abc import Mapping

from sqlmodel import Session, select

from core.config_store import ConfigItem
from core.db import engine


BUSINESS_INVITE_MAIL_PROVIDER_KEYS = {
    "default": "business_invite_default_mail_provider",
    "prolite": "business_invite_prolite_mail_provider",
}
DEFAULT_BUSINESS_INVITE_MAIL_PROVIDERS = {"default": "gmail", "prolite": "gmail"}
BUSINESS_INVITE_MAIL_PROVIDERS = frozenset({"gmail"})


def validate_business_invite_mail_provider(value) -> str:
    """Configuration must name a concrete mailbox; auto cannot refer to itself."""
    if not isinstance(value, str) or value not in BUSINESS_INVITE_MAIL_PROVIDERS:
        raise ValueError("独立项目的邀请候选邮箱只能是 gmail")
    return value


def get_business_invite_mail_providers(session: Session | None = None) -> dict[str, str]:
    """Read only these two settings, without caching or environment overrides.

    Use scalar values so a caller's existing ORM identity map cannot hide a
    recently saved setting. Passing a session keeps selection and policy in the
    same transaction. Missing keys retain the historical defaults; malformed
    stored values and database errors remain visible.
    """
    if session is None:
        with Session(engine) as owned_session:
            return get_business_invite_mail_providers(owned_session)
    saved = dict(session.exec(select(ConfigItem.key, ConfigItem.value).where(
        ConfigItem.key.in_(tuple(BUSINESS_INVITE_MAIL_PROVIDER_KEYS.values()))
    )).all())
    return {
        seat: validate_business_invite_mail_provider(saved.get(
            key, DEFAULT_BUSINESS_INVITE_MAIL_PROVIDERS[seat]
        ))
        for seat, key in BUSINESS_INVITE_MAIL_PROVIDER_KEYS.items()
    }


def resolve_candidate_mail_provider(provider, seat_type, *, session=None, defaults=None) -> str:
    """Resolve auto from current seat policy; explicit choices always win.

    A preloaded complete defaults mapping may be supplied by consumers that
    already read the settings. Unknown seats deliberately stay auto until live
    seat detection completes and do not access configuration.
    """
    if session is not None and defaults is not None:
        raise ValueError("session 与 defaults 不能同时提供")
    value = str(provider or "auto").strip().lower()
    value = "icloud" if value == "qqmail" else value
    if value not in {"auto", "gmail"}:
        raise ValueError("独立项目的邀请候选邮箱只能是 auto 或 gmail")
    if value != "auto":
        return value
    seat = str(seat_type or "").strip().lower().replace("_", "-")
    if seat in {"default", "standard", "regular"}:
        seat = "default"
    elif seat in {"prolite", "pro-lite"}:
        seat = "prolite"
    else:
        return "gmail"
    if defaults is None:
        defaults = get_business_invite_mail_providers(session)
    elif not isinstance(defaults, Mapping) or set(defaults) != set(BUSINESS_INVITE_MAIL_PROVIDER_KEYS):
        raise ValueError("席位默认邮箱配置必须同时包含 default 和 prolite")
    # Validate the pair even when only one seat is selected so malformed
    # snapshots never silently become a partial policy.
    validated = {key: validate_business_invite_mail_provider(defaults[key])
                 for key in BUSINESS_INVITE_MAIL_PROVIDER_KEYS}
    return validated[seat]

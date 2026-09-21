"""Provider-neutral SMS activation lifecycle with durable local records."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel, Session, select

from core.config_store import config_store
from core.db import engine
from core.secret_store import get_secret, has_secret, set_secret
from platforms.chatgpt.smsbower_client import SmsbowerClient


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SmsActivation(SQLModel, table=True):
    __tablename__ = "sms_activations"
    id: int | None = Field(default=None, primary_key=True)
    provider: str = Field(index=True, max_length=40)
    remote_id: str = Field(index=True, max_length=160)
    phone: str = Field(default="", max_length=40)
    service: str = Field(default="", max_length=80)
    country: str = Field(default="", max_length=40)
    state: str = Field(default="allocated", index=True, max_length=40)
    code_received: bool = False
    error_code: str = Field(default="", max_length=120)
    provider_payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utcnow, index=True)
    updated_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime | None = None


class SmsProvider(ABC):
    code: str
    label: str

    @abstractmethod
    def balance(self) -> float: ...

    @abstractmethod
    def acquire(self, *, service: str, country: str, max_price: str) -> dict: ...

    @abstractmethod
    def status(self, activation_id: str) -> dict: ...

    @abstractmethod
    def complete(self, activation_id: str) -> Any: ...

    @abstractmethod
    def cancel(self, activation_id: str) -> Any: ...


class ActivationApiProvider(SmsProvider):
    """Adapter for SMS-Activate compatible APIs used by SMSBower/GrizzlySMS."""

    def __init__(self, code: str, label: str, *, default_base_url: str):
        self.code, self.label = code, label
        self.default_base_url = default_base_url

    @property
    def secret_key(self) -> str:
        return f"sms_{self.code}_api_key"

    def configured(self) -> bool:
        return has_secret(self.secret_key) or (
            self.code == "smsbower" and has_secret("smsbower_api_key")
        )

    def client(self) -> SmsbowerClient:
        legacy_key = "smsbower_api_key" if self.code == "smsbower" else self.secret_key
        api_key = get_secret(self.secret_key) or get_secret(legacy_key)
        if not api_key:
            raise ValueError(f"{self.label} API Key 未配置")
        base = str(config_store.get(f"sms_{self.code}_base_url", "") or "").strip()
        if not base and self.code == "smsbower":
            base = str(config_store.get("smsbower_base_url", "") or "").strip()
        proxy = str(config_store.get(f"sms_{self.code}_proxy", "") or "").strip()
        if not proxy and self.code == "smsbower":
            proxy = str(config_store.get("smsbower_proxy", "") or "").strip()
        return SmsbowerClient(api_key, base_url=base or self.default_base_url, proxy=proxy or None)

    def balance(self) -> float:
        return self.client().balance()

    def acquire(self, *, service: str, country: str, max_price: str) -> dict:
        return self.client().get_number(service=service, country=country, max_price=max_price)

    def status(self, activation_id: str) -> dict:
        return self.client().get_status(activation_id)

    def complete(self, activation_id: str) -> Any:
        return self.client().confirm(activation_id)

    def cancel(self, activation_id: str) -> Any:
        return self.client().cancel(activation_id)


_PROVIDERS: dict[str, ActivationApiProvider] = {
    "smsbower": ActivationApiProvider(
        "smsbower", "SMSBower", default_base_url="https://smsbower.page/stubs/handler_api.php"
    ),
    "grizzly": ActivationApiProvider(
        "grizzly", "GrizzlySMS", default_base_url="https://api.grizzlysms.com/stubs/handler_api.php"
    ),
}


def init_tables() -> None:
    SQLModel.metadata.create_all(engine, tables=[SmsActivation.__table__])


def provider(code: str) -> ActivationApiProvider:
    try:
        return _PROVIDERS[str(code or "").strip().lower()]
    except KeyError:
        raise ValueError("不支持的短信供应商") from None


def providers() -> list[dict]:
    return [
        {"code": item.code, "label": item.label, "configured": item.configured()}
        for item in _PROVIDERS.values()
    ]


def configure_provider(code: str, *, api_key: str | None = None, base_url: str = "", proxy: str = "") -> dict:
    item = provider(code)
    if api_key is not None and api_key.strip():
        set_secret(item.secret_key, api_key)
    config_store.set(f"sms_{item.code}_base_url", str(base_url or "").strip())
    config_store.set(f"sms_{item.code}_proxy", str(proxy or "").strip())
    return next(value for value in providers() if value["code"] == item.code)


def acquire(code: str, *, service: str, country: str, max_price: str) -> dict:
    item = provider(code)
    result = item.acquire(service=service, country=country, max_price=max_price)
    with Session(engine) as session:
        row = SmsActivation(
            provider=item.code,
            remote_id=str(result["activation_id"]),
            phone=str(result["phone"]),
            service=service,
            country=country,
            provider_payload={k: v for k, v in result.items() if k != "raw"},
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return activation_dto(row)


def refresh(activation_id: int) -> dict:
    with Session(engine) as session:
        row = session.get(SmsActivation, activation_id)
        if row is None:
            raise KeyError(activation_id)
        result = provider(row.provider).status(row.remote_id)
        row.state = str(result.get("state") or row.state)
        row.code_received = row.code_received or bool(result.get("code"))
        row.updated_at = utcnow()
        row.provider_payload = {k: v for k, v in result.items() if k != "raw"}
        session.add(row)
        session.commit()
        session.refresh(row)
        dto = activation_dto(row)
        dto["code"] = result.get("code")
        return dto


def finish(activation_id: int, action: str) -> dict:
    if action not in {"complete", "cancel"}:
        raise ValueError("短信终态操作无效")
    with Session(engine) as session:
        row = session.get(SmsActivation, activation_id)
        if row is None:
            raise KeyError(activation_id)
        getattr(provider(row.provider), action)(row.remote_id)
        row.state = "completed" if action == "complete" else "cancelled"
        row.completed_at = row.updated_at = utcnow()
        session.add(row)
        session.commit()
        session.refresh(row)
        return activation_dto(row)


def list_activations(limit: int = 100) -> list[dict]:
    with Session(engine) as session:
        rows = session.exec(select(SmsActivation).order_by(SmsActivation.id.desc()).limit(max(1, min(limit, 500)))).all()
        return [activation_dto(row) for row in rows]


def activation_dto(row: SmsActivation) -> dict:
    return {
        "id": row.id,
        "provider": row.provider,
        "remote_id": row.remote_id,
        "phone": row.phone,
        "service": row.service,
        "country": row.country,
        "state": row.state,
        "code_received": row.code_received,
        "error_code": row.error_code,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
    }


__all__ = [
    "SmsActivation", "SmsProvider", "acquire", "configure_provider", "finish",
    "init_tables", "list_activations", "provider", "providers", "refresh",
]

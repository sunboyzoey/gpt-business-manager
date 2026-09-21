"""BUSINESS CSV workflow service.

This workflow is intentionally separate from BUSINESS RT Loop UI state.  It reuses
CHATGPT platform-management registration tasks and marks created accounts with
`business_csv_*` metadata so the new page can export Business invite CSV files and
then run activation/RT/AT batches for only those accounts.

批次(batch)概念已移除：所有 business_csv 账号统一进一个列表，操作范围只有
「全部」或「勾选的账号」。RT / AT / 激活任务支持优雅停止(已在跑的任务做完、
不再启动新的)。
"""
from __future__ import annotations

import collections
import csv
import io
import json
import os
import re
import threading
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Any, Callable

from sqlmodel import Session, select

from core.db import AccountModel, TaskLog, engine

BUSINESS_CSV_SOURCE = "business_csv"
BUSINESS_CSV_HEADER = ["email", "role", "seat type"]
# 用于识别 business_csv 账号的标记键(新老账号都有 business_csv_status)。
BUSINESS_CSV_MARKER = "business_csv_status"

_DEFAULT_ROLE = "member"
_DEFAULT_SEAT_TYPE = "ChatGPT"
_VALID_ROLES = {
    "member": "Member",
    "standard-user": "Member",
    "standard_user": "Member",
    "user": "Member",
    "admin": "Admin",
    "owner": "Owner",
}
_VALID_SEAT_TYPES = {
    "chatgpt": "ChatGPT",
    "chat": "ChatGPT",
    "default": "ChatGPT",
    "codex": "Codex",
    "usage_based": "Codex",
}

_EXPORT_ROOT = os.path.abspath(os.path.join(os.getcwd(), "exports", "business_csv"))
_RECENT_LOGS_MAX = 500


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_filename(value: str, fallback: str = "business_csv") -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", str(value or "").strip())
    safe = safe.strip("._-")
    return safe or fallback


def normalize_business_csv_role(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return _DEFAULT_ROLE
    lowered = text.lower()
    return _VALID_ROLES.get(lowered, text[:1].upper() + text[1:])


def normalize_business_csv_seat_type(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return _DEFAULT_SEAT_TYPE
    lowered = text.lower().replace(" ", "_")
    return _VALID_SEAT_TYPES.get(lowered, text[:1].upper() + text[1:])


def patch_business_csv_extra(
    extra: dict | None,
    *,
    role: Any = _DEFAULT_ROLE,
    seat_type: Any = _DEFAULT_SEAT_TYPE,
    status: str = "registered",
) -> dict:
    """Return a copy of account/task extra with independent BUSINESS CSV markers."""
    patched = dict(extra or {})
    patched["business_csv_status"] = str(status or "registered").strip() or "registered"
    patched["business_csv_role"] = normalize_business_csv_role(role)
    patched["business_csv_seat_type"] = normalize_business_csv_seat_type(seat_type)
    patched.setdefault("business_csv_created_at", _now_iso())
    return patched


def _account_extra(account: Any) -> dict:
    if account is None:
        return {}
    get_extra = getattr(account, "get_extra", None)
    if callable(get_extra):
        try:
            extra = get_extra()
            return extra if isinstance(extra, dict) else {}
        except Exception:
            return {}
    extra = getattr(account, "extra", None)
    if isinstance(extra, dict):
        return dict(extra)
    extra_json = getattr(account, "extra_json", "")
    if extra_json:
        try:
            parsed = json.loads(extra_json)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _is_business_csv_account(extra: dict) -> bool:
    return bool(extra.get("business_csv_status") or extra.get("business_csv_batch_id"))


def _has_chatgpt_rt(extra: dict) -> bool:
    """是否真正获取过 ChatGPT RT(而非 Outlook 邮箱的 refresh_token)。

    判据: RT 步骤成功时会写 business_csv_rt_acquired_at 并置状态 rt_ready。
    注册阶段 Outlook 账号 extra 里的 refresh_token 是微软邮箱 RT, 不算。
    """
    if str(extra.get("business_csv_rt_acquired_at") or "").strip():
        return True
    return str(extra.get("business_csv_status") or "") == "rt_ready"


def _parse_saved_cookies(extra: dict) -> dict:
    """从账号 extra 里解析注册时保存的 cookie(name->value)。用于 AT 免登录快速通道。"""
    raw = (extra or {}).get("cookies")
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if k}
    if isinstance(raw, str) and raw.strip():
        try:
            data = json.loads(raw)
        except Exception:
            return {}
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if k}
        if isinstance(data, list):
            out: dict[str, str] = {}
            for c in data:
                if isinstance(c, dict) and c.get("name"):
                    out[str(c["name"])] = str(c.get("value") or "")
            return out
    return {}


def build_business_invite_csv(accounts: list[Any]) -> str:
    """Build OpenAI Business bulk invite CSV text.

    Columns intentionally match the Business UI upload format: email, role,
    seat type.
    """
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(BUSINESS_CSV_HEADER)
    for account in accounts:
        email = str(getattr(account, "email", "") or "").strip().lower()
        if not email or "@" not in email:
            continue
        writer.writerow([
            email,
            _DEFAULT_ROLE,
            _DEFAULT_SEAT_TYPE,
        ])
    return output.getvalue()


def _apply_cfworker_options(
    extra: dict,
    *,
    domain_override: str = "",
    subdomain_mode: str = "managed",
    subdomain_prefix: str = "acc",
    subdomain_max_accounts: Any = 100,
) -> dict:
    """Apply the same CFWorker domain/subdomain controls used by CHATGPT registration."""
    domain = str(domain_override or "").strip().lower()
    if domain:
        extra["cfworker_domain_override"] = domain

    mode = str(subdomain_mode or "managed").strip().lower()
    if mode not in {"global", "root", "random", "managed"}:
        mode = "managed"
    extra["cfworker_subdomain_mode"] = mode

    if mode == "global":
        return extra
    if mode == "root":
        extra["cfworker_force_subdomain"] = "0"
        extra["cfworker_random_subdomain"] = "0"
        extra["cfworker_random_name_subdomain"] = "0"
        extra["cfworker_subdomain"] = ""
    elif mode == "random":
        extra["cfworker_force_subdomain"] = "0"
        extra["cfworker_random_subdomain"] = "1"
        extra["cfworker_random_name_subdomain"] = "0"
        extra["cfworker_subdomain"] = ""
    else:
        extra["cfworker_force_subdomain"] = "1"
        extra["cfworker_random_subdomain"] = "0"
        extra["cfworker_random_name_subdomain"] = "0"
        extra["cfworker_subdomain"] = ""
        prefix = str(subdomain_prefix or "acc").strip() or "acc"
        extra["cfworker_subdomain_prefix"] = prefix
        try:
            max_accounts = max(1, int(subdomain_max_accounts or 100))
        except Exception:
            max_accounts = 100
        extra["cfworker_subdomain_max_accounts"] = str(max_accounts)
    return extra


def build_business_csv_register_request(
    *,
    count: int,
    concurrency: int,
    executor_type: str = "protocol",
    captcha_solver: str = "yescaptcha",
    mail_provider: str = "cfworker",
    proxy: str = "",
    proxy_node: str = "",
    register_delay_seconds: float = 0,
    role: Any = _DEFAULT_ROLE,
    seat_type: Any = _DEFAULT_SEAT_TYPE,
    extra: dict | None = None,
    cfworker_domain_override: str = "",
    cfworker_subdomain_mode: str = "managed",
    cfworker_subdomain_prefix: str = "acc",
    cfworker_subdomain_max_accounts: Any = 100,
):
    """Build a normal /tasks/register request for CHATGPT with business_csv markers."""
    from api.tasks import RegisterTaskRequest

    merged_extra = dict(extra or {})
    if mail_provider:
        merged_extra["mail_provider"] = str(mail_provider).strip()
    if str(mail_provider or "").strip().lower() == "cfworker":
        _apply_cfworker_options(
            merged_extra,
            domain_override=cfworker_domain_override,
            subdomain_mode=cfworker_subdomain_mode,
            subdomain_prefix=cfworker_subdomain_prefix,
            subdomain_max_accounts=cfworker_subdomain_max_accounts,
        )
    merged_extra = patch_business_csv_extra(
        merged_extra,
        role=_DEFAULT_ROLE,
        seat_type=_DEFAULT_SEAT_TYPE,
        status="registered",
    )
    merged_extra["business_csv_register_task"] = "1"
    return RegisterTaskRequest(
        platform="chatgpt",
        count=max(1, int(count or 1)),
        concurrency=max(1, int(concurrency or 1)),
        register_delay_seconds=max(0.0, float(register_delay_seconds or 0)),
        proxy=str(proxy or ""),
        proxy_node=str(proxy_node or ""),
        executor_type=str(executor_type or "protocol"),
        captcha_solver=str(captcha_solver or "yescaptcha"),
        extra=merged_extra,
    )


class BusinessCSVRunner:
    _instance: "BusinessCSVRunner | None" = None
    _instance_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "BusinessCSVRunner":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._logs: collections.deque[str] = collections.deque(maxlen=_RECENT_LOGS_MAX)
        self._rt_lock = threading.Lock()
        self._at_lock = threading.Lock()
        self._activate_lock = threading.Lock()
        self._rt_state: dict[str, Any] = self._empty_worker_state("rt")
        self._at_state: dict[str, Any] = self._empty_worker_state("at")
        self._activate_state: dict[str, Any] = self._empty_worker_state("activate")
        self._rt_stop = threading.Event()
        self._at_stop = threading.Event()
        self._activate_stop = threading.Event()

    @staticmethod
    def _empty_worker_state(action: str) -> dict[str, Any]:
        return {
            "action": action,
            "running": False,
            "stopping": False,
            "scope": "",
            "total": 0,
            "done": 0,
            "success": 0,
            "failed": 0,
            "concurrency": 0,
            "started_at": "",
            "finished_at": "",
            "last_error": "",
        }

    def _log(self, message: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
        self._logs.append(line)
        try:
            print(f"[business-csv] {message}", flush=True)
        except Exception:
            pass

    # ────────────────────────── registration ──────────────────────────

    def start_register(self, *, count: int, concurrency: int,
                       executor_type: str = "protocol", captcha_solver: str = "yescaptcha",
                       mail_provider: str = "cfworker", proxy: str = "",
                       proxy_node: str = "", register_delay_seconds: float = 0,
                       role: Any = _DEFAULT_ROLE, seat_type: Any = _DEFAULT_SEAT_TYPE,
                       extra: dict | None = None,
                       cfworker_domain_override: str = "",
                       cfworker_subdomain_mode: str = "managed",
                       cfworker_subdomain_prefix: str = "acc",
                       cfworker_subdomain_max_accounts: Any = 100) -> dict[str, Any]:
        from api.tasks import enqueue_register_task

        req = build_business_csv_register_request(
            count=count,
            concurrency=concurrency,
            executor_type=executor_type,
            captcha_solver=captcha_solver,
            mail_provider=mail_provider,
            proxy=proxy,
            proxy_node=proxy_node,
            register_delay_seconds=register_delay_seconds,
            role=role,
            seat_type=seat_type,
            extra=extra,
            cfworker_domain_override=cfworker_domain_override,
            cfworker_subdomain_mode=cfworker_subdomain_mode,
            cfworker_subdomain_prefix=cfworker_subdomain_prefix,
            cfworker_subdomain_max_accounts=cfworker_subdomain_max_accounts,
        )
        task_id = enqueue_register_task(
            req,
            source=BUSINESS_CSV_SOURCE,
            meta={
                "task_mode": BUSINESS_CSV_SOURCE,
                "count": req.count,
                "role": normalize_business_csv_role(role),
                "seat_type": normalize_business_csv_seat_type(seat_type),
            },
        )
        self._log(f"注册任务已启动 task={task_id} count={req.count}")
        return {"ok": True, "task_id": task_id}

    # ──────────────────────────── queries ─────────────────────────────

    def _query_targets(self, account_ids: list[int] | None = None) -> list[AccountModel]:
        """返回 business_csv 账号：account_ids 给定则取交集，否则取全部。"""
        ids: list[int] | None = None
        if account_ids:
            ids = []
            for raw in account_ids:
                try:
                    value = int(raw)
                except Exception:
                    continue
                if value > 0:
                    ids.append(value)
            if not ids:
                return []
        with Session(engine) as s:
            stmt = (
                select(AccountModel)
                .where(AccountModel.platform == "chatgpt")
                .where(AccountModel.extra_json.contains(BUSINESS_CSV_MARKER))
            )
            if ids is not None:
                stmt = stmt.where(AccountModel.id.in_(ids))  # type: ignore[attr-defined]
            rows = s.exec(stmt.order_by(AccountModel.id.desc())).all()
        return [row for row in rows if _is_business_csv_account(_account_extra(row))]

    def _aggregate_counts(self) -> dict[str, Any]:
        counts: dict[str, Any] = {"total": 0, "statuses": {}, "rt_ready": 0, "at_ready": 0}
        for row in self._query_targets():
            extra = _account_extra(row)
            counts["total"] += 1
            st = str(extra.get("business_csv_status") or row.status or "unknown")
            counts["statuses"][st] = counts["statuses"].get(st, 0) + 1
            if _has_chatgpt_rt(extra):
                counts["rt_ready"] += 1
            if str(extra.get("business_csv_at_status") or "") == "at_ready":
                counts["at_ready"] += 1
        return counts

    def status(self) -> dict[str, Any]:
        with self._rt_lock:
            rt_state = dict(self._rt_state)
        with self._at_lock:
            at_state = dict(self._at_state)
        with self._activate_lock:
            activate_state = dict(self._activate_state)
        return {
            "ok": True,
            "counts": self._aggregate_counts(),
            "rt_state": rt_state,
            "at_state": at_state,
            "activate_state": activate_state,
            "logs": list(self._logs)[-200:],
        }

    def list_accounts(self, *, page: int = 1, page_size: int = 50,
                      business_csv_status: str = "",
                      downloaded: str = "",
                      account_ids: list[int] | None = None) -> dict[str, Any]:
        rows = self._query_targets(account_ids)
        # business_csv_status 支持逗号分隔多值(用于「已导出未授权」这类复合过滤)。
        status_set = {
            s.strip() for s in str(business_csv_status or "").split(",") if s.strip()
        }
        if status_set:
            rows = [
                r for r in rows
                if str(_account_extra(r).get("business_csv_status") or "") in status_set
            ]
        # downloaded 过滤: yes=只看已下载, no=只看未下载, 其它=不过滤。
        dl_filter = str(downloaded or "").strip().lower()
        if dl_filter in {"yes", "no"}:
            want = dl_filter == "yes"
            rows = [
                r for r in rows
                if bool(_account_extra(r).get("business_csv_downloaded")) == want
            ]
        total = len(rows)
        page = max(1, int(page or 1))
        page_size = max(1, min(500, int(page_size or 50)))
        page_rows = rows[(page - 1) * page_size: page * page_size]
        items = []
        for row in page_rows:
            extra = _account_extra(row)
            items.append({
                "id": row.id,
                "email": row.email,
                "status": row.status,
                "business_csv_status": extra.get("business_csv_status", ""),
                "business_csv_role": extra.get("business_csv_role", _DEFAULT_ROLE),
                "business_csv_seat_type": extra.get("business_csv_seat_type", _DEFAULT_SEAT_TYPE),
                # has_rt 只认「真正获取过 ChatGPT RT」的账号：
                # Outlook 账号 extra 里的 refresh_token 是微软邮箱的 RT(用于读 OTP 邮件),
                # 不是 ChatGPT RT, 所以不能用它判断。真正拿到 RT 时 _rt_one 会写
                # business_csv_rt_acquired_at 并把状态置 rt_ready。
                "has_rt": _has_chatgpt_rt(extra),
                "has_at": bool(
                    str(extra.get("business_csv_at_status") or "") == "at_ready"
                    and str(extra.get("access_token") or row.token or "").strip()
                    and str(extra.get("business_csv_at_account_id") or "").strip()
                ),
                "at_expires_at": extra.get("business_csv_at_expires_at") or "",
                "at_error": extra.get("business_csv_at_error", ""),
                "rt_error": extra.get("business_csv_rt_error") or extra.get("rt_acquisition_error") or extra.get("rt_auto_last_error") or "",
                "activate_error": extra.get("business_csv_activate_error", ""),
                "downloaded": bool(extra.get("business_csv_downloaded")),
                "downloaded_at": extra.get("business_csv_downloaded_at") or "",
                "created_at": row.created_at.isoformat() if row.created_at else "",
                "updated_at": row.updated_at.isoformat() if row.updated_at else "",
            })
        return {"total": total, "page": page, "page_size": page_size, "items": items}

    # ───────────────────────────── export ─────────────────────────────

    def export_csv(self, *, account_ids: list[int] | None = None,
                   scope: str = "all", count: int | None = None) -> dict[str, Any]:
        scope = str(scope or "all").strip().lower()
        if scope == "selected":
            if not account_ids:
                return {"ok": False, "error": "请先勾选要导出的账号"}
            accounts = self._query_targets(account_ids)
            scope_label = "selected"
        else:
            accounts = self._query_targets()
            scope_label = "all"
        if not accounts:
            return {"ok": False, "error": "没有可导出的账号"}
        if count and count > 0:
            accounts = accounts[:count]
        csv_text = build_business_invite_csv(accounts)
        if csv_text.count("\n") <= 1:
            return {"ok": False, "error": "没有有效 email 可写入 CSV"}
        exported_at = _now_iso()
        selected_ids = {int(a.id) for a in accounts if a.id is not None}
        with Session(engine) as s:
            db_rows = s.exec(select(AccountModel).where(AccountModel.id.in_(selected_ids))).all()  # type: ignore[attr-defined]
            for acc in db_rows:
                extra = acc.get_extra()
                extra["business_csv_csv_exported_at"] = exported_at
                extra["business_csv_status"] = "csv_exported"
                acc.set_extra(extra)
                acc.updated_at = datetime.now(timezone.utc)
                s.add(acc)
            s.commit()
        os.makedirs(_EXPORT_ROOT, exist_ok=True)
        filename = f"business_invites_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = os.path.join(_EXPORT_ROOT, filename)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(csv_text)
        self._log(f"CSV 已生成 scope={scope_label} count={len(accounts)} path={path}")
        return {
            "ok": True,
            "scope": scope_label,
            "count": len(accounts),
            "csv": csv_text,
            "path": path,
            "filename": filename,
        }

    def mark_uploaded(self, *, account_ids: list[int] | None = None,
                      scope: str = "all") -> dict[str, Any]:
        scope = str(scope or "all").strip().lower()
        if scope == "selected":
            if not account_ids:
                return {"ok": False, "error": "请先勾选要标记的账号"}
            accounts = self._query_targets(account_ids)
        else:
            accounts = self._query_targets()
        uploaded_at = _now_iso()
        ids = [int(a.id) for a in accounts if a.id is not None]
        if not ids:
            return {"ok": False, "error": "没有可标记的账号"}
        with Session(engine) as s:
            db_rows = s.exec(select(AccountModel).where(AccountModel.id.in_(ids))).all()  # type: ignore[attr-defined]
            for acc in db_rows:
                extra = acc.get_extra()
                extra["business_csv_status"] = "csv_uploaded"
                extra["business_csv_uploaded_at"] = uploaded_at
                extra.pop("business_csv_activate_error", None)
                acc.set_extra(extra)
                acc.updated_at = datetime.now(timezone.utc)
                s.add(acc)
            s.commit()
        self._log(f"已标记 CSV 上传 count={len(ids)}")
        return {"ok": True, "updated": len(ids)}

    def delete_accounts(self, *, account_ids: list[int] | None = None,
                        scope: str = "all") -> dict[str, Any]:
        """删除 business_csv 账号：scope=selected 删勾选，否则删全部。"""
        scope = str(scope or "all").strip().lower()
        if scope == "selected":
            if not account_ids:
                return {"ok": False, "error": "请先勾选要删除的账号"}
            accounts = self._query_targets(account_ids)
        else:
            accounts = self._query_targets()
        ids = [int(a.id) for a in accounts if a.id is not None]
        if not ids:
            return {"ok": False, "error": "没有可删除的账号"}
        with Session(engine) as s:
            rows = s.exec(select(AccountModel).where(AccountModel.id.in_(ids))).all()  # type: ignore[attr-defined]
            for acc in rows:
                s.delete(acc)
            s.commit()
        self._log(f"删除账号 scope={scope} count={len(ids)}")
        return {"ok": True, "deleted": len(ids)}

    # ─────────────────── streaming pool with graceful stop ────────────

    def _run_pool(self, *, ids: list[int], concurrency: int, worker: Callable[[int], dict],
                  lock: threading.Lock, state: dict, stop_event: threading.Event) -> None:
        """流式线程池：已提交的任务做完，收到 stop 后不再提交新任务。"""
        ids_iter = iter(ids)
        concurrency = max(1, int(concurrency or 1))
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="bizcsv") as ex:
            futures = set()
            for _ in range(concurrency):
                try:
                    aid = next(ids_iter)
                except StopIteration:
                    break
                futures.add(ex.submit(worker, aid))
            while futures:
                done, futures = wait(futures, return_when=FIRST_COMPLETED)
                for fut in done:
                    try:
                        result = fut.result()
                    except Exception as exc:
                        result = {"ok": False, "error": str(exc)}
                    with lock:
                        state["done"] += 1
                        if result.get("ok"):
                            state["success"] += 1
                        else:
                            state["failed"] += 1
                            state["last_error"] = str(result.get("error") or "")[:300]
                if stop_event.is_set():
                    continue
                for _ in range(len(done)):
                    try:
                        aid = next(ids_iter)
                    except StopIteration:
                        break
                    futures.add(ex.submit(worker, aid))

    def stop_rt(self) -> dict[str, Any]:
        with self._rt_lock:
            if not self._rt_state.get("running"):
                return {"ok": False, "error": "RT 任务未在运行"}
            self._rt_stop.set()
            self._rt_state["stopping"] = True
        self._log("请求停止 RT 任务(已在跑的做完)")
        return {"ok": True}

    def stop_at(self) -> dict[str, Any]:
        with self._at_lock:
            if not self._at_state.get("running"):
                return {"ok": False, "error": "AT 任务未在运行"}
            self._at_stop.set()
            self._at_state["stopping"] = True
        self._log("请求停止 AT 任务(已在跑的做完)")
        return {"ok": True}

    def stop_activate(self) -> dict[str, Any]:
        with self._activate_lock:
            if not self._activate_state.get("running"):
                return {"ok": False, "error": "激活任务未在运行"}
            self._activate_stop.set()
            self._activate_state["stopping"] = True
        self._log("请求停止激活任务(已在跑的做完)")
        return {"ok": True}

    # ──────────────────────────── activate ────────────────────────────

    def start_activate(self, *, concurrency: int = 5,
                       account_ids: list[int] | None = None,
                       scope: str = "all") -> dict[str, Any]:
        scope = str(scope or "all").strip().lower()
        if scope == "selected" and not account_ids:
            return {"ok": False, "error": "请先勾选要激活的账号"}
        with self._activate_lock:
            if self._activate_state.get("running"):
                return {"ok": False, "error": "BUSINESS CSV 激活任务正在运行"}
            accounts = self._query_targets(account_ids if scope == "selected" else None)
            targets = [a for a in accounts if str(_account_extra(a).get("business_csv_status") or "") in {"csv_uploaded", "activate_failed"}]
            self._activate_stop.clear()
            self._activate_state = self._empty_worker_state("activate")
            self._activate_state.update({
                "running": True,
                "scope": "selected" if scope == "selected" else "all",
                "total": len(targets),
                "concurrency": max(1, min(20, int(concurrency or 5))),
                "started_at": _now_iso(),
            })
        if not targets:
            with self._activate_lock:
                self._activate_state["running"] = False
                self._activate_state["finished_at"] = _now_iso()
            return {"ok": False, "error": "没有 csv_uploaded/activate_failed 状态的账号可激活"}
        ids = [int(a.id) for a in targets if a.id is not None]
        concurrency = self._activate_state["concurrency"]
        threading.Thread(
            target=self._run_activate_batch,
            args=(ids, concurrency),
            daemon=True,
            name="business-csv-activate",
        ).start()
        self._log(f"激活任务启动 count={len(ids)} concurrency={concurrency}")
        return {"ok": True, "queued": len(ids)}

    def _run_activate_batch(self, account_ids: list[int], concurrency: int) -> None:
        try:
            self._run_pool(
                ids=account_ids, concurrency=concurrency, worker=self._activate_one,
                lock=self._activate_lock, state=self._activate_state, stop_event=self._activate_stop,
            )
        finally:
            with self._activate_lock:
                self._activate_state["running"] = False
                self._activate_state["stopping"] = False
                self._activate_state["finished_at"] = _now_iso()
            self._log("激活任务结束")

    def _activate_one(self, account_id: int) -> dict[str, Any]:
        from core.config_store import config_store
        from platforms.chatgpt.plugin import _activate_invite_via_email

        with Session(engine) as s:
            acc = s.get(AccountModel, account_id)
            if not acc:
                return {"ok": False, "error": "账号不存在"}
            email = acc.email
            extra = acc.get_extra()
            extra["business_csv_status"] = "activating"
            extra.pop("business_csv_activate_error", None)
            acc.set_extra(extra)
            acc.updated_at = datetime.now(timezone.utc)
            s.add(acc)
            s.commit()
        cfworker_api_url = str(config_store.get("cfworker_api_url", "") or "").strip()
        cfworker_admin_token = str(config_store.get("cfworker_admin_token", "") or "").strip()
        cfworker_custom_auth = str(config_store.get("cfworker_custom_auth", "") or "").strip()
        proxy = str(extra.get("register_proxy") or config_store.get("default_proxy", "") or "").strip()
        call_extra = dict(extra)
        call_extra["business_email"] = email
        call_extra.setdefault("email", email)
        result = _activate_invite_via_email(
            call_extra,
            cfworker_api_url,
            cfworker_admin_token,
            self._log,
            proxy=proxy,
            cfworker_custom_auth=cfworker_custom_auth,
            timeout_seconds=180,
        )
        with Session(engine) as s:
            acc = s.get(AccountModel, account_id)
            if not acc:
                return {"ok": False, "error": "账号已删除"}
            extra = acc.get_extra()
            if result.get("ok"):
                extra["business_csv_status"] = "activated"
                extra["business_csv_activated_at"] = _now_iso()
                extra.pop("business_csv_activate_error", None)
                if result.get("invite_url"):
                    extra["business_csv_invite_url"] = str(result.get("invite_url"))[:300]
                ok = True
                err = ""
            else:
                err = str(result.get("error") or "激活失败")
                extra["business_csv_status"] = "activate_failed"
                extra["business_csv_activate_error"] = err[:500]
                ok = False
            acc.set_extra(extra)
            acc.updated_at = datetime.now(timezone.utc)
            s.add(acc)
            s.commit()
        if ok:
            self._log(f"激活成功 {email}")
            return {"ok": True, "email": email}
        self._log(f"激活失败 {email}: {err[:160]}")
        return {"ok": False, "email": email, "error": err}

    # ──────────────────────────────  RT  ──────────────────────────────

    def start_rt(self, *, concurrency: int = 5,
                 account_ids: list[int] | None = None,
                 max_retries: int | None = None,
                 scope: str = "all",
                 browser_mode: str = "protocol") -> dict[str, Any]:
        with self._rt_lock, self._at_lock:
            if self._rt_state.get("running"):
                return {"ok": False, "error": "BUSINESS CSV RT 任务正在运行"}
            if self._at_state.get("running"):
                return {"ok": False, "error": "BUSINESS CSV AT 任务正在运行,请等待完成"}
            scope = str(scope or "all").strip().lower()
            browser_mode = str(browser_mode or "protocol").strip().lower()
            if browser_mode not in {"protocol", "headless", "headed"}:
                browser_mode = "protocol"
            if scope == "selected":
                if not account_ids:
                    return {"ok": False, "error": "请先勾选需要获取 RT 的账号"}
                accounts = self._query_targets(account_ids)
                scope_label = "selected"
            else:
                accounts = self._query_targets()
                scope_label = "all"
            targets = []
            for acc in accounts:
                extra = _account_extra(acc)
                # 已拿到 ChatGPT RT 的跳过。注意: 不能用 extra["refresh_token"] 判断,
                # 那是 Outlook 邮箱 RT(读 OTP 用), 不是 ChatGPT RT; 只有真正获取过
                # ChatGPT RT 时才会置状态 rt_ready(见 _has_chatgpt_rt)。
                if _has_chatgpt_rt(extra):
                    continue
                csv_status = str(extra.get("business_csv_status") or "")
                if csv_status in {"csv_uploaded", "activated", "rt_failed", "registered", "csv_exported"}:
                    targets.append(acc)
            self._rt_stop.clear()
            self._rt_state = self._empty_worker_state("rt")
            self._rt_state.update({
                "running": True,
                "scope": scope_label,
                "total": len(targets),
                "concurrency": max(1, min(20, int(concurrency or 5))),
                "started_at": _now_iso(),
                "max_retries": max_retries,
                "browser_mode": browser_mode,
            })
        if not targets:
            with self._rt_lock:
                self._rt_state["running"] = False
                self._rt_state["finished_at"] = _now_iso()
            return {"ok": False, "error": "没有需要补 RT 的账号"}
        ids = [int(a.id) for a in targets if a.id is not None]
        concurrency = self._rt_state["concurrency"]
        threading.Thread(
            target=self._run_rt_batch,
            args=(ids, concurrency, max_retries, browser_mode),
            daemon=True,
            name="business-csv-rt",
        ).start()
        self._log(
            f"RT 任务启动 scope={scope_label} count={len(ids)} "
            f"concurrency={concurrency} browser_mode={browser_mode}"
        )
        return {"ok": True, "scope": scope_label, "queued": len(ids)}

    def _run_rt_batch(self, account_ids: list[int], concurrency: int,
                      max_retries: int | None, browser_mode: str) -> None:
        try:
            self._run_pool(
                ids=account_ids, concurrency=concurrency,
                worker=lambda aid: self._rt_one(aid, max_retries, browser_mode),
                lock=self._rt_lock, state=self._rt_state, stop_event=self._rt_stop,
            )
        finally:
            with self._rt_lock:
                self._rt_state["running"] = False
                self._rt_state["stopping"] = False
                self._rt_state["finished_at"] = _now_iso()
            self._log("RT 任务结束")
            # RT 跑完后, 对涉及的母号自动重解析空间信息(best-effort)
            try:
                self._refresh_masters_stats_for_accounts(account_ids)
            except Exception:
                pass

    def _refresh_masters_stats_for_accounts(self, account_ids: list[int]) -> None:
        """找出这批账号归属的母号, 逐个重解析并缓存空间信息。"""
        if not account_ids:
            return
        master_ids: set[str] = set()
        with Session(engine) as s:
            for aid in account_ids:
                acc = s.get(AccountModel, aid)
                if not acc:
                    continue
                mid = str(_account_extra(acc).get("business_master_id") or "").strip()
                if mid:
                    master_ids.add(mid)
        if not master_ids:
            return
        from api.business_masters import _refresh_stats_safe
        for mid in master_ids:
            try:
                _refresh_stats_safe(int(mid))
            except Exception:
                pass

    def _rt_one(self, account_id: int, max_retries: int | None,
                browser_mode: str = "protocol") -> dict[str, Any]:
        from services.business_rt_loop import BusinessRTLoopRunner

        with Session(engine) as s:
            acc = s.get(AccountModel, account_id)
            if not acc:
                return {"ok": False, "error": "账号不存在"}
            email = acc.email
            extra = acc.get_extra()
            extra["business_csv_status"] = "rt_running"
            extra.pop("business_csv_rt_error", None)
            acc.set_extra(extra)
            acc.updated_at = datetime.now(timezone.utc)
            s.add(acc)
            s.commit()
        # 先记「开始」日志, 这样 UI 在账号刚进入处理时就能看到, 而不是等成功/失败才出现。
        self._log(f"RT 开始 {email} (browser={browser_mode})")
        result = BusinessRTLoopRunner.instance()._fixup_one_rt(
            account_id, max_retries, browser_mode=browser_mode,
        )
        ok = bool(result.get("ok"))
        with Session(engine) as s:
            acc = s.get(AccountModel, account_id)
            if not acc:
                return {"ok": ok, "email": email, "deleted": True, "error": result.get("error", "")}
            extra = acc.get_extra()
            if ok:
                extra["business_csv_status"] = "rt_ready"
                extra["business_csv_rt_acquired_at"] = _now_iso()
                extra.pop("business_csv_rt_error", None)
            else:
                extra["business_csv_status"] = "rt_failed"
                extra["business_csv_rt_error"] = str(result.get("error") or "RT 获取失败")[:500]
            acc.set_extra(extra)
            acc.updated_at = datetime.now(timezone.utc)
            s.add(acc)
            s.commit()
        if ok:
            self._log(f"RT 成功 {email}")
        else:
            self._log(f"RT 失败 {email}: {str(result.get('error') or '')[:160]}")
        return result

    # ──────────────────────────────  AT  ──────────────────────────────

    def start_at(self, *, concurrency: int = 3,
                 account_ids: list[int] | None = None,
                 scope: str = "all", browser_mode: str = "headless") -> dict[str, Any]:
        with self._rt_lock, self._at_lock:
            if self._at_state.get("running"):
                return {"ok": False, "error": "BUSINESS CSV AT 任务正在运行"}
            if self._rt_state.get("running"):
                return {"ok": False, "error": "BUSINESS CSV RT 任务正在运行,请等待完成"}
            scope = str(scope or "all").strip().lower()
            browser_mode = str(browser_mode or "headless").strip().lower()
            if browser_mode not in {"headless", "headed"}:
                return {"ok": False, "error": "获取 AT 必须使用无头或可见浏览器"}
            if scope == "selected":
                if not account_ids:
                    return {"ok": False, "error": "请先勾选需要获取 AT 的账号"}
                accounts = self._query_targets(account_ids)
                scope_label = "selected"
            else:
                accounts = self._query_targets()
                scope_label = "all"
            targets = [a for a in accounts if a.id is not None]
            self._at_stop.clear()
            self._at_state = self._empty_worker_state("at")
            self._at_state.update({
                "running": True,
                "scope": scope_label,
                "total": len(targets),
                "concurrency": max(1, min(20, int(concurrency or 3))),
                "started_at": _now_iso(),
                "browser_mode": browser_mode,
            })
        if not targets:
            with self._at_lock:
                self._at_state["running"] = False
                self._at_state["finished_at"] = _now_iso()
            return {"ok": False, "error": "没有可获取 AT 的账号"}
        ids = [int(a.id) for a in targets]
        concurrency = self._at_state["concurrency"]
        threading.Thread(
            target=self._run_at_batch,
            args=(ids, concurrency, browser_mode),
            daemon=True,
            name="business-csv-at",
        ).start()
        self._log(
            f"AT 任务启动 scope={scope_label} count={len(ids)} "
            f"concurrency={concurrency} browser_mode={browser_mode}"
        )
        return {"ok": True, "scope": scope_label, "queued": len(ids)}

    def _run_at_batch(self, account_ids: list[int], concurrency: int,
                      browser_mode: str) -> None:
        try:
            self._run_pool(
                ids=account_ids, concurrency=concurrency,
                worker=lambda aid: self._at_one(aid, browser_mode),
                lock=self._at_lock, state=self._at_state, stop_event=self._at_stop,
            )
        finally:
            with self._at_lock:
                self._at_state["running"] = False
                self._at_state["stopping"] = False
                self._at_state["finished_at"] = _now_iso()
            self._log("AT 任务结束")

    def _acquire_at_for_account(self, account_id: int, browser_mode: str) -> dict[str, Any]:
        from services.business_rt_loop import BusinessRTLoopRunner
        from platforms.chatgpt.gpt_pro_login import (
            acquire_business_at_via_cookies,
            acquire_business_at_via_login,
        )
        from platforms.chatgpt.plugin import _BusinessOAuthEmailAdapter

        with Session(engine) as s:
            acc = s.get(AccountModel, account_id)
            if not acc:
                raise RuntimeError("账号不存在")
            email = acc.email
            password = acc.password or ""
            extra = acc.get_extra()
        runner = BusinessRTLoopRunner.instance()
        config_input = dict(extra or {})
        config_input.setdefault("email", email)
        config_input.setdefault("password", password)
        extra_config = runner._build_rt_fixup_extra_config(config_input)
        proxy, proxy_source = runner._pick_proxy_with_source(extra_config)
        headless = browser_mode == "headless"
        self._log(f"[AT {email}] 浏览器模式={browser_mode},代理来源={proxy_source}")

        # ① 优先用注册时保存的 Cookie 直接登录 chatgpt.com、选第一个空间取 AT(免验证码,
        #    更快也更稳,不用再过 OTP / CF)。Cookie 失效则自动回退到验证码登录。
        cookies = _parse_saved_cookies(extra)
        if cookies:
            try:
                self._log(f"[AT {email}] 优先尝试 Cookie 免登录取 AT(共 {len(cookies)} 个 cookie)")
                return acquire_business_at_via_cookies(
                    email,
                    cookies=cookies,
                    headless=headless,
                    proxy=proxy or "",
                    log_fn=self._log,
                )
            except Exception as exc:
                self._log(f"[AT {email}] Cookie 免登录失败({str(exc)[:140]}), 回退验证码登录")

        # ② 回退: 验证码登录
        adapter = extra_config.get("_otp_email_adapter")
        if adapter is None:
            api_url = str(extra_config.get("cfworker_api_url") or "").strip()
            admin_token = str(extra_config.get("cfworker_admin_token") or "").strip()
            if not api_url or not admin_token:
                raise RuntimeError("无法构建 OTP 邮箱适配器: CF Worker/Outlook 邮箱配置缺失")
            adapter = _BusinessOAuthEmailAdapter(
                email=email,
                api_url=api_url,
                admin_token=admin_token,
                custom_auth=str(extra_config.get("cfworker_custom_auth") or ""),
                log_fn=self._log,
            )
        return acquire_business_at_via_login(
            email,
            email_adapter=adapter,
            headless=headless,
            proxy=proxy or "",
            log_fn=self._log,
        )

    def _at_one(self, account_id: int, browser_mode: str = "headless") -> dict[str, Any]:
        with Session(engine) as s:
            acc = s.get(AccountModel, account_id)
            if not acc:
                return {"ok": False, "error": "账号不存在"}
            email = acc.email
            extra = acc.get_extra()
            extra["business_csv_at_status"] = "at_running"
            extra.pop("business_csv_at_error", None)
            acc.set_extra(extra)
            acc.updated_at = datetime.now(timezone.utc)
            s.add(acc)
            s.commit()
        try:
            result = self._acquire_at_for_account(account_id, browser_mode)
            access_token = str(result.get("access_token") or "").strip()
            if not access_token:
                raise RuntimeError("/api/auth/session 未返回 accessToken")
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if not acc:
                    return {"ok": False, "email": email, "error": "账号已不存在"}
                extra = acc.get_extra()
                extra["access_token"] = access_token
                if result.get("session_token"):
                    extra["session_token"] = str(result.get("session_token"))
                extra["business_csv_at_account_id"] = str(result.get("account_id") or "")
                extra["business_csv_at_plan_type"] = str(result.get("plan_type") or "")
                extra["business_csv_at_acquired_at"] = _now_iso()
                extra["business_csv_at_expires_at"] = str(result.get("expires_at") or "")
                extra["business_csv_at_status"] = "at_ready"
                extra.pop("business_csv_at_error", None)
                acc.token = access_token
                acc.set_extra(extra)
                acc.updated_at = datetime.now(timezone.utc)
                s.add(acc)
                s.commit()
            self._log(f"AT 成功 {email} workspace={result.get('account_id') or '-'}")
            return {"ok": True, "id": account_id, "email": email, **result}
        except Exception as exc:
            error = str(exc)
            deactivated = "account_deactivated" in error.lower()
            with Session(engine) as s:
                acc = s.get(AccountModel, account_id)
                if acc:
                    extra = acc.get_extra()
                    if deactivated:
                        # 账号已被 OpenAI 停用/删除, 单独标记, 方便在列表里筛出并删除。
                        extra["business_csv_at_status"] = "account_deactivated"
                        extra["business_csv_status"] = "deactivated"
                    else:
                        extra["business_csv_at_status"] = "at_failed"
                    extra["business_csv_at_error"] = error[:500]
                    acc.set_extra(extra)
                    acc.updated_at = datetime.now(timezone.utc)
                    s.add(acc)
                    s.commit()
            self._log(
                f"AT {'账号已停用/删除' if deactivated else '失败'} {email}: {error[:160]}"
            )
            return {"ok": False, "id": account_id, "email": email, "error": error,
                    "account_deactivated": deactivated}

    # ─────────────────────────── final export ─────────────────────────

    def export_ready(self, *, count: int, format: str = "cpa",
                     account_ids: list[int] | None = None,
                     scope: str = "all",
                     delete_after_export: bool = False,
                     mark_downloaded: bool = False) -> dict[str, Any]:
        fmt = str(format or "cpa").strip().lower()
        if fmt not in {"cpa", "sub2api", "kanwang"}:
            return {"ok": False, "error": "format 必须是 cpa/sub2api/kanwang"}
        scope = str(scope or "all").strip().lower()
        if scope == "selected" and not account_ids:
            return {"ok": False, "error": "请先勾选要导出的账号"}
        pool = self._query_targets(account_ids if scope == "selected" else None)

        def _has_rt(a) -> bool:
            extra = _account_extra(a)
            return _has_chatgpt_rt(extra) and bool(str(extra.get("refresh_token") or "").strip())

        def _has_at(a) -> bool:
            extra = _account_extra(a)
            return (
                str(extra.get("business_csv_at_status") or "") == "at_ready"
                and bool(str(extra.get("access_token") or a.token or "").strip())
            )

        limit = max(1, int(count or 1))
        if fmt == "kanwang":
            # 卡网是 refresh_token 格式, 只能导出带真正 ChatGPT RT 的账号。
            accounts = [a for a in pool if _has_rt(a)][:limit]
            if not accounts:
                return {"ok": False, "error": "没有带 ChatGPT RT 的账号(卡网格式必须有 RT)"}
        else:
            # CPA / SUB2API: 有 RT 或 有 AT 均可导出。
            accounts = [a for a in pool if _has_rt(a) or _has_at(a)][:limit]
            if not accounts:
                return {"ok": False, "error": "没有可导出的账号(需要带 RT 或 AT)"}
            # 只有 AT 的账号: 清掉 extra 里的邮箱 refresh_token(那是微软邮箱 RT, 不是
            # ChatGPT RT), 避免把错误的 RT 写进 CPA/SUB2API 文件。仅改内存对象, 不落库。
            for a in accounts:
                if not _has_rt(a):
                    cleaned = dict(_account_extra(a))
                    cleaned["refresh_token"] = ""
                    a.set_extra(cleaned)
        from services.business_rt_loop import BusinessRTLoopRunner

        runner = BusinessRTLoopRunner.instance()
        payloads = runner._build_export_payloads(accounts, fmt)
        export_id = f"bizcsv_{uuid.uuid4().hex[:12]}"
        os.makedirs(_EXPORT_ROOT, exist_ok=True)
        file_path = runner._write_export_file(export_id, fmt, payloads)
        if delete_after_export:
            ids = [int(a.id) for a in accounts if a.id is not None]
            with Session(engine) as s:
                db_rows = s.exec(select(AccountModel).where(AccountModel.id.in_(ids))).all()  # type: ignore[attr-defined]
                for acc in db_rows:
                    s.delete(acc)
                s.add(TaskLog(
                    platform="chatgpt",
                    email=f"business_csv_export:{len(ids)}",
                    status="exported",
                    detail_json=json.dumps({"export_id": export_id, "file_path": file_path}, ensure_ascii=False),
                ))
                s.commit()
        elif mark_downloaded:
            # 「下载即标记」: 把导出的账号打上已下载标记, 供列表按已/未下载过滤。
            downloaded_at = _now_iso()
            ids = [int(a.id) for a in accounts if a.id is not None]
            if ids:
                with Session(engine) as s:
                    db_rows = s.exec(select(AccountModel).where(AccountModel.id.in_(ids))).all()  # type: ignore[attr-defined]
                    for acc in db_rows:
                        extra = acc.get_extra()
                        extra["business_csv_downloaded"] = True
                        extra["business_csv_downloaded_at"] = downloaded_at
                        acc.set_extra(extra)
                        acc.updated_at = datetime.now(timezone.utc)
                        s.add(acc)
                    s.commit()
        filename = os.path.basename(file_path)
        self._log(f"授权文件导出 count={len(accounts)} path={file_path}")
        return {
            "ok": True,
            "count": len(accounts),
            "format": fmt,
            "export_id": export_id,
            "file_path": file_path,
            "filename": filename,
            "download_url": f"/api/business-csv/exports/{export_id}/download",
        }

    @staticmethod
    def find_export_file(export_id: str) -> str:
        safe = _safe_filename(export_id, "")
        if not safe:
            return ""
        candidates = []
        # BusinessRTLoopRunner writes into exports/business_rt_loop; keep compatibility.
        for root in (_EXPORT_ROOT, os.path.abspath(os.path.join(os.getcwd(), "exports", "business_rt_loop"))):
            if not os.path.isdir(root):
                continue
            for name in os.listdir(root):
                if safe in name:
                    path = os.path.join(root, name)
                    if os.path.isfile(path):
                        candidates.append(path)
        return sorted(candidates, key=lambda p: os.path.getmtime(p), reverse=True)[0] if candidates else ""

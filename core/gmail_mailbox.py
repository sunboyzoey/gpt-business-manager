"""Gmail plus-alias mailbox: leased registration or exact fixed-account reads."""
from __future__ import annotations

from email.utils import getaddresses
import time

from core.base_mailbox import BaseMailbox, MailboxAccount, _extract_trusted_chatgpt_password_link, _mail_time_is_fresh
from services import gmail_registration as registration
from services import gmail_store as store
from services.gmail_transport import GmailTransport, GmailTransportError


_READ_ERRORS = {
    "auth_required": "应用专用密码授权失效", "authentication_failed": "应用专用密码授权失效",
    "timeout": "连接超时", "network_error": "网络连接失败", "tls_error": "安全连接失败",
}


class GmailMailboxReadError(RuntimeError):
    """Fixed local classification; never carries a transport exception body."""
    def __init__(self, code):
        self.code = code if code in _READ_ERRORS else "mail_service_unavailable"
        self.reason = _READ_ERRORS.get(self.code, "邮件服务暂时不可用")
        super().__init__("Gmail 收件失败：" + self.reason)


class GmailMailbox(BaseMailbox):
    def __init__(self, extra: dict | None = None, proxy: str | None = None):
        self.extra = dict(extra or {})
        self.proxy = proxy or ""
        self._last_email = None
        self._claim = None
        self._baseline = set()
        self._baseline_at = time.time()
        self._fixed = bool(self.extra.get("gmail_fixed_account") or self.extra.get("gmail_fixed_email"))
        # An explicit fixed email never allocates an unrelated alias.
        self._fixed_email = str(self.extra.get("gmail_fixed_email") or self.extra.get("email") or "").strip().lower()
        if self._fixed_email:
            self._fixed = True

    def _account(self, row):
        return MailboxAccount(email=row["email"], account_id=str(row["id"]), extra={
            "mail_provider": "gmail", "gmail_source_id": row["source_id"], "gmail_alias_id": row["id"],
            "gmail_registration_resume": bool(row.get("registration_resume")),
        })

    def fixed_account(self) -> MailboxAccount:
        row = registration.resolve_fixed_alias(self._fixed_email,
            source_id=self.extra.get("gmail_source_id"), alias_id=self.extra.get("gmail_alias_id"))
        registration.require_receive_ready(row["id"])
        self._last_email = self._account(row)
        return self._last_email

    def get_email(self) -> MailboxAccount:
        if self._last_email:
            return self._last_email
        if self._fixed:
            return self.fixed_account()
        self._claim = registration.claim_alias(
            task_id=self.extra.get("gmail_task_id") or self.extra.get("_task_id") or "",
            source_id=self.extra.get("gmail_source_id"), alias_ids=self.extra.get("gmail_alias_ids"),
            allow_retry=bool(self.extra.get("_gmail_retry") or self.extra.get("gmail_allow_retry")), options=self.extra)
        self._last_email = self._account(self._claim)
        return self._last_email

    def registration_started(self, stage: str = "registering", password: str = ""):
        if self._claim:
            registration.mark_started(self._claim["id"], self._claim["lease_token"], stage=stage, password=password)

    def mark_stage(self, stage: str):
        self.registration_started(stage=stage)

    def registration_rejected(self, code: str):
        """Retire an owned production source only for an explicit remote code."""
        if code != "user_already_exists" or not self._claim:
            return False
        registration.block_source_for_claim(self._claim["id"], self._claim["lease_token"])
        self._claim = None
        return True

    def get_registration_password(self) -> str:
        if not self._last_email:
            return ""
        from core.credential_crypto import decrypt_credential
        from core.db import ChatGptAccountSecurityModel
        from sqlmodel import Session
        with Session(store.engine) as session:
            row = session.get(ChatGptAccountSecurityModel, self._last_email.email)
            return decrypt_credential(row.email, "password", row.password_ciphertext) if row and row.password_ciphertext else ""

    def load_registered_account(self):
        if not self._claim or not self._claim.get("registered_account_id"):
            return None
        from core.db import AccountModel
        from sqlmodel import Session
        with Session(store.engine) as session:
            registration.heartbeat(self._claim["id"], self._claim["lease_token"])
            row = session.get(AccountModel, self._claim["registered_account_id"])
            if row is None or row.email.lower() != self._last_email.email or row.platform != "chatgpt":
                raise store.GmailStoreError("saved_account_missing", "已注册 GPT 账号的本地记录暂不可用，将重试恢复", 409)
            return row

    def resume_saved_account(self):
        """Compatibility for callers expecting the platform Account object."""
        row = self.load_registered_account()
        if row is None:
            return None
        from core.base_platform import Account, AccountStatus
        try:
            status = AccountStatus(row.status)
        except ValueError:
            status = AccountStatus.REGISTERED
        return Account(platform=row.platform, email=row.email, password=row.password, user_id=row.user_id,
                       region=row.region, token=row.token, status=status, extra=row.get_extra())

    def save_account(self, account):
        if not self._claim:
            raise store.GmailStoreError("registration_not_claimed", "Gmail 子号未被当前任务占用", 409)
        saved = registration.persist_registration_account(self._claim["id"], self._claim["lease_token"], account)
        self._claim["registered_account_id"] = saved.id
        return saved

    def checkpoint_remote_registration(self, account):
        if not self._claim:
            return
        if not isinstance(account.extra, dict):
            account.extra = {}
        account.extra.update(self._last_email.extra)
        saved = self.save_account(account)
        registration.complete_registration(self._claim["id"], self._claim["lease_token"], saved, final=False)
        self._claim["registered_account_id"] = saved.id

    def complete_registration(self, saved_account):
        if self._claim:
            result = registration.complete_registration(self._claim["id"], self._claim["lease_token"], saved_account)
            self._claim = None
            return result

    def finalize_account(self, email: str):
        if not self._claim:
            return
        from core.db import AccountModel
        from sqlmodel import Session, select
        with Session(store.engine) as session:
            saved = session.exec(select(AccountModel).where(AccountModel.platform == "chatgpt",
                AccountModel.email == str(email).lower()).order_by(AccountModel.id.desc())).first()
            if saved:
                self.complete_registration(saved)

    def release_account(self, email: str = "", *, cancelled: bool = False, error: str = ""):
        if self._claim:
            registration.release_alias(self._claim["id"], self._claim["lease_token"], cancelled=cancelled, error=error)
            self._claim = None

    def close(self):
        # Transport connections are per call. A retained allocation is released
        # conservatively as interrupted; explicit cancellation was handled earlier.
        if self._claim:
            self.release_account()
        self._last_email = None
        self._baseline.clear()

    def _resolve(self, account):
        email = str(getattr(account, "email", "") or "").strip().lower()
        account_extra = getattr(account, "extra", None) or {}
        source_id = account_extra.get("gmail_source_id")
        alias_id = account_extra.get("gmail_alias_id")
        if self._fixed:
            fixed = registration.resolve_fixed_alias(self._fixed_email,
                source_id=self.extra.get("gmail_source_id"), alias_id=self.extra.get("gmail_alias_id"))
            if email != fixed["email"] or (source_id is not None and source_id != fixed["source_id"]) or (alias_id is not None and alias_id != fixed["id"]):
                raise store.GmailStoreError("alias_mismatch", "Gmail 收件请求与配置的子号不一致", 409)
            source_id, alias_id = fixed["source_id"], fixed["id"]
        row = registration.resolve_fixed_alias(email, source_id=source_id, alias_id=alias_id)
        if self._last_email and email != self._last_email.email:
            raise store.GmailStoreError("alias_mismatch", "Gmail 收件请求与当前子号不一致", 409)
        registration.require_receive_ready(row["id"])
        return row

    def _messages(self, account, limit=100, *, deadline=None):
        self._checkpoint()
        row = self._resolve(account)
        if self._claim:
            registration.heartbeat(self._claim["id"], self._claim["lease_token"])
        snapshot = store.network_snapshot(row["source_id"], row["id"])
        password = store.decrypt_snapshot_password(snapshot)
        try:
            budget = {"deadline": deadline} if deadline is not None else {}
            with GmailTransport(snapshot.email, password, proxy_url=snapshot.proxy_url or self.proxy, **budget) as transport:
                messages = transport.list_messages(row["email"], limit=limit)
        except GmailTransportError as exc:
            if exc.code in {"auth_required", "authentication_failed"}:
                store.record_network_result(snapshot, status=exc.code,
                    message="Gmail 应用专用密码失效，请更新收件授权", checked_at=store.utcnow())
            raise GmailMailboxReadError(exc.code) from None
        finally:
            password = ""
        self._checkpoint()
        # Transport already validates exact envelope headers; enforce it again at adapter boundary.
        return [message for message in messages if row["email"] in {
            str(value).strip().lower() for value in message.get("recipients", [])}]

    def get_current_ids(self, account: MailboxAccount, *, strict: bool = True) -> set:
        if self._claim:
            registration.require_registration_work(self._claim["id"], self._claim["lease_token"])
        started = time.time()
        self._baseline = {str(row["id"]) for row in self._messages(account, 500)}
        self._baseline_at = started
        return set(self._baseline)

    def get_action_link_baseline(self, account: MailboxAccount) -> set:
        return self.get_current_ids(account, strict=True)

    @staticmethod
    def _trusted_sender(message):
        addresses = [address for _, address in getaddresses([str(message.get("from") or "")])]
        if not addresses:
            return False
        for address in addresses:
            if "@" not in address:
                return False
            domain = address.rsplit("@", 1)[1].lower().rstrip(".")
            if not any(domain == root or domain.endswith("." + root) for root in ("openai.com", "chatgpt.com")):
                return False
        return True

    def _wait(self, account, *, timeout, before_ids, not_before, action=False, keyword="", code_pattern=None, exclude_codes=None):
        deadline = time.monotonic() + max(int(timeout or 0), 1)
        seen = {str(value) for value in (before_ids if before_ids is not None else self._baseline)}
        after = not_before if not_before is not None else self._baseline_at
        excluded = {str(value) for value in (exclude_codes or set()) if value}
        def poll():
            for row in self._messages(account, deadline=deadline):
                mid = str(row.get("id") or "")
                if not mid or mid in seen:
                    continue
                seen.add(mid)
                if not self._trusted_sender(row) or not _mail_time_is_fresh(row.get("received_at"), after):
                    continue
                subject, content = str(row.get("subject") or ""), str(row.get("text") or "")
                if action:
                    value = _extract_trusted_chatgpt_password_link(subject=subject, sender=row.get("from"), content=content)
                else:
                    if keyword and keyword.lower() not in (subject + " " + content + " " + str(row.get("from", ""))).lower():
                        continue
                    value = self._safe_extract(subject + " " + content, code_pattern)
                if value and (action or value not in excluded):
                    return value
            return None
        # Keep the original wait deadline, email identity, baseline and seen IDs
        # across connection losses. Only transport-proven transient errors are
        # retried; auth, TLS, identity and task-control errors leave immediately.
        last_failure = None
        retries = 0
        while time.monotonic() < deadline:
            self._checkpoint()
            try:
                value = poll()
                last_failure = None
                if value:
                    return value
            except GmailMailboxReadError as exc:
                if exc.code not in {"network_error", "timeout"}:
                    raise
                self._checkpoint()
                last_failure = exc
                retries += 1
                self._log(f"[Gmail 收件] {exc.reason}，在本次等待时间内重新连接（第 {retries} 次）")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._sleep_with_checkpoint(min(3, remaining))
        self._checkpoint()
        reason = "Gmail 等待新的 GPT 密码邮件超时" if action else "Gmail 等待新的 GPT 验证码超时"
        if last_failure is not None:
            reason += f"；最近一次收件失败：{last_failure.reason}（{last_failure.code}），已在等待时间内自动重试"
        raise TimeoutError(reason)

    def wait_for_code(self, account, keyword="", timeout=120, before_ids=None, code_pattern=None, **kwargs):
        return self._wait(account, timeout=timeout, before_ids=before_ids,
                          not_before=kwargs.get("not_before") or kwargs.get("otp_sent_at"),
                          keyword=keyword, code_pattern=code_pattern, exclude_codes=kwargs.get("exclude_codes"))

    def wait_for_action_link(self, account, *, timeout=120, before_ids=None, not_before=None):
        return self._wait(account, timeout=timeout, before_ids=before_ids, not_before=not_before, action=True)

    def list_recent(self, account, limit=20):
        messages = self._messages(account, limit)
        self._last_list_recent_metadata = {"identity_scheme": "imap_uidvalidity", "identity_version": 3,
            "uidvalidity_verified": True, "folder_coverage": {}}
        return [{"id": row["id"], "from": row.get("from", ""), "subject": row.get("subject", ""),
                 "body": row.get("text", ""), "preview": row.get("text", "")[:300], "is_html": False,
                 "time": row.get("received_at", ""), "received_at": row.get("received_at", ""),
                 "received_time_trusted": bool(row.get("received_at")), "received_at_source": "imap_INTERNALDATE",
                 "identity_scheme": "imap_uidvalidity", "identity_version": 3, "folder": "Gmail"}
                for row in messages]

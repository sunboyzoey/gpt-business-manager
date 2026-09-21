"""
Codex referral SDK + CLI.

Usage as a module:
    from codex_referral import quota, list_referrals, invite
    status, data = invite("foo@bar.com")

Usage as a CLI:
    python3 codex_referral.py quota
    python3 codex_referral.py list
    python3 codex_referral.py invite foo@bar.com bar@baz.com

The script reads the access token from ~/.codex/auth.json, which is kept
fresh by the Codex desktop app. Set CODEX_PROXY=http://127.0.0.1:7890 if
you need to route through a local HTTP proxy.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable

DEFAULT_AUTH_PATH = os.path.expanduser("~/.codex/auth.json")
# 2026: referral 接口从 /backend-api/wham 挪到了 /backend-api(不带 wham)。
BASE_URL = "https://chatgpt.com/backend-api"
# 2026 新接口: 旧的 referral_key=codex_referral_persistent_invite 已废弃,
# 改为 program_id + entrypoint。个人号用 consumer, 工作空间号用 workspace。
PROGRAM_ID = "codex_referral_consumer"
PROGRAM_ID_WORKSPACE = "codex_referral_workspace"
ENTRYPOINT = "persistent"
REFERRAL_KEY = "codex_referral_persistent_invite"   # deprecated, 保留避免旧 import 报错
DEFAULT_UA = "Codex/26.506.31421 (Mac)"


class CodexReferralError(RuntimeError):
    def __init__(self, status: int, body):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


def load_auth(auth_path: str = DEFAULT_AUTH_PATH) -> tuple[str, str]:
    with open(auth_path) as f:
        data = json.load(f)
    tokens = data["tokens"]
    return tokens["access_token"], tokens["account_id"]


def _request(
    method: str,
    path: str,
    *,
    token: str,
    account_id: str,
    body: dict | None = None,
    query: dict | None = None,
    proxy: str | None = None,
    timeout: int = 30,
    extra_headers: dict | None = None,
) -> tuple[int, dict]:
    url = f"{BASE_URL}{path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)

    headers = {
        "Authorization": f"Bearer {token}",
        "ChatGPT-Account-Id": account_id,
        "Accept": "*/*",
        "User-Agent": DEFAULT_UA,
    }
    if extra_headers:
        headers.update(extra_headers)

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        opener = urllib.request.build_opener()

    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": raw}


def _auth(token: str | None, account_id: str | None, auth_path: str):
    if token is None or account_id is None:
        return load_auth(auth_path)
    return token, account_id


def quota(
    token: str | None = None,
    account_id: str | None = None,
    *,
    program_id: str = PROGRAM_ID,
    proxy: str | None = None,
    auth_path: str = DEFAULT_AUTH_PATH,
) -> tuple[int, dict]:
    """(新接口)返回邀请资格 + 奖励概况。GET /referrals/invite/eligibility。

    响应含 grants[](每个 {amount, grant_type, recipient})、remaining_reward_capacity、
    remaining_send_capacity。
    """
    token, account_id = _auth(token, account_id, auth_path)
    return _request(
        "GET",
        "/referrals/invite/eligibility",
        token=token,
        account_id=account_id,
        query={"program_id": program_id, "entrypoint": ENTRYPOINT},
        extra_headers={"OpenAI-Internal-Referral-Eligibility-Preview": "true"},
        proxy=proxy,
    )


# 兼容旧名: quota 现在等价于 eligibility
eligibility = quota


def reward_info(
    token: str | None = None,
    account_id: str | None = None,
    *,
    program_id: str = PROGRAM_ID,
    proxy: str | None = None,
    auth_path: str = DEFAULT_AUTH_PATH,
) -> dict:
    """邀请奖励概况: 每次邀请拿多少积分 + 还能拿几次 + 还能发几个 + 文案。

    真实响应示例(consumer): grants 里 referrer/recipient 各一份 personal_credits amount=250,
    title="Get 250 credits", remaining_send_capacity=10, remaining_reward_capacity=3。
    """
    status, data = quota(token, account_id, program_id=program_id, proxy=proxy, auth_path=auth_path)
    if status != 200:
        raise CodexReferralError(status, data)
    grants = data.get("grants") or []
    # 邀请者自己拿的那份(recipient=="referrer");没有就取任意一份
    ref_grant = next((g for g in grants if g.get("recipient") == "referrer"), (grants[0] if grants else {}))
    return {
        "per_invite_reward": ref_grant.get("amount"),          # 每次成功邀请自己拿的积分(如 250)
        "grant_type": ref_grant.get("grant_type"),             # 如 personal_credits
        "remaining_reward_capacity": int(data.get("remaining_reward_capacity") or 0),  # 本月还能拿几次
        "remaining_send_capacity": int(data.get("remaining_send_capacity") or 0),      # 本月还能发几个
        "title": data.get("title"),                            # "Get 250 credits"
        "description": data.get("description"),
        "should_show": data.get("should_show"),
        "ineligible_reason": data.get("ineligible_reason"),
        # offer_id=="none" 或 grants 为空 = OpenAI 当前没给该号发放邀请奖励 offer(发了也没积分)
        "offer_id": data.get("offer_id"),
        "has_reward_offer": bool(grants) and str(data.get("offer_id") or "").lower() != "none",
        "grants": grants,
    }


def remaining(
    token: str | None = None,
    account_id: str | None = None,
    *,
    program_id: str = PROGRAM_ID,
    proxy: str | None = None,
    auth_path: str = DEFAULT_AUTH_PATH,
) -> int:
    """还能发几个邀请(remaining_send_capacity)。"""
    status, data = quota(token, account_id, program_id=program_id, proxy=proxy, auth_path=auth_path)
    if status != 200:
        raise CodexReferralError(status, data)
    return max(int(data.get("remaining_send_capacity") or 0), 0)


def list_referrals(
    token: str | None = None,
    account_id: str | None = None,
    *,
    program_id: str = PROGRAM_ID,
    period: str = "past_90_days",
    proxy: str | None = None,
    auth_path: str = DEFAULT_AUTH_PATH,
) -> tuple[int, dict]:
    """(新接口)已发邀请列表。GET /referrals/invite/tracking(游标翻页)。"""
    token, account_id = _auth(token, account_id, auth_path)
    items: list = []
    cursor = None
    for _ in range(50):  # 最多 50 页保护
        query = {"program_id": program_id, "period": period, "limit": 100}
        if cursor:
            query["cursor"] = cursor
        status, data = _request(
            "GET", "/referrals/invite/tracking",
            token=token, account_id=account_id, query=query, proxy=proxy,
        )
        if status != 200:
            return status, data
        items.extend(data.get("items") or [])
        cursor = data.get("cursor")
        if not cursor:
            break
    return 200, {"items": items}


def invite(
    emails: str | Iterable[str],
    token: str | None = None,
    account_id: str | None = None,
    *,
    program_id: str = PROGRAM_ID,
    proxy: str | None = None,
    auth_path: str = DEFAULT_AUTH_PATH,
) -> tuple[int, dict]:
    """(新接口)发推荐邀请。POST /referrals/invite  body {program_id, entrypoint, emails}。"""
    if isinstance(emails, str):
        emails = [emails]
    else:
        emails = list(emails)
    if not emails:
        raise ValueError("emails must not be empty")
    token, account_id = _auth(token, account_id, auth_path)
    return _request(
        "POST",
        "/referrals/invite",
        token=token,
        account_id=account_id,
        body={"program_id": program_id, "entrypoint": ENTRYPOINT, "emails": emails},
        proxy=proxy,
    )


def _print(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _cli(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="codex-referral", description="Codex referral CLI")
    parser.add_argument("--auth", default=DEFAULT_AUTH_PATH, help="Path to auth.json")
    parser.add_argument(
        "--proxy",
        default=os.environ.get("CODEX_PROXY"),
        help="HTTP proxy (or set CODEX_PROXY env)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("quota", help="Show remaining invite quota and rules")
    sub.add_parser("remaining", help="Print just the integer remaining count")
    sub.add_parser("list", help="List sent referrals")

    p_invite = sub.add_parser("invite", help="Send referral invite to one or more emails")
    p_invite.add_argument("emails", nargs="+")

    args = parser.parse_args(argv)
    token, account_id = load_auth(args.auth)
    common = dict(token=token, account_id=account_id, proxy=args.proxy)

    if args.cmd == "quota":
        status, data = quota(**common)
        _print(data)
        return 0 if status == 200 else 1

    if args.cmd == "remaining":
        try:
            print(remaining(**common))
            return 0
        except CodexReferralError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    if args.cmd == "list":
        status, data = list_referrals(**common)
        _print(data)
        return 0 if status == 200 else 1

    if args.cmd == "invite":
        status, data = invite(args.emails, **common)
        _print(data)
        return 0 if status == 200 else 1

    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))

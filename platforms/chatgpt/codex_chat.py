"""Codex Chat SDK — 用 OAuth access_token 直接调 ChatGPT 后端的 Codex 通道。

参考实现:Wei-Shaw/sub2api(LGPLv3)的 account_test_service.go,protocol 已验证。

端点:
  POST https://chatgpt.com/backend-api/codex/responses
Headers:
  Authorization: Bearer <access_token>
  chatgpt-account-id: <chatgpt_account_id>
  Accept: text/event-stream
  Content-Type: application/json
  Host: chatgpt.com
  User-Agent: codex_cli_rs/...
  Originator: codex_cli_rs               ← 命中官方白名单关键
  Version: codex 版本
Body:
  {
    "model": "gpt-5.4",                  ← OAuth 路径默认模型
    "input": [{"role":"user","content":[{"type":"input_text","text":"hi"}]}],
    "stream": true,
    "store": false,                       ← OAuth 必须 false
    "instructions": "<Codex CLI base prompt>"   ← 必填,否则 422
  }
SSE:
  data: {"type":"response.output_text.delta","delta":"..."}  → 拼字串
  data: {"type":"response.completed"}                         → 终止
  data: [DONE]                                                → 兜底终止
  data: {"type":"response.failed","response":{"error":{...}}} → 失败
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

CODEX_RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
DEFAULT_UA = "codex_cli_rs/0.125.0 (Ubuntu 22.4.0; x86_64) xterm-256color"
DEFAULT_ORIGINATOR = "codex_cli_rs"
DEFAULT_VERSION = "0.125.0"
DEFAULT_MODEL = "gpt-5.5"   # OAuth 路径 ChatGPT 账号支持的最新模型(2026.06 实测;
                            # sub2api 默认 gpt-5.4 已被 OpenAI 滚向前)
DEFAULT_PROMPT = "hi"

_INSTRUCTIONS_PATH = Path(__file__).parent / "codex_instructions.txt"


def _load_instructions() -> str:
    try:
        return _INSTRUCTIONS_PATH.read_text(encoding="utf-8")
    except Exception:
        # 兜底:OpenAI 在 instructions 为空时仍会响应,只是少了 codex 风格
        return "You are Codex, OpenAI's coding assistant. Answer briefly."


def codex_chat(
    *,
    access_token: str,
    chatgpt_account_id: str,
    prompt: str = DEFAULT_PROMPT,
    model: str = DEFAULT_MODEL,
    proxy: Optional[str] = None,
    instructions: Optional[str] = None,
    timeout: int = 120,
    rich_body: bool = True,
) -> dict:
    """单轮调 Codex 通道,返回 {ok, reply, http_status, latency_ms, chunks, raw_error?}.

    rich_body=True (默认): 模仿 Codex CLI/App 真实 body — 带 reasoning / tools /
    include / tool_choice 等字段。OpenAI 会把这种请求计入 Codex 真实使用 (能触发周配额重置);
    rich_body=False: 旧的极简 body, 仅 input + stream + store + instructions。

    成功:reply 是 OpenAI 返回的完整文本(SSE delta 拼起来)。
    失败:返回 {ok:False, http_status, raw_error} 包含原始错误体前 1600 字。
    """
    if not access_token or not chatgpt_account_id:
        return {
            "ok": False,
            "http_status": 0,
            "raw_error": "missing access_token / chatgpt_account_id",
            "reply": "", "chunks": 0, "latency_ms": 0,
        }

    payload: dict = {
        "model": model,
        "input": [
            {
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            }
        ],
        "stream": True,
        "store": False,
        "instructions": instructions if instructions is not None else _load_instructions(),
    }
    if rich_body:
        # ── Codex CLI 实际 body 关键字段(让 OpenAI 把请求计入 Codex 真实使用) ──
        # reasoning: gpt-5/gpt-5.5 是推理模型,Codex CLI 默认 effort=medium
        payload["reasoning"] = {"effort": "medium", "summary": "auto"}
        # include: 让响应带回 reasoning 加密载体(Codex CLI 一定带)
        payload["include"] = ["reasoning.encrypted_content"]
        # tools: Codex CLI 注册的核心 3 个工具 — shell / apply_patch / update_plan
        # 简化 schema; 模型不会主动调,只是让 OpenAI 识别"这是真正的 Codex 会话"
        payload["tools"] = [
            {
                "type": "function",
                "name": "shell",
                "description": "Run a shell command",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "array", "items": {"type": "string"}},
                        "workdir": {"type": "string"},
                        "timeout_ms": {"type": "integer"},
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
                "strict": False,
            },
            {
                "type": "function",
                "name": "apply_patch",
                "description": "Apply a unified diff patch to files",
                "parameters": {
                    "type": "object",
                    "properties": {"input": {"type": "string"}},
                    "required": ["input"],
                    "additionalProperties": False,
                },
                "strict": False,
            },
            {
                "type": "function",
                "name": "update_plan",
                "description": "Update the agent's plan",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "explanation": {"type": "string"},
                        "plan": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "step": {"type": "string"},
                                    "status": {"type": "string"},
                                },
                                "required": ["step", "status"],
                                "additionalProperties": False,
                            },
                        },
                    },
                    "required": ["plan"],
                    "additionalProperties": False,
                },
                "strict": False,
            },
        ]
        payload["tool_choice"] = "auto"
        payload["parallel_tool_calls"] = False
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "chatgpt-account-id": chatgpt_account_id,
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "Host": "chatgpt.com",
        "User-Agent": DEFAULT_UA,
        "Originator": DEFAULT_ORIGINATOR,
        "Version": DEFAULT_VERSION,
    }
    req = urllib.request.Request(
        CODEX_RESPONSES_URL, data=body, method="POST", headers=headers,
    )

    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)

    t0 = time.time()
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = (e.read() or b"").decode("utf-8", errors="replace")[:1600]
        except Exception:
            pass
        return {
            "ok": False,
            "http_status": e.code,
            "raw_error": raw or f"HTTP {e.code}",
            "reply": "", "chunks": 0,
            "latency_ms": int((time.time() - t0) * 1000),
        }
    except Exception as e:
        return {
            "ok": False,
            "http_status": 0,
            "raw_error": f"REQUEST_FAILED: {e}",
            "reply": "", "chunks": 0,
            "latency_ms": int((time.time() - t0) * 1000),
        }

    status_code = getattr(resp, "status", 200) or 200
    if status_code != 200:
        try:
            raw = (resp.read() or b"").decode("utf-8", errors="replace")[:1600]
        except Exception:
            raw = ""
        return {
            "ok": False,
            "http_status": status_code,
            "raw_error": raw or f"HTTP {status_code}",
            "reply": "", "chunks": 0,
            "latency_ms": int((time.time() - t0) * 1000),
        }

    # ── SSE 解析(逐行) ────────────────────────────────────────
    reply_parts: list[str] = []
    chunks = 0
    completed = False
    failed_reason = ""
    try:
        for raw_line in resp:
            try:
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            except Exception:
                continue
            if not line:
                continue
            if not line.startswith("data:"):
                continue
            data_str = line[5:].lstrip()
            if data_str == "[DONE]":
                break
            try:
                evt = json.loads(data_str)
            except Exception:
                continue
            etype = str(evt.get("type") or "")
            if etype == "response.output_text.delta":
                delta = evt.get("delta")
                if isinstance(delta, str) and delta:
                    reply_parts.append(delta)
                    chunks += 1
            elif etype in ("response.completed", "response.done"):
                completed = True
                break
            elif etype == "response.failed":
                err = (evt.get("response") or {}).get("error") or {}
                failed_reason = f"{err.get('code') or 'error'}: {err.get('message') or ''}".strip()
                break
    finally:
        try: resp.close()
        except Exception: pass

    elapsed_ms = int((time.time() - t0) * 1000)
    if failed_reason:
        return {
            "ok": False,
            "http_status": status_code,
            "raw_error": failed_reason,
            "reply": "".join(reply_parts),
            "chunks": chunks,
            "latency_ms": elapsed_ms,
        }

    reply = "".join(reply_parts)
    return {
        "ok": True if (completed or reply) else False,
        "http_status": status_code,
        "raw_error": "" if (completed or reply) else "Stream ended before response.completed",
        "reply": reply,
        "chunks": chunks,
        "latency_ms": elapsed_ms,
        "model": model,
    }

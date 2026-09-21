# Architecture

## Runtime

The React application talks only to the same-origin FastAPI API. Browser
automation runs in worker threads and is never executed in a request handler.
Every external operation is represented by a durable job, attempt or lease so
a process restart can resume from a confirmed checkpoint.

```text
React UI
   │ same-origin HTTPS
FastAPI API ─── administrator authentication
   │
   ├── workflow services ─── durable jobs / attempts / logs
   ├── provider adapters ─── mail / SMS / proxy / browser
   └── account services ─── Gmail / GPT / BUSINESS
                 │
          SQLite or PostgreSQL
```

## Module ownership

- `api/` validates transport input and maps service errors to HTTP responses.
- `services/` owns workflows, durable state transitions and provider gateways.
- `core/` owns persistence, encryption, authentication primitives and runtime
  infrastructure.
- `platforms/chatgpt/` contains the ChatGPT browser/protocol adapter. It must
  not directly manage administrator sessions or UI state.
- `frontend/` consumes stable API DTOs and never reads server-side credentials.

## Registration state machine

```text
queued → mailbox_reserved → proxy_reserved → browser_started
       → email_submitted → password_set → email_verified
       → profile_completed → mfa_enabled → session_saved
       → sms_pending? → oauth_pending? → completed
```

Each transition is idempotent. A retry inspects saved evidence before issuing
another external mutation. Provider errors use stable codes; secret values and
verification codes are not stored in logs.

## Secrets

Account passwords, TOTP seeds, recovery codes and provider keys use AES-256-GCM
envelopes. The encryption key is supplied by the deployment or generated as a
0600 runtime file. Losing the key makes ciphertext unrecoverable; copying only
the database is not a valid backup.

Administrator passwords use Argon2id. Browser sessions are signed, versioned,
HttpOnly, same-site cookies. API clients may use the bearer token returned by
the login endpoint.

## Provider interfaces

Mail, proxy, browser and SMS integrations are adapters. The SMS contract is:

```python
balance()
acquire(service, country, max_price)
status(activation_id)
complete(activation_id)
cancel(activation_id)
```

Provider-specific payloads stop at the gateway. Workflow code consumes the
normalized activation state and local activation ID.

## Compatibility boundary

The public version retains a compatibility state layer for the proven Gmail,
GPT security and BUSINESS workflows. Unrelated platform adapters, pages,
runtime workers and API routers are removed from this repository. A few legacy
table and module names remain because durable BUSINESS jobs already reference
them; they do not start the former marketplace or automatic-sales runtimes.
Compatibility tables will be removed only through reviewed migrations and
data-copy tools, never by deleting tables during application startup.

# Contributing

1. Create a focused branch and never commit runtime data or credentials.
2. Install with `./scripts/setup.sh`.
3. Run `pytest -q tests`, `npm run build`, and the frontend tests.
4. Add a migration for every schema change after the initial release.
5. Provider integrations must implement the shared mailbox, proxy, browser or
   SMS interface; workflow code must not depend on one vendor response format.
6. Logs and exceptions must redact passwords, tokens, provider keys, phone
   verification codes and signed callback URLs.

Substantial code copied from another project must retain its license and
copyright notice.

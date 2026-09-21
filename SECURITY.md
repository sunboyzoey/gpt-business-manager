# Security policy

Do not open a public issue containing account credentials, cookies, OAuth
tokens, mailbox passwords, TOTP seeds, provider keys, proxy credentials or
database files. Report a vulnerability privately through the repository's
security advisory feature.

Supported releases are the latest tagged release and the current `main`
branch. Before exposing the service, initialize the administrator password,
enable TOTP, use HTTPS, set `GBM_COOKIE_SECURE=true`, keep the application on a
private network or behind an authenticated reverse proxy, and back up both the
database and credential-encryption key.

The first administrator password can only be initialized through a direct
loopback request. Complete initialization on the server or through an SSH
port-forward before exposing the reverse proxy. Interactive API documentation
is disabled by default; enable it only for local development with
`GBM_ENABLE_API_DOCS=true`.

The application deliberately excludes runtime data through `.gitignore`.
Maintainers must use synthetic account fixtures, run `gitleaks git .` and the
test workflow before publishing. Do not copy production account examples into
tests, documentation, screenshots, commits or pull-request descriptions.

Publish from Git (`git archive` or a clean clone). Do not upload a zip of a
working directory: ignored databases, logs, browser profiles, virtual
environments and generated credential keys can still contain local secrets or
absolute user paths even though Git will not include them.

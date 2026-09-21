"""NexusVault-only direct HTTP transport.

Do not mutate process proxy variables or the shared requests library: browser,
OAuth, mail and other platforms must retain their existing proxy behaviour.
Each NV request has a private session which ignores environment/macOS proxies
and .netrc. TLS verification, caller timeouts and response bounds stay intact.
There are no retries here, especially for uncertain listing/price mutations.

Closing the session after dispatch matches requests.api.request's lifecycle;
streamed responses are still consumed and closed by the existing NV callers.
An OS-level TUN can still intercept direct sockets; this does not modify TUN.
"""
from __future__ import annotations

import requests as _requests

# Preserve callers' exception handling and their narrow test injection seams.
RequestException = _requests.RequestException
Timeout = _requests.Timeout
ConnectionError = _requests.ConnectionError


def _request(method, url, **kwargs):
    with _requests.Session() as session:
        session.trust_env = False
        session.proxies.clear()
        kwargs["proxies"] = {}
        return session.request(method, url, **kwargs)


def get(url, **kwargs):
    return _request("GET", url, **kwargs)


def post(url, **kwargs):
    return _request("POST", url, **kwargs)


def patch(url, **kwargs):
    return _request("PATCH", url, **kwargs)

"""Centralized TLS context for outbound HTTPS calls.

httpx defaults to ``ssl.create_default_context()``, which loads CAs
from the platform default store. On macOS Python (python.org
installer) and Windows Store Python the default store is empty until
the user runs a separate cert-install step, so a plain
``pip install mipiti-verify`` followed by ``mipiti-verify audit``
fails with ``CERTIFICATE_VERIFY_FAILED`` even though the upstream
certs are valid.

The CLI must work without requiring users to debug their Python's CA
bundle. ``certifi`` ships a Mozilla-curated bundle and is already a
transitive dependency of httpx, so binding to it is free and keeps
the CA root explicit.
"""

from __future__ import annotations

import ssl
from functools import lru_cache


@lru_cache(maxsize=1)
def tls_context() -> ssl.SSLContext:
    """Return a process-wide TLS context backed by certifi's CA bundle.

    Cached so the bundle is parsed once. Pass to httpx as
    ``verify=tls_context()`` on every ``httpx.Client(...)`` and
    ``httpx.get(...)`` call.
    """
    import certifi
    return ssl.create_default_context(cafile=certifi.where())

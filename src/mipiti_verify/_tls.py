"""Centralized TLS trust resolution for outbound HTTPS calls.

The CLI must work for two users our default ``ssl.create_default_context()``
strands:

1. **Macos / Windows Python with an empty platform CA store.** A plain
   ``pip install mipiti-verify`` followed by ``mipiti-verify audit``
   crashes at JWKS fetch with ``CERTIFICATE_VERIFY_FAILED`` until the
   user runs ``Install Certificates.command`` (python.org installer)
   or sets ``SSL_CERT_FILE`` manually. ``certifi`` ships a Mozilla-
   curated bundle and is already a transitive dep of httpx, so binding
   to it is free and gets the well-known certs (Let's Encrypt, etc.)
   that ``api.mipiti.io`` and other upstreams use.

2. **Corporate TLS-intercepting proxy (Zscaler, Netskope, Palo Alto
   Decryption, Cloudflare WARP).** The cert seen on the wire is signed
   by a private CA the corporate IT installed into the OS trust store
   (macOS Keychain, Windows Cert Store, Linux ca-certificates). certifi
   does NOT have that CA. ``truststore`` makes Python's ``ssl`` module
   read from the OS trust store on each platform, so the corporate CA
   is picked up automatically with no manual cert-bundle gymnastics.

Resolution order (first hit wins):

1. ``MIPITI_CA_BUNDLE`` env var — explicit override for power users
   shipping a custom bundle (e.g. air-gapped CI with internal CA).
2. ``truststore.SSLContext`` — OS trust store. Covers corporate-CA
   users AND most regular users (the OS keychain typically already
   has Mozilla / well-known roots).
3. ``certifi.where()`` — Mozilla baseline. Covers the macOS / Windows
   empty-platform-store case where truststore can't help.
4. ``ssl.create_default_context()`` — last resort; works on Linux
   distros that ship a populated /etc/ssl/certs.

Power-user notes:

- ``SSL_CERT_FILE`` (OpenSSL env var) is honored by the OpenSSL layer
  underneath every path here, so users who already set it for other
  Python tooling don't need a Mipiti-specific override.
- A ``--ca-bundle <path>`` CLI flag can be added per-command for
  scenarios where users can't / don't want to use env vars.
"""

from __future__ import annotations

import os
import ssl
from functools import lru_cache


@lru_cache(maxsize=1)
def tls_context() -> ssl.SSLContext:
    """Return a process-wide TLS context for outbound HTTPS.

    Cached so the bundle / OS trust scan happens once per process.
    Pass to httpx as ``verify=tls_context()`` on every
    ``httpx.Client(...)`` and ``httpx.get(...)`` call.
    """
    # 1. Explicit override.
    bundle = os.environ.get("MIPITI_CA_BUNDLE", "").strip()
    if bundle:
        return ssl.create_default_context(cafile=bundle)

    # 2. OS trust store via truststore. Picks up corporate CAs
    # (Zscaler, Netskope, etc.) installed by IT.
    try:
        import truststore
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except Exception:
        # truststore not installed, or failed to bind to the OS API
        # (rare; possible on locked-down sandboxes). Fall through.
        pass

    # 3. certifi fallback — Mozilla bundle. Covers the macOS / Windows
    # empty-platform-store case.
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass

    # 4. Last resort: platform default. Works on Linux with
    # ca-certificates installed; fails on the macOS / Windows empty-
    # store case but at that point we've exhausted reasonable defaults.
    return ssl.create_default_context()

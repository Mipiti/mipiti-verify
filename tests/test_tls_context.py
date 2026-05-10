"""Pin the TLS-trust resolution chain used by every outbound HTTPS call.

Two failure modes the platform-default SSLContext doesn't cover:

1. macOS / Windows Python with an empty platform CA store. Plain
   ``pip install mipiti-verify`` followed by ``mipiti-verify audit``
   crashes with ``CERTIFICATE_VERIFY_FAILED`` until the user runs a
   manual cert-install step. ``certifi`` fixes this.
2. Corporate TLS-intercepting proxy (Zscaler, Netskope, Palo Alto
   Decryption, Cloudflare WARP). The cert seen on the wire is signed
   by a private CA installed by IT into the OS trust store; certifi
   doesn't have it. ``truststore`` fixes this by reading the OS trust
   store directly.

These tests pin the resolution order so a future refactor can't
silently regress either case.
"""

from __future__ import annotations

import os
import ssl
import sys
from unittest.mock import patch

import certifi


def _clear_cache():
    """``tls_context`` is lru_cached; clear before each path-specific
    test so the function actually re-runs against the patched env."""
    from mipiti_verify._tls import tls_context
    tls_context.cache_clear()


def test_returns_sslcontext():
    _clear_cache()
    from mipiti_verify._tls import tls_context
    ctx = tls_context()
    assert isinstance(ctx, ssl.SSLContext)


def test_explicit_ca_bundle_env_var_wins():
    """``MIPITI_CA_BUNDLE`` is the explicit user override. When set, it
    must be honoured before any other resolution path."""
    _clear_cache()
    bundle_path = certifi.where()  # any valid bundle file
    with patch.dict(os.environ, {"MIPITI_CA_BUNDLE": bundle_path}, clear=False):
        from mipiti_verify._tls import tls_context
        ctx = tls_context()
        cas = ctx.get_ca_certs()
        assert len(cas) >= 50, (
            f"Expected ≥50 CAs from MIPITI_CA_BUNDLE bundle, got {len(cas)}. "
            "The explicit env-var override is not being honoured."
        )
    _clear_cache()


def test_default_path_uses_truststore():
    """When no env override is set, the chain prefers truststore so
    corporate-CA users (Zscaler / Netskope / etc.) work automatically.
    The truststore SSLContext lives in the ``truststore._api`` module."""
    _clear_cache()
    saved_env = os.environ.pop("MIPITI_CA_BUNDLE", None)
    try:
        from mipiti_verify._tls import tls_context
        ctx = tls_context()
        assert "truststore" in type(ctx).__module__, (
            f"Expected truststore-backed SSLContext, got "
            f"{type(ctx).__module__}.{type(ctx).__name__}. Without truststore "
            "as the default, corporate TLS-intercept users (Zscaler etc.) "
            "hit CERTIFICATE_VERIFY_FAILED on every outbound call."
        )
    finally:
        if saved_env is not None:
            os.environ["MIPITI_CA_BUNDLE"] = saved_env
        _clear_cache()


def test_certifi_fallback_when_truststore_unavailable():
    """If truststore is missing or fails to load, the chain must fall
    through to certifi rather than the empty platform default. This
    is the macOS/Windows-Python-without-Install-Certificates case."""
    _clear_cache()
    saved_env = os.environ.pop("MIPITI_CA_BUNDLE", None)
    saved_module = sys.modules.pop("truststore", None)
    try:
        # Force any future `import truststore` to raise ImportError.
        with patch.dict(sys.modules, {"truststore": None}):
            from mipiti_verify._tls import tls_context
            ctx = tls_context()
            cas = ctx.get_ca_certs()
            assert len(cas) >= 50, (
                f"With truststore unavailable, expected certifi's CA bundle "
                f"(~140 anchors) to engage; got {len(cas)} CAs. The certifi "
                "fallback path isn't firing."
            )
    finally:
        if saved_env is not None:
            os.environ["MIPITI_CA_BUNDLE"] = saved_env
        if saved_module is not None:
            sys.modules["truststore"] = saved_module
        _clear_cache()


def test_certifi_path_exists():
    """Sanity: certifi.where() returns an existing file. If the wheel
    was built without certifi this fires before httpx does."""
    assert os.path.exists(certifi.where())


def test_truststore_importable():
    """Sanity: truststore is a hard dep, must be importable. If this
    fails the wheel was built without truststore — corporate-CA users
    (Zscaler, Netskope, etc.) would silently fall through to certifi
    and hit CERTIFICATE_VERIFY_FAILED."""
    import truststore  # noqa: F401


def test_caching_returns_same_context():
    _clear_cache()
    from mipiti_verify._tls import tls_context
    a = tls_context()
    b = tls_context()
    assert a is b

"""Pin that the verify CLI uses certifi's CA bundle for outbound HTTPS.

The bug this regression test guards against: macOS Python (python.org
installer) and Windows Store Python ship with an empty default CA
store. ``ssl.create_default_context()`` succeeds but verification of
real certs fails with ``CERTIFICATE_VERIFY_FAILED``. The CLI must
work on a fresh ``pip install mipiti-verify`` without a separate
cert-install step.
"""

from __future__ import annotations

import ssl

import certifi

from mipiti_verify._tls import tls_context


def test_tls_context_returns_sslcontext() -> None:
    ctx = tls_context()
    assert isinstance(ctx, ssl.SSLContext)


def test_tls_context_loads_certifi_bundle() -> None:
    """The context should have at least the Mozilla bundle's CAs.
    certifi ships ~140 trust anchors; the empty default has 0."""
    ctx = tls_context()
    cas = ctx.get_ca_certs()
    assert len(cas) >= 50, (
        f"Expected certifi's CA bundle (~140 anchors), got {len(cas)}. "
        "If 0, the platform default CA store is being used instead "
        "of certifi.where(), and macOS/Windows users will hit "
        "CERTIFICATE_VERIFY_FAILED on every outbound HTTPS call."
    )


def test_tls_context_is_cached() -> None:
    """The bundle is parsed once per process; same context returned."""
    a = tls_context()
    b = tls_context()
    assert a is b


def test_certifi_path_exists() -> None:
    """Sanity: certifi.where() returns an existing file. If certifi is
    missing or the wheel is incomplete, this fires before httpx does."""
    import os
    assert os.path.exists(certifi.where())

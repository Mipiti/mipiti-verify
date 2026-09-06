"""pytest plugin that disables one mechanism for the duration of a session.

Loaded only by ``mipiti-verify attest-dependence`` (``-p
mipiti_verify._disable_plugin``), in the customer's own test job. It reads
``MIPITI_DISABLE_MECHANISM=<file>::<symbol>``, imports the module the file
defines, and replaces the symbol with a stub before any test is collected: a
function becomes one that returns ``None``; a class becomes one whose every
method returns ``None``; ``Class.method`` is patched on the class.

A test that still passes under the stub does not depend on the mechanism.
That is the whole purpose of the plugin, and it is why the outcome is
recorded rather than judged. When the module cannot be imported the plugin
writes a marker file (``MIPITI_DISABLE_MARKER``) and aborts the session so
the pair is recorded as an error, never as a pass.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from pathlib import Path

ENV_MECHANISM = "MIPITI_DISABLE_MECHANISM"
ENV_MARKER = "MIPITI_DISABLE_MARKER"


def _stub(*_args, **_kwargs):
    return None


class _StubMeta(type):
    def __getattr__(cls, _name):
        return _stub


class _StubClass(metaclass=_StubMeta):
    """Stands in for a disabled class: construction succeeds, every method
    returns ``None``."""

    def __init__(self, *_args, **_kwargs):
        pass

    def __getattr__(self, _name):
        return _stub

    def __call__(self, *_args, **_kwargs):
        return None


def _dotted_candidates(rel_file: str) -> list[str]:
    """Dotted names the file may already be importable under, most specific
    first: ``src/pkg/mod.py`` is ``src.pkg.mod`` on a plain checkout and
    ``pkg.mod`` under a src layout."""
    parts = Path(rel_file).with_suffix("").as_posix().split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    parts = [p for p in parts if p and p != "."]
    return [".".join(parts[i:]) for i in range(len(parts))]


def import_mechanism_module(project_root: Path, rel_file: str):
    """The module ``rel_file`` defines.

    Imported by dotted name where one resolves to this very file, so a later
    ``import a.b.c`` in the code under test sees the patched object. Failing
    that, loaded from the path and registered under the dotted name derived
    from it.
    """
    path = (project_root / rel_file).resolve()
    if not path.is_file():
        raise ImportError(f"{rel_file} is not a file under {project_root}")
    candidates = _dotted_candidates(rel_file)
    for dotted in candidates:
        if not dotted:
            continue
        try:
            module = importlib.import_module(dotted)
        except Exception:  # noqa: BLE001
            continue
        module_file = getattr(module, "__file__", None)
        if module_file and Path(module_file).resolve() == path:
            return module
    dotted = candidates[0] if candidates else path.stem
    spec = importlib.util.spec_from_file_location(dotted, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot build an import spec for {rel_file}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[dotted] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(dotted, None)
        raise
    return module


def disable_symbol(module, symbol: str) -> None:
    """Replace ``symbol`` on ``module`` with a stub."""
    owner, _, leaf = symbol.rpartition(".")
    if owner:
        target = getattr(module, owner)
        if not hasattr(target, leaf):
            raise AttributeError(f"{owner} has no attribute {leaf!r}")
        setattr(target, leaf, _stub)
        return
    if not hasattr(module, leaf):
        raise AttributeError(f"{module.__name__} has no attribute {leaf!r}")
    current = getattr(module, leaf)
    setattr(module, leaf, _StubClass if isinstance(current, type) else _stub)


def _mark(message: str) -> None:
    marker = os.environ.get(ENV_MARKER, "").strip()
    if not marker:
        return
    try:
        Path(marker).write_text(message, encoding="utf-8")
    except OSError:
        pass


def pytest_configure(config) -> None:
    spec = os.environ.get(ENV_MECHANISM, "").strip()
    if not spec:
        return
    import pytest

    rel_file, _, symbol = spec.partition("::")
    rel_file = rel_file.strip().replace("\\", "/")
    symbol = symbol.strip()
    if not rel_file or not symbol:
        _mark(f"malformed mechanism reference {spec!r}")
        raise pytest.UsageError(f"{ENV_MECHANISM} must be <file>::<symbol>, got {spec!r}")
    root = Path(str(config.rootpath)) if getattr(config, "rootpath", None) else Path.cwd()
    try:
        module = import_mechanism_module(root, rel_file)
        disable_symbol(module, symbol)
    except Exception as e:  # noqa: BLE001
        _mark(f"{type(e).__name__}: {e}")
        raise pytest.UsageError(
            f"cannot disable {spec}: {type(e).__name__}: {e}"
        ) from e

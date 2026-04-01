"""Config verifiers: config_key_exists, config_value_matches, env_var_referenced."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import PathTraversalError, VerifierResult, register, resolve_content, safe_read_file, safe_resolve_path


def _parse_config(project_root: Path, file_param: str) -> dict | None:
    """Parse config file (JSON, YAML, TOML, INI, .env) into a dict."""
    content = safe_read_file(project_root, file_param)
    if content is None:
        return None
    file_path = safe_resolve_path(project_root, file_param)
    suffix = file_path.suffix.lower()

    if suffix == ".json":
        return json.loads(content)

    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
            return yaml.safe_load(content) or {}
        except ImportError:
            # Fallback: simple key: value parsing
            return _parse_simple_kv(content, sep=":")

    if suffix == ".toml":
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                return _parse_simple_kv(content, sep="=")
        return tomllib.loads(content)

    if suffix in (".ini", ".cfg"):
        try:
            import configparser
            cp = configparser.ConfigParser()
            cp.read_string(content)
            result = {}
            for section in cp.sections():
                for key, value in cp.items(section):
                    result[f"{section}.{key}"] = value
                    result[key] = value  # also flat
            return result
        except Exception:
            return _parse_simple_kv(content, sep="=")

    if suffix == ".env" or file_path.name == ".env":
        return _parse_env(content)

    # Fallback: try JSON, then simple key=value
    try:
        return json.loads(content)
    except Exception:
        return _parse_simple_kv(content, sep="=")


def _parse_simple_kv(content: str, sep: str = "=") -> dict:
    """Parse simple KEY=VALUE or KEY: VALUE format."""
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if sep in line:
            key, _, value = line.partition(sep)
            result[key.strip()] = value.strip().strip("\"'")
    return result


def _parse_env(content: str) -> dict:
    """Parse .env file."""
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip().strip("\"'")
    return result


def _nested_get(d: dict, key: str):
    """Get a value from a nested dict using dot notation."""
    parts = key.split(".")
    current = d
    for part in parts:
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                return None
        else:
            return None
    return current


@register("config_key_exists")
class ConfigKeyExistsVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            config = _parse_config(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if config is None:
            return VerifierResult(passed=False, details=f"Could not parse config file: {params['file']}")

        key = params["key"]
        value = _nested_get(config, key)
        if value is not None:
            return VerifierResult(passed=True, details=f"Config key '{key}' exists")
        # Also check flat keys
        if key in config:
            return VerifierResult(passed=True, details=f"Config key '{key}' exists")
        return VerifierResult(passed=False, details=f"Config key '{key}' not found in {params['file']}")


@register("config_value_matches")
class ConfigValueMatchesVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            config = _parse_config(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if config is None:
            return VerifierResult(passed=False, details=f"Could not parse config file: {params['file']}")

        key = params["key"]
        pattern = params["pattern"]
        value = _nested_get(config, key)
        if value is None:
            value = config.get(key)
        if value is None:
            return VerifierResult(passed=False, details=f"Config key '{key}' not found")

        if re.search(pattern, str(value)):
            return VerifierResult(passed=True, details=f"Config '{key}' matches pattern '{pattern}'")
        return VerifierResult(passed=False, details=f"Config '{key}' = '{value}' does not match pattern '{pattern}'")


@register("env_var_referenced")
class EnvVarReferencedVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")
        variable = params["variable"]

        # Look for common env var access patterns
        patterns = [
            rf'os\.environ\b[^)]*["\']{ re.escape(variable)}["\']',
            rf'os\.getenv\s*\(\s*["\']{ re.escape(variable)}["\']',
            rf'process\.env\.{re.escape(variable)}\b',
            rf'process\.env\[[\'"]{re.escape(variable)}[\'"]\]',
            rf'env\s*\(\s*["\']{ re.escape(variable)}["\']',
            rf'ENV\[[\'"]{re.escape(variable)}[\'"]\]',
            rf'\$\{{{re.escape(variable)}\}}',
            rf'\${re.escape(variable)}\b',
        ]

        for pattern in patterns:
            if re.search(pattern, content):
                return VerifierResult(
                    passed=True,
                    details=f"Env var '{variable}' referenced in {source}",
                )

        return VerifierResult(passed=False, details=f"Env var '{variable}' not found in {source}")

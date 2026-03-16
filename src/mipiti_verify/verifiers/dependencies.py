"""Dependency verifiers: dependency_exists, dependency_version."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import PathTraversalError, VerifierResult, register, safe_resolve_path


def _parse_manifest(file_path: Path) -> dict[str, str]:
    """Parse a dependency manifest into {package: version_spec}.

    Supports: requirements.txt, package.json, Cargo.toml, go.mod, pyproject.toml.
    """
    name = file_path.name.lower()
    content = file_path.read_text(encoding="utf-8", errors="replace")

    if name == "requirements.txt" or name.endswith(".txt"):
        return _parse_requirements_txt(content)
    if name == "package.json":
        return _parse_package_json(content)
    if name == "cargo.toml":
        return _parse_cargo_toml(content)
    if name == "go.mod":
        return _parse_go_mod(content)
    if name == "pyproject.toml":
        return _parse_pyproject_toml(content)
    if name == "pom.xml":
        return _parse_pom_xml(content)

    # Fallback: try as requirements.txt format
    return _parse_requirements_txt(content)


def _parse_requirements_txt(content: str) -> dict[str, str]:
    """Parse requirements.txt (pip format)."""
    deps: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package==1.0, package>=1.0, package~=1.0, package
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([<>=!~]+.+)?", line)
        if match:
            pkg = match.group(1).lower().replace("-", "_")
            ver = (match.group(2) or "").strip()
            deps[pkg] = ver
    return deps


def _parse_package_json(content: str) -> dict[str, str]:
    """Parse package.json dependencies."""
    data = json.loads(content)
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg, ver in data.get(section, {}).items():
            deps[pkg] = ver
    return deps


def _parse_cargo_toml(content: str) -> dict[str, str]:
    """Parse Cargo.toml dependencies (simple regex, not full TOML)."""
    deps: dict[str, str] = {}
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r"\[.*dependencies.*\]", stripped, re.IGNORECASE):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # Handle inline tables: { version = "1.0" }
            ver_match = re.search(r'version\s*=\s*"([^"]*)"', value)
            if ver_match:
                deps[key] = ver_match.group(1)
            elif not value.startswith("{"):
                deps[key] = value
    return deps


def _parse_go_mod(content: str) -> dict[str, str]:
    """Parse go.mod require block."""
    deps: dict[str, str] = {}
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if stripped == ")" and in_require:
            in_require = False
            continue
        if in_require:
            parts = stripped.split()
            if len(parts) >= 2:
                deps[parts[0]] = parts[1]
        elif stripped.startswith("require "):
            parts = stripped[len("require "):].split()
            if len(parts) >= 2:
                deps[parts[0]] = parts[1]
    return deps


def _parse_pyproject_toml(content: str) -> dict[str, str]:
    """Parse pyproject.toml dependencies section."""
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads(content)
        deps: dict[str, str] = {}
        for dep_str in data.get("project", {}).get("dependencies", []):
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([<>=!~]+.+)?", dep_str)
            if match:
                pkg = match.group(1).lower().replace("-", "_")
                ver = (match.group(2) or "").strip()
                deps[pkg] = ver
        return deps
    except Exception:
        return _parse_requirements_txt(content)


def _parse_pom_xml(content: str) -> dict[str, str]:
    """Parse pom.xml dependencies (simple regex)."""
    deps: dict[str, str] = {}
    # Find <dependency> blocks
    for m in re.finditer(
        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>"
        r"(?:\s*<version>([^<]+)</version>)?",
        content,
    ):
        group_id = m.group(1)
        artifact_id = m.group(2)
        version = m.group(3) or ""
        deps[f"{group_id}:{artifact_id}"] = version
        deps[artifact_id] = version  # also by artifact ID only
    return deps


@register("dependency_exists")
class DependencyExistsVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            manifest_path = safe_resolve_path(project_root, params["manifest"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if not manifest_path.is_file():
            return VerifierResult(passed=False, details=f"Manifest not found: {params['manifest']}")

        deps = _parse_manifest(manifest_path)
        package = params["package"]
        normalized = package.lower().replace("-", "_")

        # Check both original name and normalized
        for dep_name in deps:
            if dep_name.lower().replace("-", "_") == normalized or dep_name == package:
                return VerifierResult(
                    passed=True,
                    details=f"Package '{package}' found in {params['manifest']}",
                )

        return VerifierResult(passed=False, details=f"Package '{package}' not found in {params['manifest']}")


@register("dependency_version")
class DependencyVersionVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            manifest_path = safe_resolve_path(project_root, params["manifest"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if not manifest_path.is_file():
            return VerifierResult(passed=False, details=f"Manifest not found: {params['manifest']}")

        deps = _parse_manifest(manifest_path)
        package = params["package"]
        constraint = params["constraint"]
        normalized = package.lower().replace("-", "_")

        version_spec = None
        for dep_name, ver in deps.items():
            if dep_name.lower().replace("-", "_") == normalized or dep_name == package:
                version_spec = ver
                break

        if version_spec is None:
            return VerifierResult(passed=False, details=f"Package '{package}' not found in {params['manifest']}")

        # Try Python packaging.specifiers for precise checking
        try:
            from packaging.specifiers import SpecifierSet
            from packaging.version import Version

            # Extract version number from spec (e.g., ">=1.0,<2.0" -> check constraint)
            # The constraint param is what we check: e.g., ">=1.0"
            # The version_spec from manifest is the actual installed version
            spec = SpecifierSet(constraint)
            # Extract a clean version from version_spec
            ver_match = re.search(r"[\d]+(?:\.[\d]+)*", version_spec)
            if ver_match:
                ver = Version(ver_match.group())
                if ver in spec:
                    return VerifierResult(
                        passed=True,
                        details=f"Package '{package}' version {ver} satisfies {constraint}",
                    )
                return VerifierResult(
                    passed=False,
                    details=f"Package '{package}' version {ver} does not satisfy {constraint}",
                )
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: string match
        if constraint in version_spec or version_spec in constraint:
            return VerifierResult(passed=True, details=f"Package '{package}': {version_spec} matches {constraint}")
        return VerifierResult(
            passed=False,
            details=f"Package '{package}': {version_spec} may not satisfy {constraint} (install 'packaging' for precise checking)",
        )

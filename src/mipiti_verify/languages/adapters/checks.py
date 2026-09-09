"""Compile and lint checks that gate a source mutation.

A mutated tree that does not compile proves nothing about the test, so the
pair is recorded as ``error`` with the tool's reason. Each check returns
an empty string when the tree is sound and the reason otherwise; a
language with no usable toolchain on this machine is a reason too.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path
from typing import Optional

from ._common import Runner, run_command, tail, which

CHECK_TIMEOUT = 600

# Marks the one reason that is an ANSWER from the toolchain: it ran, it read
# the tree, and it rejected it. Every other reason a check returns -- an
# absent tool, no project file above the source, a timeout, a tool that
# could not be started -- is the absence of an answer. A caller that treats
# a refusal as proof of anything must be able to tell the two apart without
# reading prose, so the answer carries this marker and nothing else does.
TOOLCHAIN_REJECTED = "rejected by the toolchain: "


def rejected_by_toolchain(reason: str) -> bool:
    """Whether a check's reason is the toolchain's own rejection of the
    tree, rather than a report that the check could not be made."""
    return reason.startswith(TOOLCHAIN_REJECTED)


def without_rejection_marker(reason: str) -> str:
    """The reason as prose, for a caller that has already said which of the
    two cases it is in."""
    return reason[len(TOOLCHAIN_REJECTED):] if rejected_by_toolchain(reason) else reason


def _nearest(project_root: Path, rel_file: str, marker_names: tuple[str, ...]) -> Optional[Path]:
    """The closest directory at or above ``rel_file`` (bounded by the
    project root) holding one of ``marker_names``."""
    root = project_root.resolve()
    current = (root / rel_file).resolve().parent
    while True:
        for name in marker_names:
            if any(True for _ in glob.iglob(str(current / name))):
                return current
        if current == root or root not in current.parents:
            return None
        current = current.parent


def _run(argv: list[str], cwd: Path, runner: Optional[Runner], env: Optional[dict] = None) -> str:
    code, out, err, note = run_command(argv, cwd=cwd, env=env, timeout=CHECK_TIMEOUT, runner=runner)
    if note:
        return f"{argv[0]}: {note}"
    if code != 0:
        return f"{TOOLCHAIN_REJECTED}{' '.join(argv[:2])} failed: {tail(err or out)}"
    return ""


def check_go(project_root: Path, rel_file: str, runner: Optional[Runner] = None) -> str:
    if which("go") is None:
        return "go is not installed, so the mutated tree could not be compiled"
    cwd = _nearest(project_root, rel_file, ("go.mod",)) or project_root
    return _run(["go", "build", "./..."], cwd, runner)


def check_rust(project_root: Path, rel_file: str, runner: Optional[Runner] = None) -> str:
    if which("cargo") is None:
        return "cargo is not installed, so the mutated tree could not be checked"
    cwd = _nearest(project_root, rel_file, ("Cargo.toml",))
    if cwd is None:
        return "no Cargo.toml above the mechanism file"
    return _run(["cargo", "check", "--quiet", "--tests"], cwd, runner)


def _gradle(cwd: Path) -> list[str]:
    wrapper = cwd / "gradlew"
    if wrapper.is_file():
        return [str(wrapper)]
    return ["gradle"] if which("gradle") else []


def check_java(project_root: Path, rel_file: str, runner: Optional[Runner] = None,
               work_dir: Optional[Path] = None) -> str:
    maven_dir = _nearest(project_root, rel_file, ("pom.xml",))
    if maven_dir is not None and which("mvn"):
        return _run(["mvn", "-q", "-B", "-DskipTests", "compile"], maven_dir, runner)
    gradle_dir = _nearest(project_root, rel_file, ("build.gradle", "build.gradle.kts"))
    if gradle_dir is not None:
        argv = _gradle(gradle_dir)
        if argv:
            return _run(argv + ["compileJava", "-q"], gradle_dir, runner)
    if which("javac") is None:
        return "javac is not installed, so the mutated file could not be compiled"
    out = str(work_dir or project_root / ".mipiti-javac")
    os.makedirs(out, exist_ok=True)
    return _run(["javac", "-d", out, "-proc:none", rel_file], project_root, runner)


def check_kotlin(project_root: Path, rel_file: str, runner: Optional[Runner] = None,
                 work_dir: Optional[Path] = None) -> str:
    gradle_dir = _nearest(project_root, rel_file, ("build.gradle", "build.gradle.kts"))
    if gradle_dir is not None:
        argv = _gradle(gradle_dir)
        if argv:
            return _run(argv + ["compileKotlin", "-q"], gradle_dir, runner)
    maven_dir = _nearest(project_root, rel_file, ("pom.xml",))
    if maven_dir is not None and which("mvn"):
        return _run(["mvn", "-q", "-B", "-DskipTests", "compile"], maven_dir, runner)
    if which("kotlinc") is None:
        return "kotlinc is not installed, so the mutated file could not be compiled"
    out = str(work_dir or project_root / ".mipiti-kotlinc")
    os.makedirs(out, exist_ok=True)
    return _run(["kotlinc", rel_file, "-d", out], project_root, runner)


def check_c(project_root: Path, rel_file: str, runner: Optional[Runner] = None) -> str:
    compiler = which("cc") or which("gcc") or which("clang")
    if compiler is None:
        return "no C compiler (cc/gcc/clang) is installed"
    include = str((project_root / rel_file).parent)
    return _run([compiler, "-fsyntax-only", "-I", str(project_root), "-I", include, rel_file], project_root, runner)


def check_cpp(project_root: Path, rel_file: str, runner: Optional[Runner] = None) -> str:
    compiler = which("c++") or which("g++") or which("clang++")
    if compiler is None:
        return "no C++ compiler (c++/g++/clang++) is installed"
    include = str((project_root / rel_file).parent)
    return _run([compiler, "-fsyntax-only", "-I", str(project_root), "-I", include, rel_file], project_root, runner)


def check_csharp(project_root: Path, rel_file: str, runner: Optional[Runner] = None) -> str:
    if which("dotnet") is None:
        return "dotnet is not installed, so the mutated tree could not be built"
    cwd = _nearest(project_root, rel_file, ("*.csproj", "*.sln")) or project_root
    return _run(["dotnet", "build", "--nologo", "-v", "q"], cwd, runner)


def check_swift(project_root: Path, rel_file: str, runner: Optional[Runner] = None) -> str:
    package_dir = _nearest(project_root, rel_file, ("Package.swift",))
    if package_dir is not None and which("swift"):
        return _run(["swift", "build"], package_dir, runner)
    if which("swiftc") is None:
        return "swiftc is not installed, so the mutated file could not be type-checked"
    return _run(["swiftc", "-typecheck", rel_file], project_root, runner)


def check_verilog(project_root: Path, rel_file: str, runner: Optional[Runner] = None) -> str:
    if which("verilator"):
        return _run(["verilator", "--lint-only", "-Wno-fatal", rel_file], project_root, runner)
    if which("slang"):
        return _run(["slang", "--lint-only", rel_file], project_root, runner)
    if which("iverilog"):
        return _run(["iverilog", "-g2012", "-t", "null", rel_file], project_root, runner)
    return "no Verilog lint tool (verilator, slang or iverilog) is installed"


def check_vhdl(project_root: Path, rel_file: str, runner: Optional[Runner] = None,
               work_dir: Optional[Path] = None) -> str:
    work = str(work_dir or project_root / ".mipiti-vhdl")
    os.makedirs(work, exist_ok=True)
    if which("ghdl"):
        return _run(["ghdl", "-a", "--std=08", f"--workdir={work}", rel_file], project_root, runner)
    if which("nvc"):
        return _run(["nvc", f"--work=work:{work}", "-a", rel_file], project_root, runner)
    return "no VHDL analyser (ghdl or nvc) is installed"


CHECKS = {
    "go": check_go,
    "rust": check_rust,
    "java": check_java,
    "kotlin": check_kotlin,
    "c": check_c,
    "cpp": check_cpp,
    "csharp": check_csharp,
    "swift": check_swift,
    "verilog": check_verilog,
    "systemverilog": check_verilog,
    "vhdl": check_vhdl,
}


def compile_check(language: str, project_root: Path, rel_file: str, *,
                  runner: Optional[Runner] = None, work_dir: Optional[Path] = None) -> str:
    """Empty when the tree compiles; otherwise the reason it does not."""
    check = CHECKS.get(language)
    if check is None:
        return f"no compile check is defined for {language or 'this language'}"
    try:
        return check(project_root, rel_file, runner, work_dir)  # type: ignore[call-arg]
    except TypeError:
        return check(project_root, rel_file, runner)

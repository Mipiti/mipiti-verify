"""Maven (``-Dtest=``) and Gradle (``--tests``)."""

from __future__ import annotations

import re
from pathlib import Path
from . import AdapterError, RunnerAdapter
from ._common import OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, Outcome, tail


def split_test_id(test_id: str) -> tuple[str, str]:
    """``(class, method)`` from ``Class::method``, ``Class#method``,
    ``pkg.Class.method`` (a lower-case leaf after a capitalised class) or a
    bare class."""
    text = str(test_id or "").strip()
    for sep in ("::", "#"):
        if sep in text:
            cls, _, method = text.partition(sep)
            return cls.strip(), method.strip()
    parts = text.split(".")
    if len(parts) >= 2 and parts[-2][:1].isupper() and not parts[-1][:1].isupper():
        return ".".join(parts[:-1]), parts[-1]
    return text, ""


class MavenAdapter(RunnerAdapter):
    name = "maven"
    languages = ("java", "kotlin")
    mutation_languages = ("java", "kotlin")

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        return (Path(project_root) / "pom.xml").is_file()

    def select_argv(self, test_id: str) -> list[str]:
        cls, method = split_test_id(test_id)
        selector = f"{cls}#{method}" if method else cls
        return ["mvn", "-q", "-B", "test", f"-Dtest={selector}",
                "-Dsurefire.failIfNoSpecifiedTests=true", "-DfailIfNoTests=true"]

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        text = stdout + stderr
        if "COMPILATION ERROR" in text or "BUILD FAILURE" in text and "Tests run:" not in text:
            if "No tests were executed" in text or "No tests matching" in text:
                return Outcome(OUTCOME_ERROR, returncode, "maven selected no tests")
            return Outcome(OUTCOME_ERROR, returncode, f"maven build failed: {tail(text, 4)}")
        if "No tests were executed" in text or "No tests matching pattern" in text:
            return Outcome(OUTCOME_ERROR, returncode, "maven selected no tests")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 1:
            return Outcome(OUTCOME_FAILED, 1)
        return Outcome(OUTCOME_ERROR, returncode, f"maven exit status {returncode}: {tail(text, 4)}")

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        pom = (self.project_root / "pom.xml").read_text(encoding="utf-8", errors="replace")
        if "jacoco-maven-plugin" not in pom:
            raise AdapterError("pom.xml does not configure jacoco-maven-plugin")
        outcome = self._execute(self.select_argv(test_id) + ["jacoco:report"], env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "maven could not run under coverage")
        report = self.project_root / "target" / "site" / "jacoco" / "jacoco.xml"
        if not report.is_file():
            raise AdapterError("maven wrote no target/site/jacoco/jacoco.xml")
        return report


class GradleAdapter(RunnerAdapter):
    name = "gradle"
    languages = ("java", "kotlin")
    mutation_languages = ("java", "kotlin")

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        root = Path(project_root)
        return (root / "build.gradle").is_file() or (root / "build.gradle.kts").is_file()

    def _gradle(self) -> list[str]:
        wrapper = self.project_root / "gradlew"
        if wrapper.is_file():
            return [str(wrapper)]
        return ["gradle"]

    def select_argv(self, test_id: str) -> list[str]:
        cls, method = split_test_id(test_id)
        selector = f"{cls}.{method}" if method else cls
        return self._gradle() + ["cleanTest", "test", "--tests", selector, "-q"]

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        text = stdout + stderr
        if "No tests found for given includes" in text:
            return Outcome(OUTCOME_ERROR, returncode, "gradle selected no tests")
        if "Compilation failed" in text or "compileJava FAILED" in text or "compileKotlin FAILED" in text:
            return Outcome(OUTCOME_ERROR, returncode, f"gradle build failed: {tail(text, 4)}")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 1:
            if "FAILED" in text and re.search(r"\btest\b.*FAILED|tests? completed, \d+ failed", text):
                return Outcome(OUTCOME_FAILED, 1)
            return Outcome(OUTCOME_FAILED, 1)
        return Outcome(OUTCOME_ERROR, returncode, f"gradle exit status {returncode}: {tail(text, 4)}")

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        build_files = [self.project_root / "build.gradle", self.project_root / "build.gradle.kts"]
        text = "".join(p.read_text(encoding="utf-8", errors="replace") for p in build_files if p.is_file())
        if "jacoco" not in text:
            raise AdapterError("the build script does not apply the jacoco plugin")
        outcome = self._execute(self.select_argv(test_id) + ["jacocoTestReport"], env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "gradle could not run under coverage")
        report = self.project_root / "build" / "reports" / "jacoco" / "test" / "jacocoTestReport.xml"
        if not report.is_file():
            raise AdapterError(
                "gradle wrote no build/reports/jacoco/test/jacocoTestReport.xml; enable the XML report")
        return report

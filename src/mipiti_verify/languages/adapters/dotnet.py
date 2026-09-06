"""``dotnet test --filter``."""

from __future__ import annotations

from pathlib import Path
from . import AdapterError, RunnerAdapter
from ._common import OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, Outcome, tail


def test_filter(test_id: str) -> str:
    text = str(test_id or "").strip()
    if "::" in text:
        cls, _, method = text.partition("::")
        return f"FullyQualifiedName~{cls.strip()}.{method.strip()}"
    if "." in text:
        return f"FullyQualifiedName={text}"
    return f"Name={text}"


class DotnetAdapter(RunnerAdapter):
    name = "dotnet"
    languages = ("csharp",)
    mutation_languages = ("csharp",)

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        root = Path(project_root)
        return any(root.glob("*.sln")) or any(root.glob("*.csproj")) or any(root.glob("*/*.csproj"))

    def select_argv(self, test_id: str) -> list[str]:
        return ["dotnet", "test", "--nologo", "-v", "q", "--filter", test_filter(test_id)]

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        text = stdout + stderr
        if "No test matches the given testcase filter" in text or "No test is available" in text:
            return Outcome(OUTCOME_ERROR, returncode, "dotnet test selected no tests")
        if "Build FAILED" in text or "error CS" in text:
            return Outcome(OUTCOME_ERROR, returncode, f"dotnet build failed: {tail(text, 4)}")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 1:
            return Outcome(OUTCOME_FAILED, 1)
        return Outcome(OUTCOME_ERROR, returncode, f"dotnet test exit status {returncode}: {tail(text, 4)}")

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        argv = self.select_argv(test_id) + [
            "--collect:XPlat Code Coverage", "--results-directory", str(work_dir)]
        outcome = self._execute(argv, env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "dotnet test could not run under coverage")
        reports = sorted(Path(work_dir).glob("**/coverage.cobertura.xml"))
        if not reports:
            raise AdapterError("dotnet test wrote no coverage.cobertura.xml; is coverlet.collector referenced?")
        return reports[0]

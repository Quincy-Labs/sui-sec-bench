"""Shared helpers: load cases, copy packages, run `sui move test`."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Case:
    path: Path
    meta: dict

    @property
    def id(self) -> str:
        return self.meta["id"]


def load_cases(root: Path) -> list[Case]:
    """All cases under root (folders with a meta.yaml; underscore folders are skipped)."""
    cases = []
    for d in sorted(root.iterdir()):
        if d.is_dir() and not d.name.startswith("_") and (d / "meta.yaml").exists():
            meta = yaml.safe_load((d / "meta.yaml").read_text()) or {}
            cases.append(Case(d, meta))
    return cases


def read_sources(pkg: Path) -> str:
    """Concatenate .move sources for the model, with file headers."""
    parts = []
    for f in sorted((pkg / "sources").rglob("*.move")):
        parts.append(f"// File: {f.relative_to(pkg)}\n{f.read_text()}")
    return "\n\n".join(parts)


def model_visible_files(case: Case) -> list[Path]:
    """Files the model sees: vulnerable sources and the prompt."""
    files = sorted((case.path / "vulnerable" / "sources").rglob("*.move"))
    prompt = case.path / "prompt.md"
    if prompt.exists():
        files.append(prompt)
    return files


@dataclass
class MoveTestResult:
    passed: bool
    phase: str  # ok | build_failed | test_failed | build_timeout | timeout | error
    log: str
    returncode: int | None = None


_TEST_PHASE_MARK = re.compile(r"Running Move unit tests", re.I)


def _decode(b) -> str:
    if isinstance(b, bytes):
        return b.decode(errors="replace")
    return b or ""


def run_move_tests(
    pkg: Path, test_dirs: list[Path], extra_files: dict[str, str] | None = None, timeout: int = 900
) -> MoveTestResult:
    """Copy pkg to a temp dir, add test files, run `sui move test`.

    The source package is never modified. The returned log carries
    `SSB-RUN phase=<phase>` markers so build failure, test failure, and
    timeout are distinguishable downstream.
    """
    with tempfile.TemporaryDirectory(prefix="ssb-") as tmp:
        work = Path(tmp) / "pkg"
        try:
            shutil.copytree(pkg, work)
        except OSError as e:
            return MoveTestResult(False, "error", f"SSB-RUN phase=error setup failed: {e}")
        tests = work / "tests"
        tests.mkdir(exist_ok=True)
        for d in test_dirs:
            if d and d.exists():
                for f in sorted(d.glob("*.move")):
                    shutil.copy(f, tests / f.name)
        for name, content in (extra_files or {}).items():
            (tests / name).write_text(content)
        log = f"SSB-RUN phase=setup pkg={pkg.name}\n"
        try:
            proc = subprocess.run(
                ["sui", "move", "test"], cwd=work, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired as e:
            out = _decode(e.stdout)
            err = _decode(e.stderr)
            phase = "timeout" if _TEST_PHASE_MARK.search(out) else "build_timeout"
            return MoveTestResult(False, phase, log + f"SSB-RUN phase={phase} after {timeout}s\n{out}\n{err}")
        out, err = proc.stdout or "", proc.stderr or ""
        ran = _TEST_PHASE_MARK.search(out) or _TEST_PHASE_MARK.search(err)
        if proc.returncode == 0:
            phase = "ok"
        elif ran:
            phase = "test_failed"
        else:
            phase = "build_failed"
        tail = (out + err)[-8000:]
        return MoveTestResult(
            proc.returncode == 0,
            phase,
            log + f"SSB-RUN phase={phase} rc={proc.returncode}\n{tail}",
            returncode=proc.returncode,
        )


def write_package_with_sources(src_pkg: Path, new_sources: dict[str, str], dest: Path) -> Path:
    """Copy a package and replace its sources (used to apply a model's patch)."""
    shutil.copytree(src_pkg, dest)
    for rel, content in new_sources.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return dest


def safe_source_path(rel: str) -> bool:
    """True if rel is a file path inside sources/ with no directory escapes.

    Patch grading uses this to keep model output from writing outside the
    package sources or overwriting the case's test folders.
    """
    rel = (rel or "").strip().lstrip("/")
    if not rel.startswith("sources/"):
        return False
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts:
        return False
    return len(p.parts) >= 2


def validate_source_paths(files: dict) -> list[str]:
    """Return the unsafe paths in a model patch (empty means all safe)."""
    return [p for p in files if not safe_source_path(p)]

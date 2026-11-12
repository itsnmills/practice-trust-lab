"""Packaging contract: the project installs, both entry styles work, and CI's
dev tooling is configured where the workflows expect it."""

from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    tomllib = pytest.importorskip("tomli")

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


@pytest.fixture(scope="module")
def project() -> dict[str, Any]:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _module_and_attr(target: str) -> tuple[str, str]:
    module, _, attr = target.partition(":")
    assert module and attr, f"bad entry-point target: {target!r}"
    return module, attr


def test_package_layout_matches_build_config(project: dict[str, Any]) -> None:
    assert (ROOT / "evidence" / "practice_evidence" / "__init__.py").is_file()
    assert (ROOT / "evidence" / "practice_evidence" / "sections" / "__init__.py").is_file()
    setuptools_cfg = project["tool"]["setuptools"]
    assert setuptools_cfg["package-dir"][""] == "evidence"
    assert setuptools_cfg["packages"]["find"]["where"] == ["evidence"]
    assert "practice_evidence*" in setuptools_cfg["packages"]["find"]["include"]
    assert "practice_render*" in setuptools_cfg["packages"]["find"]["include"]
    assert setuptools_cfg["package-data"]["practice_render"] == ["assets/*.css"]


def test_runtime_dependencies_are_empty(project: dict[str, Any]) -> None:
    assert project["project"]["dependencies"] == []


def test_requires_python_covers_ci_matrix(project: dict[str, Any]) -> None:
    assert project["project"]["requires-python"] == ">=3.10"


def test_console_scripts_exist_and_resolve(project: dict[str, Any]) -> None:
    scripts = project["project"]["scripts"]
    assert scripts["velari-collect"] == "practice_evidence.cli:main"
    assert scripts["velari-render"] == "render_practice_snapshot:main"
    assert scripts["velari-verify"] == "verify_evidence:main"
    for name, target in scripts.items():
        module_name, attr = _module_and_attr(target)
        module = importlib.import_module(module_name)
        assert callable(getattr(module, attr)), f"{name} -> {target} is not callable"


def test_every_package_module_is_discovered() -> None:
    """New sections must be inside the packaged tree, not a sibling directory."""
    package = importlib.import_module("practice_evidence")
    package_dir = Path(package.__file__).resolve().parent
    assert package_dir == (ROOT / "evidence" / "practice_evidence").resolve()
    for module in sorted(package_dir.rglob("*.py")):
        assert module.name == "__init__.py" or module.stem.isidentifier(), module
        rel = module.relative_to(package_dir).with_suffix("")
        assert " " not in str(rel)


@pytest.mark.parametrize(
    "script",
    ["evidence/collect_practice_evidence.py", "evidence/render_practice_snapshot.py"],
)
def test_legacy_script_entry_style_still_works(script: str) -> None:
    result = subprocess.run(
        [sys.executable, script, "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()


def test_installed_console_scripts_work_when_available() -> None:
    # CI invokes .venv/bin/python without activating the venv, so PATH alone misses the scripts.
    search = f"{Path(sys.executable).parent}:{os.environ.get('PATH', '')}"
    collect = shutil.which("velari-collect", path=search)
    if not collect:  # pragma: no cover - only in a bare checkout
        pytest.skip("project is not installed in this environment")
    result = subprocess.run([collect, "--help"], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "--verify-ledger" in result.stdout
    verify = shutil.which("velari-verify", path=search)
    assert verify, "velari-verify console script was not installed"
    result = subprocess.run([verify, "--help"], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "checkpoint" in result.stdout


def test_dev_tooling_configured(project: dict[str, Any]) -> None:
    tool = project["tool"]
    assert tool["ruff"]["target-version"] == "py310"
    assert tool["mypy"]["files"] == ["evidence/practice_evidence"]
    assert tool["mypy"]["disallow_untyped_defs"] is True
    assert tool["coverage"]["run"]["branch"] is True
    assert tool["coverage"]["report"]["fail_under"] >= 50
    assert project["project"]["optional-dependencies"]["dev"]


def test_no_docker_needed_for_unit_suite() -> None:
    """Guardrail: the default suite must stay runnable with no lab and no
    privilege. Only the explicitly-marked heavy workflow may start Docker."""
    workflow_dir = ROOT / ".github" / "workflows"
    if not workflow_dir.is_dir():
        pytest.skip("no workflows directory")
    for path in workflow_dir.glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        starts_lab = "bootstrap.sh" in text or "run-evidence.sh" in text
        if starts_lab:
            # Heavy/manual workflows must not run on every push.
            assert "workflow_dispatch" in text, f"{path.name} starts the lab without workflow_dispatch"

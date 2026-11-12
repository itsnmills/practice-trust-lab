"""Static checks for the lab shell scripts, plus teardown dry-run behaviour."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIRS = [ROOT / "scripts", ROOT / "samba-dc", ROOT / "endpoint"]
SCRIPTS = sorted(path for directory in SCRIPT_DIRS for path in directory.glob("*.sh"))
SCRIPT_IDS = [str(path.relative_to(ROOT)) for path in SCRIPTS]


def run(*args, **kwargs):
    return subprocess.run(list(args), capture_output=True, text=True, **kwargs)


def test_scripts_are_discovered():
    names = {path.name for path in SCRIPTS}
    assert {"bootstrap.sh", "teardown.sh", "verify-boundaries.sh", "entrypoint.sh"} <= names


@pytest.mark.parametrize("script", SCRIPTS, ids=SCRIPT_IDS)
def test_bash_syntax(script):
    result = run("bash", "-n", str(script))
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("script", SCRIPTS, ids=SCRIPT_IDS)
def test_scripts_are_executable(script):
    assert script.stat().st_mode & 0o111, f"{script} is not executable"


@pytest.mark.parametrize("script", SCRIPTS, ids=SCRIPT_IDS)
def test_scripts_use_strict_mode(script):
    text = script.read_text(encoding="utf-8")
    assert text.startswith("#!"), f"{script} has no shebang"
    assert "set -euo pipefail" in text, f"{script} does not set -euo pipefail"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
@pytest.mark.parametrize("script", SCRIPTS, ids=SCRIPT_IDS)
def test_shellcheck(script):
    result = run("shellcheck", "--severity=warning", "--shell=bash", str(script))
    assert result.returncode == 0, result.stdout + result.stderr


def test_teardown_dry_run_lists_every_compose_project():
    result = run("bash", str(ROOT / "scripts" / "teardown.sh"), "--dry-run")
    assert result.returncode == 0, result.stderr
    for directory in ("workstation-01", "frontdesk-01", "msp-jump-01", "clinic-ehr", "samba-dc"):
        assert f"{directory}/docker-compose.yml" in result.stdout
    assert "docker network rm mills-lab" in result.stdout
    assert "docker volume rm mills-lab-shares" in result.stdout
    assert "nothing was changed" in result.stdout


def test_teardown_dry_run_only_prints_prefixed_actions():
    result = run("bash", str(ROOT / "scripts" / "teardown.sh"), "--dry-run")
    assert result.returncode == 0
    action_lines = [line for line in result.stdout.splitlines() if "docker" in line]
    assert action_lines
    assert all(line.startswith("[dry-run] ") for line in action_lines)


def test_teardown_dry_run_does_not_need_a_docker_daemon():
    result = run(
        "bash",
        str(ROOT / "scripts" / "teardown.sh"),
        "--dry-run",
        env={"PATH": "/usr/bin:/bin", "DOCKER_HOST": "unix:///nonexistent/docker.sock"},
    )
    assert result.returncode == 0, result.stderr


def test_teardown_dry_run_with_purge_data_is_safe():
    result = run("bash", str(ROOT / "scripts" / "teardown.sh"), "--dry-run", "--purge-data")
    assert result.returncode == 0
    assert "rm -rf clinic-ehr/data" in result.stdout
    assert "nothing was changed" in result.stdout


def test_teardown_help_and_bad_option():
    help_result = run("bash", str(ROOT / "scripts" / "teardown.sh"), "--help")
    assert help_result.returncode == 0
    assert "--dry-run" in help_result.stdout
    bad = run("bash", str(ROOT / "scripts" / "teardown.sh"), "--nope")
    assert bad.returncode != 0
    assert "unknown option" in bad.stderr


def test_compose_files_keep_documented_container_names():
    expected = {
        "workstation-01/docker-compose.yml": "container_name: ws-clinical-01",
        "frontdesk-01/docker-compose.yml": "container_name: fd-frontdesk-01",
        "msp-jump-01/docker-compose.yml": "container_name: msp-jump-01",
        "clinic-ehr/docker-compose.yml": "container_name: clinic-ehr",
        "samba-dc/docker-compose.yml": "container_name: samba-dc",
    }
    for relative, marker in expected.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert marker in text, f"{relative} is missing {marker}"

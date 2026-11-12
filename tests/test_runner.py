"""Read-only runner contract: allowlist, refusals, fake runner, preflight."""

from __future__ import annotations

import subprocess

import pytest
from practice_evidence import config, runner
from practice_evidence.runner import (
    ERROR_PREFIX,
    CommandRefused,
    DockerRunner,
    FakeRunner,
    get_runner,
    set_runner,
    sh,
    use_runner,
)

DC = config.DC
BUMBLEBEE = str(config.BUMBLEBEE_DIR / "bin" / "bumblebee")


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = ""):
        self.returncode = returncode
        self.stdout = stdout


def _dexec(*cmd: str) -> list[str]:
    return ["docker", "exec", DC, *cmd]


ALLOWED = [
    ["docker", "info"],
    ["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Ports}}"],
    ["docker", "inspect", "-f", "{{.State.Running}}", DC],
    ["docker", "inspect", "--format", "{{.Name}}", "clinic-ehr"],
    ["docker", "inspect", DC],
    ["docker", "logs", DC],
    ["docker", "logs", "--since", "24h", DC],
    ["docker", "logs", "--since", "15m", "ws-clinical-01"],
    _dexec("samba-tool", "user", "list"),
    _dexec("samba-tool", "group", "list"),
    _dexec("samba-tool", "domain", "level", "show"),
    _dexec("samba-tool", "ntacl", "get", "/srv/samba/shares/clinical", "--as-sddl"),
    _dexec("wbinfo", "-s", "S-1-5-21-1004336348-1177238915-682003330-1105"),
    _dexec("samba-tool", "user", "show", "jchen"),
    _dexec("samba-tool", "user", "show", "DC1$"),
    _dexec("samba-tool", "group", "listmembers", "Domain Admins"),
    _dexec("samba-tool", "group", "listmembers", "SG-IT"),
    _dexec("samba-tool", "domain", "passwordsettings", "show"),
    _dexec("cat", "/etc/samba/smb.conf"),
    _dexec("find", "/srv/samba/shares", "-type", "f"),
    _dexec("sha256sum", "/srv/samba/shares/clinical/patient-schedule-export-2026-09.csv"),
    [BUMBLEBEE, "scan", "--findings-only", "--max-duration", "90s"],
    [
        BUMBLEBEE,
        "scan",
        "--findings-only",
        "--max-duration",
        "90s",
        "--root",
        "/lab/workstation-01/home",
        "--exposure-catalog",
        "/lab/evidence/.catalogs",
    ],
]


@pytest.mark.parametrize("argv", ALLOWED)
def test_read_only_allowlist_accepts_known_safe_commands(argv):
    DockerRunner().validate(argv)


REFUSED = [
    ["docker", "exec", DC, "samba-tool", "user", "create", "eve"],
    ["docker", "exec", DC, "samba-tool", "user", "delete", "jchen"],
    ["docker", "exec", DC, "samba-tool", "group", "addmembers", "SG-IT", "eve"],
    ["docker", "exec", DC, "rm", "-rf", "/srv/samba/shares"],
    ["docker", "exec", DC, "sh", "-c", "rm -rf /srv"],
    ["docker", "exec", DC, "bash", "-c", "cat /etc/shadow"],
    ["docker", "exec", DC, "find", "/srv/samba/shares", "-type", "f", "-delete"],
    ["docker", "exec", DC, "find", "/srv/samba/shares", "-type", "f", "-exec", "rm", "{}", ";"],
    ["docker", "exec", DC, "find", "/srv/samba/shares", "-type", "f", "-exec", "sh", "-c", "id", ";"],
    ["docker", "exec", DC, "cat", "/etc/passwd"],
    ["docker", "exec", DC, "cat", "/srv/samba/shares/../smb.conf"],
    ["docker", "exec", DC, "sha256sum", "/etc/shadow"],
    ["docker", "exec", DC, "sha256sum", "/srv/samba/shares/../../etc/shadow"],
    ["docker", "exec", DC, "samba-tool", "user", "show", "jchen; rm -rf /"],
    ["docker", "exec", DC, "samba-tool", "user", "show", "$(id)"],
    ["docker", "exec", DC, "samba-tool", "user", "show", "jchen\nrm -rf /"],
    ["docker", "exec", DC, "samba-tool", "user", "list", "--verbose"],
    ["docker", "exec", DC, "samba-tool", "ntacl", "set", "/srv/samba/shares/clinical", "--sddl", "D:PAI"],
    ["docker", "exec", DC, "samba-tool", "domain", "level", "raise", "--function-level", "2016"],
    ["docker", "exec", DC, "wbinfo", "--add", "evil"],
    ["docker", "exec", DC, "wbinfo", "-s", "not-a-sid"],
    ["docker", "exec", DC, "wbinfo", "-s", "S-1-5-21-1; rm -rf /"],
    ["docker", "exec", DC, "samba-tool", "domain", "passwordsettings", "set", "--min-pwd-length=4"],
    ["docker", "exec", "clinic-ehr", "cat", "/etc/passwd"],
    ["docker", "exec", "ws-clinical-01", "samba-tool", "user", "list"],
    ["docker", "exec", DC, "tee", "/etc/samba/smb.conf"],
    ["docker", "exec", DC, "install", "-m", "777", "/tmp/x", "/etc/samba/smb.conf"],
    ["docker", "run", "--rm", "alpine", "sh"],
    ["docker", "rm", "-f", DC],
    ["docker", "inspect", "-f", "{{.State.Running}}", "unrelated-container"],
    ["docker", "logs", "--since", "24h", "unrelated-container"],
    ["docker", "logs", "--follow", DC],
    ["docker", "logs", "--since", "24h; rm -rf /", DC],
    ["rm", "-rf", "/"],
    ["sh", "-c", "id"],
    ["/bin/sh", "-c", "id"],
    ["cat", "/etc/passwd"],
    ["find", "/srv/samba/shares", "-delete"],
    [BUMBLEBEE, "scan", "--findings-only", "--delete"],
    ["/tmp/evil/bumblebee", "scan", "--findings-only"],
]


@pytest.mark.parametrize("argv", REFUSED)
def test_write_ish_and_bypass_commands_are_refused(argv):
    with pytest.raises(CommandRefused):
        DockerRunner().validate(argv)


@pytest.mark.parametrize("argv", REFUSED)
def test_refused_commands_never_reach_subprocess(argv, monkeypatch):
    def explode(*args, **kwargs):  # pragma: no cover - should never run
        raise AssertionError(f"refused command executed: {args!r}")

    monkeypatch.setattr(runner.subprocess, "run", explode)
    with pytest.raises(CommandRefused):
        DockerRunner().run(argv)


def test_allowed_command_runs_without_a_shell(monkeypatch):
    seen = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        return _Completed(0, "ok\n")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert DockerRunner().run(["docker", "info"]) == "ok"
    assert seen["args"] == ["docker", "info"]
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["timeout"] == 30


def test_nonzero_exit_becomes_error_string(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: _Completed(3, "permission denied"))
    assert DockerRunner().run(["docker", "logs", DC]) == f"{ERROR_PREFIX} exit 3: permission denied"


def test_missing_binary_becomes_error_string(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(runner.subprocess, "run", missing)
    out = DockerRunner().run(["docker", "info"])
    assert out.startswith(f"{ERROR_PREFIX} command not found: docker")


def test_sh_turns_refusal_into_error_prefix_without_executing(monkeypatch):
    def explode(*args, **kwargs):  # pragma: no cover - should never run
        raise AssertionError("refused command executed")

    monkeypatch.setattr(runner.subprocess, "run", explode)
    with use_runner(DockerRunner()):
        out = sh(["docker", "exec", DC, "rm", "-rf", "/"])
    assert out.startswith(f"{ERROR_PREFIX} refused:")
    assert "rm -rf /" in out


def test_sh_delegates_to_installed_runner():
    fake = FakeRunner({("docker", "info"): "hello"})
    with use_runner(fake):
        assert sh(["docker", "info"]) == "hello"
        assert fake.calls == [["docker", "info"]]


def test_set_runner_returns_previous_and_none_restores_default():
    original = get_runner()
    fake = FakeRunner({})
    previous = set_runner(fake)
    assert previous is original
    assert get_runner() is fake
    restored = set_runner(None)
    assert restored is fake
    assert isinstance(get_runner(), DockerRunner)


def test_use_runner_restores_after_exception():
    original = get_runner()
    with pytest.raises(RuntimeError):
        with use_runner(FakeRunner({})):
            raise RuntimeError("boom")
    assert get_runner() is original


def test_fake_runner_serves_exact_argv_and_records_calls():
    fake = FakeRunner({("docker", "ps", "--format", "x"): "row"})
    assert fake.run(["docker", "ps", "--format", "x"]) == "row"
    assert fake.run(["docker", "ps", "--format", "y"]) == f"{ERROR_PREFIX} no recorded output"
    assert fake.calls == [["docker", "ps", "--format", "x"], ["docker", "ps", "--format", "y"]]
    fake.add(["docker", "info"], "info")
    assert fake.run(["docker", "info"]) == "info"


def test_fake_runner_is_a_runner_protocol():
    assert isinstance(FakeRunner({}), runner.Runner)
    assert isinstance(DockerRunner(), runner.Runner)


# --- preflight --------------------------------------------------------------


def test_preflight_success():
    fake = FakeRunner(
        {
            ("docker", "info"): "Server Version: 27.0.4\n",
            ("docker", "inspect", "-f", "{{.State.Running}}", DC): "true",
        }
    )
    with use_runner(fake):
        assert runner.preflight() is True


def test_preflight_daemon_failure_returns_false(capsys):
    with use_runner(FakeRunner({("docker", "info"): f"{ERROR_PREFIX} exit 1: Cannot connect to daemon"})):
        assert runner.preflight() is False
    assert "docker daemon not reachable" in capsys.readouterr().err


def test_preflight_missing_cli_returns_false(capsys):
    with use_runner(FakeRunner({("docker", "info"): f"{ERROR_PREFIX} command not found: docker"})):
        assert runner.preflight() is False
    assert "docker CLI not available" in capsys.readouterr().err


def test_preflight_stopped_dc_returns_false(capsys):
    fake = FakeRunner(
        {
            ("docker", "info"): "Server Version: 27.0.4\n",
            ("docker", "inspect", "-f", "{{.State.Running}}", DC): "false",
        }
    )
    with use_runner(fake):
        assert runner.preflight() is False
    assert f"container '{DC}' is not running" in capsys.readouterr().err


def test_subprocess_stdlib_import_still_available():
    # The allowlist test monkeypatches runner.subprocess.run; the real module object
    # must be the stdlib subprocess module.
    assert runner.subprocess is subprocess

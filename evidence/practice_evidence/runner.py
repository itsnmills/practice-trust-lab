"""Subprocess helpers, the read-only runner abstraction, and the Docker/DC preflight.

The collector is read-only by contract, so the only way a command reaches the
operating system is through a :class:`Runner`:

* :class:`DockerRunner` is the production runner. It validates every argv against
  a positive allowlist (see :meth:`DockerRunner.validate`) before calling
  ``subprocess.run`` and never uses a shell.
* :class:`FakeRunner` serves recorded stdout keyed by the exact argv. It is what
  the end-to-end tests use, so the whole pipeline runs without Docker.

Section modules import the module-level :func:`sh` and :func:`dexec` helpers.
Those delegate to the currently installed runner, which can be swapped with
:func:`set_runner` or the :func:`use_runner` context manager without touching a
section file.

A refused command is never executed. It surfaces as a ``__ERROR__`` string so
the calling section records an evidence gap instead of crashing the run.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol, runtime_checkable

from .config import BUMBLEBEE_DIR, DC, LAB_CONTAINERS

ERROR_PREFIX = "__ERROR__"

_SMB_CONF = "/etc/samba/smb.conf"
_SHARE_ROOT = "/srv/samba/shares/"
# Account, group and share-path tokens are strict so a metacharacter, a flag, or
# a traversal segment can never be smuggled into an argument that reaches
# subprocess. Account names include spaces ("Domain Admins") and machine-account
# dollar signs ("DC1$"); share paths stay under the lab share root.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@$-]*$")
_PATH_RE = re.compile(r"^/srv/samba/shares/[A-Za-z0-9 ._@$/-]+$")
_SID_RE = re.compile(r"^S-1-(?:[0-9]+-)+[0-9]+$")
_SINCE_RE = re.compile(r"^[0-9]{1,6}[smhd]$")
_BUMBLEBEE_VALUE_FLAGS = {"--max-duration", "--root", "--exposure-catalog"}
_BUMBLEBEE_BOOL_FLAGS = {"--findings-only", "--quiet"}


class CommandRefused(RuntimeError):
    """A command was rejected by the read-only allowlist and never executed."""


@runtime_checkable
class Runner(Protocol):
    """Minimal runner contract: run one argv and return merged stdout/stderr."""

    def run(self, args: list[str], timeout: int = 30) -> str:  # pragma: no cover - protocol
        ...


def _display(argv: list[str]) -> str:
    return " ".join(argv)


def _is_name(value: str) -> bool:
    return bool(value) and bool(_NAME_RE.match(value))


def _is_share_path(path: str) -> bool:
    if not path.startswith(_SHARE_ROOT) or not _PATH_RE.match(path):
        return False
    return len(path) > len(_SHARE_ROOT) and ".." not in path.split("/") and "." not in path.split("/")


def _is_bumblebee(argv: list[str]) -> bool:
    """Allow only the lab's Bumblebee binary, and only its read-only scan mode."""
    if len(argv) < 2 or argv[1] != "scan":
        return False
    expected = (BUMBLEBEE_DIR / "bin" / "bumblebee").resolve()
    try:
        if Path(argv[0]).resolve() != expected:
            return False
    except OSError:
        return False
    index = 2
    while index < len(argv):
        flag = argv[index]
        if flag in _BUMBLEBEE_BOOL_FLAGS:
            index += 1
            continue
        if flag in _BUMBLEBEE_VALUE_FLAGS:
            if index + 1 >= len(argv):
                return False
            value = argv[index + 1]
            if value.startswith("-") or "\x00" in value:
                return False
            index += 2
            continue
        return False
    return True


def _validate_exec(cmd: list[str]) -> None:
    if cmd == ["samba-tool", "user", "list"]:
        return
    if cmd == ["samba-tool", "group", "list"]:
        return
    if cmd == ["samba-tool", "domain", "passwordsettings", "show"]:
        return
    if cmd == ["samba-tool", "domain", "level", "show"]:
        return
    if len(cmd) == 4 and cmd[:3] == ["samba-tool", "user", "show"] and _is_name(cmd[3]):
        return
    if len(cmd) == 4 and cmd[:3] == ["samba-tool", "group", "listmembers"] and _is_name(cmd[3]):
        return
    # ntacl get renders the effective ACL; ntacl set (and every other verb) is refused.
    if len(cmd) == 5 and cmd[:3] == ["samba-tool", "ntacl", "get"] and cmd[4] == "--as-sddl":
        if _is_share_path(cmd[3]):
            return
    if len(cmd) == 3 and cmd[0] == "wbinfo" and cmd[1] == "-s" and _SID_RE.match(cmd[2]):
        return
    if cmd == ["cat", _SMB_CONF]:
        return
    # Exact argv: no -delete, -exec, or any extra flag can ride along.
    if cmd == ["find", "/srv/samba/shares", "-type", "f"]:
        return
    if len(cmd) == 2 and cmd[0] == "sha256sum" and _is_share_path(cmd[1]):
        return
    raise CommandRefused(f"docker exec command not on the read-only allowlist: {_display(cmd)}")


def _validate_docker(argv: list[str]) -> None:
    if argv == ["docker", "info"]:
        return
    if len(argv) < 2:
        raise CommandRefused("incomplete docker command")
    sub = argv[1]
    if sub == "ps":
        if len(argv) == 4 and argv[2] == "--format":
            return
        raise CommandRefused("docker ps is limited to a --format inventory")
    if sub == "inspect":
        target = None
        if len(argv) == 5 and argv[2] in ("-f", "--format"):
            target = argv[4]
        elif len(argv) == 3:
            target = argv[2]
        if target in LAB_CONTAINERS:
            return
        raise CommandRefused(f"docker inspect is limited to lab containers; refused {target!r}")
    if sub == "logs":
        if len(argv) == 3 and argv[2] in LAB_CONTAINERS:
            return
        if len(argv) == 5 and argv[2] == "--since" and _SINCE_RE.match(argv[3]) and argv[4] in LAB_CONTAINERS:
            return
        raise CommandRefused("docker logs is limited to lab containers and an optional --since window")
    if sub == "exec":
        if len(argv) < 4:
            raise CommandRefused("incomplete docker exec command")
        if argv[2] != DC:
            raise CommandRefused(f"docker exec is limited to the lab DC ({DC}); refused {argv[2]!r}")
        _validate_exec(argv[3:])
        return
    raise CommandRefused(f"docker subcommand not on the read-only allowlist: {sub}")


class DockerRunner:
    """Production runner: allowlisted, shell-free, read-only lab commands only."""

    def validate(self, args: list[str]) -> None:
        """Raise :class:`CommandRefused` unless argv is an approved read-only command."""
        argv = list(args)
        if not argv:
            raise CommandRefused("empty command")
        if any(not isinstance(arg, str) or not arg for arg in argv):
            raise CommandRefused("command arguments must be non-empty strings")
        if any("\x00" in arg for arg in argv):
            raise CommandRefused("command argument contains a NUL byte")
        if argv[0] == "docker":
            _validate_docker(argv)
            return
        if _is_bumblebee(argv):
            return
        raise CommandRefused(f"command not on the read-only allowlist: {_display(argv)}")

    def run(self, args: list[str], timeout: int = 30) -> str:
        self.validate(args)
        argv = list(args)
        try:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                shell=False,
            )
        except FileNotFoundError as exc:
            return f"{ERROR_PREFIX} command not found: {argv[0]} ({exc})"
        except subprocess.TimeoutExpired:
            return f"{ERROR_PREFIX} timed out after {timeout}s: {argv[0]}"
        except Exception as exc:  # noqa: BLE001
            return f"{ERROR_PREFIX} {type(exc).__name__}: {exc}"
        out = (proc.stdout or "").strip()
        if proc.returncode != 0:
            return f"{ERROR_PREFIX} exit {proc.returncode}: {out}".rstrip(": ")
        return out


class FakeRunner:
    """Deterministic runner for tests: serves recorded output keyed by exact argv."""

    def __init__(self, responses: dict[tuple[str, ...], str] | None = None, default: str | None = None):
        self.responses = {tuple(key): value for key, value in (responses or {}).items()}
        self.default = default if default is not None else f"{ERROR_PREFIX} no recorded output"
        self.calls: list[list[str]] = []

    def add(self, args: list[str], output: str) -> FakeRunner:
        self.responses[tuple(args)] = output
        return self

    def run(self, args: list[str], timeout: int = 30) -> str:
        argv = tuple(args)
        self.calls.append(list(argv))
        return self.responses.get(argv, self.default)


_runner: Runner = DockerRunner()


def get_runner() -> Runner:
    return _runner


def set_runner(runner: Runner | None) -> Runner:
    """Install a runner and return the previous one. ``None`` restores the default."""
    global _runner
    previous = _runner
    _runner = runner if runner is not None else DockerRunner()
    return previous


@contextmanager
def use_runner(runner: Runner) -> Iterator[Runner]:
    """Temporarily install a runner; always restores the previous runner."""
    previous = set_runner(runner)
    try:
        yield runner
    finally:
        set_runner(previous)


def sh(args: list[str], timeout: int = 30) -> str:
    """Run through the installed runner, returning output or an ``__ERROR__`` string."""
    try:
        return _runner.run(args, timeout=timeout)
    except CommandRefused as exc:
        return f"{ERROR_PREFIX} refused: {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"{ERROR_PREFIX} {type(exc).__name__}: {exc}"


def dexec(cmd: list[str], timeout: int = 30) -> str:
    return sh(["docker", "exec", DC, *cmd], timeout=timeout)


def preflight() -> bool:
    """Fail fast with a clear message when the lab is not reachable."""
    info = sh(["docker", "info"], timeout=20)
    if info.startswith(ERROR_PREFIX):
        detail = info[len(ERROR_PREFIX) :].strip()
        if "not found" in detail.lower():
            print(f"error: docker CLI not available ({detail})", file=sys.stderr)
        else:
            last = detail.splitlines()[-1] if detail else detail
            print(f"error: docker daemon not reachable ({last}); start Docker and retry", file=sys.stderr)
        return False
    running = sh(["docker", "inspect", "-f", "{{.State.Running}}", DC]).strip()
    if running != "true":
        print(f"error: container '{DC}' is not running; run scripts/bootstrap.sh first", file=sys.stderr)
        return False
    return True

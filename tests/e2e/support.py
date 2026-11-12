"""Support objects for the no-Docker end-to-end collector tests."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence"))

from practice_evidence import config  # noqa: E402
from practice_evidence.runner import ERROR_PREFIX, FakeRunner  # noqa: E402
from practice_evidence.sections import ehr, endpoints, supply_chain  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NOW = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)

PS_FORMAT = "{{.Names}}|{{.Status}}|{{.Ports}}"


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


class _FakeHTTPResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _health_response(status: str = "ok") -> dict:
    return {"status": status, "service": "clinic-ehr", "version": "0.4.2"}


def read_fixture(relative: str, scenario: str = "run1") -> str:
    """Load a fixture, letting ``run2/`` override any file for the drift scenario."""
    if scenario == "run2":
        override = FIXTURES / "run2" / relative
        if override.exists():
            return override.read_text(encoding="utf-8")
    return (FIXTURES / relative).read_text(encoding="utf-8")


def _endpoint_files() -> dict[str, dict[str, str]]:
    return {
        "workstation-01": {
            "patient-schedule-export-2026-09.csv": "synthetic schedule export\n",
            "insurance-verification-2026-09.csv": "synthetic insurance verification\n",
        },
        "frontdesk-01": {
            "intake-form-responses-2026-09.csv": "synthetic intake responses\n",
            "front-desk-runbook.md": "# synthetic front desk runbook\n",
        },
        "msp-jump-01": {
            "backup-runbook.md": "# synthetic backup runbook\n",
            "intake-form-responses-2026-09.csv": "synthetic intake responses\n",
            "front-desk-runbook.md": "# synthetic front desk runbook\n",
        },
    }


class FakeLab:
    """A temporary on-disk lab plus a FakeRunner that answers the DC commands."""

    def __init__(self, tmp_path: Path, monkeypatch):
        self.tmp_path = tmp_path
        self.root = tmp_path / "lab"
        self.artifacts = tmp_path / "out" / "artifacts"
        self.ledger = tmp_path / "out" / "ledger.jsonl"
        self.base_dir = tmp_path / "out"
        self.ehr_log = self.root / "ehr" / "access.jsonl"
        self.bin = tmp_path / "bumblebee" / "bin" / "bumblebee"
        self.catalogs = tmp_path / "bumblebee" / "catalogs" / "vendor" / "bumblebee"
        self.evidence_dir = tmp_path / "supply-evidence"
        self.scan_roots = [self.root / spec["dir"] / "home" for spec in config.ENDPOINTS]
        self._monkeypatch = monkeypatch
        self._build()

    def _build(self) -> None:
        for spec in config.ENDPOINTS:
            incoming = self.root / spec["dir"] / "home" / "Desktop" / "incoming"
            incoming.mkdir(parents=True)
            logs = self.root / spec["dir"] / "logs"
            logs.mkdir(parents=True)
            (logs / "activity.jsonl").write_text(
                (FIXTURES / "endpoints" / "activity.jsonl").read_text(encoding="utf-8"), encoding="utf-8"
            )
            for name, body in _endpoint_files()[spec["dir"]].items():
                (incoming / name).write_text(body, encoding="utf-8")
        self.ehr_log.parent.mkdir(parents=True, exist_ok=True)
        self.bin.parent.mkdir(parents=True, exist_ok=True)
        self.bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.catalogs.mkdir(parents=True, exist_ok=True)
        (self.catalogs / "exposures.json").write_text('{"packages": []}\n', encoding="utf-8")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.set_ehr("run1")

        mp = self._monkeypatch
        mp.setattr(endpoints, "LAB_ROOT", self.root)
        mp.setattr(ehr, "EHR_LOG", self.ehr_log)
        mp.setattr(ehr.urllib.request, "urlopen", lambda *a, **k: _FakeHTTPResponse(_health_response()))
        mp.setattr(supply_chain, "BIN", self.bin)
        mp.setattr(supply_chain, "CATALOGS", self.catalogs)
        mp.setattr(supply_chain, "EVIDENCE_DIR", self.evidence_dir)
        mp.setattr(supply_chain, "SCAN_ROOTS", self.scan_roots)

    def set_ehr(self, scenario: str) -> None:
        self.ehr_log.write_text(read_fixture("ehr/access.jsonl", scenario), encoding="utf-8")

    def scan_command(self) -> list[str]:
        merged = self.evidence_dir / ".catalogs"
        cmd = [str(self.bin), "scan", "--findings-only", "--max-duration", "90s"]
        for root in self.scan_roots:
            cmd += ["--root", str(root)]
        return cmd + ["--exposure-catalog", str(merged)]

    def runner(self, scenario: str = "run1") -> FakeRunner:
        dc = config.DC
        builtins = {"Administrator", "Guest", "krbtgt"}
        users = [
            line.strip()
            for line in read_fixture("samba/user-list.txt", scenario).splitlines()
            if line.strip() and line.strip() not in builtins
        ]
        groups = {
            "Domain Admins": "samba/groups/domain-admins.txt",
            "Enterprise Admins": "samba/groups/enterprise-admins.txt",
            "Schema Admins": "samba/groups/schema-admins.txt",
            "SG-IT": "samba/groups/sg-it.txt",
        }
        all_groups = (
            "Domain Admins\nEnterprise Admins\nSchema Admins\nSG-IT\nSG-Clinical\nSG-FrontOffice\nDL-ClinicalShare-RW\n"
        )
        domain_sid = "S-1-5-21-100-200-300"
        ntacl = {
            "/srv/samba/shares/clinical": (
                f"O:{domain_sid}-512G:{domain_sid}-513D:AI(A;OICI;0x1f01ff;;;{domain_sid}-1105)"
            ),
            "/srv/samba/shares/frontoffice": (
                f"O:{domain_sid}-512G:{domain_sid}-513D:AI"
                f"(A;OICI;0x1f01ff;;;{domain_sid}-1106)(A;OICI;0x1200a9;;;{domain_sid}-1107)"
            ),
            "/srv/samba/shares/it": (f"O:{domain_sid}-512G:{domain_sid}-513D:AI(A;OICI;0x1f01ff;;;{domain_sid}-1107)"),
        }
        wbinfo = {
            f"{domain_sid}-1105": "MILLSLAB\\DL-ClinicalShare-RW",
            f"{domain_sid}-1106": "MILLSLAB\\SG-FrontOffice",
            f"{domain_sid}-1107": "MILLSLAB\\SG-IT",
        }
        smb_conf = read_fixture("smb.conf").replace(
            "   log level = 3 auth_audit:3",
            "   log level = 3 auth_audit:3\n"
            "   server signing = mandatory\n"
            "   ldap server require strong auth = yes\n"
            "   ntlm auth = ntlmv2-only\n"
            "   server min protocol = SMB2",
        )
        krbtgt_age = datetime.now(timezone.utc) - timedelta(days=30)
        krbtgt_ticks = int((krbtgt_age - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
        hashes = json.loads(read_fixture("sha256sums.json", scenario))
        scan = read_fixture("bumblebee/findings.jsonl").replace("__LAB_ROOT__", str(config.LAB_ROOT))

        def dexec(*cmd: str) -> tuple[str, ...]:
            return ("docker", "exec", dc, *cmd)

        responses: dict[tuple[str, ...], str] = {
            ("docker", "info"): "Server Version: 27.0.4\n Containers: 6\n",
            ("docker", "inspect", "-f", "{{.State.Running}}", dc): "true",
            ("docker", "ps", "--format", PS_FORMAT): read_fixture("docker/ps.txt"),
            ("docker", "logs", "--since", "24h", dc): read_fixture("docker/logs-auth.txt", scenario),
            dexec("samba-tool", "domain", "passwordsettings", "show"): read_fixture("samba/passwordsettings.txt"),
            dexec("samba-tool", "user", "list"): "\n".join(users) + "\n",
            dexec("cat", "/etc/samba/smb.conf"): smb_conf,
            dexec("find", "/srv/samba/shares", "-type", "f"): read_fixture("find-shares.txt", scenario),
            dexec("samba-tool", "group", "list"): all_groups,
            dexec("samba-tool", "domain", "level", "show"): "Domain function level: (Windows) 2008 R2\n",
            dexec("samba-tool", "user", "show", "krbtgt"): f"pwdLastSet: {krbtgt_ticks}\n",
        }
        for path, sddl in ntacl.items():
            responses[dexec("samba-tool", "ntacl", "get", path, "--as-sddl")] = sddl
        for sid, name in wbinfo.items():
            responses[dexec("wbinfo", "-s", sid)] = f"{name} 2\n"
        for sam in users:
            responses[dexec("samba-tool", "user", "show", sam)] = read_fixture(f"samba/users/{sam}.txt", scenario)
        for group, relative in groups.items():
            responses[dexec("samba-tool", "group", "listmembers", group)] = read_fixture(relative, scenario)
        for path, digest in hashes.items():
            responses[dexec("sha256sum", path)] = f"{digest}  {path}\n"
        responses[tuple(self.scan_command())] = scan
        return FakeRunner(responses, default=f"{ERROR_PREFIX} unrecorded command")


def run_cli(lab: FakeLab, scenario: str, *extra: str) -> int:
    from practice_evidence import cli
    from practice_evidence.runner import use_runner

    lab.set_ehr(scenario)
    argv = ["--artifacts-dir", str(lab.artifacts), "--ledger", str(lab.ledger), *extra]
    with use_runner(lab.runner(scenario)):
        return cli.main(argv)


def snapshot_files(lab: FakeLab) -> list[Path]:
    return sorted(lab.artifacts.glob("*/*.json"))


def load_snapshot(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


__all__ = [
    "FakeLab",
    "NOW",
    "load_snapshot",
    "read_fixture",
    "run_cli",
    "snapshot_files",
]

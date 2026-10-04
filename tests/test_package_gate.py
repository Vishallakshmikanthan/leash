"""
tests/test_package_gate.py - Comprehensive unit and integration tests for Leash Package Gate (N1).
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

import pytest

from contracts.models import (
    ActionKind,
    ActionRequest,
    DecidedBy,
    Decision,
    Severity,
    TaintContext,
    Verdict,
)
from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.policy_evaluator import PolicyEvaluator
from daemon.server import LeashDaemonServer
from gates.package_gate import (
    AllowOnceManager,
    LockfileInspector,
    PackageActionParser,
    PackageGate,
    PackageKnowledge,
    damerau_levenshtein_distance,
)
from session.manager import SessionManager


def make_request(
    command: str = "",
    kind: ActionKind = ActionKind.SHELL,
    target_path: str = None,
    cwd: str = ".",
    session_id: str = "s_test_pkg",
    tainted: bool = False,
    taint_source: str = None,
    taint_line: int = None,
) -> ActionRequest:
    return ActionRequest(
        id=f"a_{uuid.uuid4().hex[:12]}",
        session=session_id,
        ts=int(time.time()),
        nonce=uuid.uuid4().hex[:8],
        kind=kind,
        command=command,
        target_path=target_path,
        cwd=cwd,
        taint=TaintContext(tainted=tainted, source=taint_source, line=taint_line),
        agent="test-agent",
    )


# -----------------------------------------------------------------------------
# 1. Damerau-Levenshtein & Lookalike Detection Tests
# -----------------------------------------------------------------------------

def test_damerau_levenshtein_distance():
    assert damerau_levenshtein_distance("requests", "requsts") == 1  # Deletion
    assert damerau_levenshtein_distance("flask", "falsk") == 1       # Transposition
    assert damerau_levenshtein_distance("django", "djagno") == 1     # Transposition
    assert damerau_levenshtein_distance("lodash", "lodsh") == 1      # Deletion
    assert damerau_levenshtein_distance("express", "exppress") == 1  # Insertion
    assert damerau_levenshtein_distance("same", "same") == 0


def test_package_knowledge_typosquat_detection():
    knowledge = PackageKnowledge()
    # Explicit catalog typosquats
    match = knowledge.find_typosquat_match("requsts")
    assert match is not None
    assert match[0] == "requests"

    # Transposition
    match = knowledge.find_typosquat_match("falsk")
    assert match is not None
    assert match[0] == "flask"

    # Lookalike affix (colors-pro -> colors)
    match = knowledge.find_typosquat_match("colors-pro")
    assert match is not None
    assert match[0] == "colors"

    # Suffix check (python-dotenvs -> python-dotenv)
    match = knowledge.find_typosquat_match("python-dotenvs")
    assert match is not None
    assert match[0] == "python-dotenv"

    # Legitimate popular package should not be a typosquat of itself
    assert knowledge.find_typosquat_match("requests") is None
    assert knowledge.find_typosquat_match("express") is None


# -----------------------------------------------------------------------------
# 2. Package Action Parser Tests
# -----------------------------------------------------------------------------

def test_package_action_parser_npm():
    req = make_request("npm install colors-pro --save-dev")
    parsed = PackageActionParser.parse_action(req)
    assert parsed.is_package_action is True
    assert parsed.manager == "npm"
    assert parsed.ecosystem == "npm"
    assert len(parsed.packages) == 1
    assert parsed.packages[0].name == "colors-pro"
    assert "--save-dev" in parsed.flags
    assert parsed.has_ignore_scripts is False


def test_package_action_parser_pip():
    req = make_request("pip install requsts==1.0.0")
    parsed = PackageActionParser.parse_action(req)
    assert parsed.is_package_action is True
    assert parsed.manager == "pip"
    assert parsed.ecosystem == "pypi"
    assert len(parsed.packages) == 1
    assert parsed.packages[0].name == "requsts"
    assert parsed.packages[0].version == "1.0.0"


def test_package_action_parser_python_m_pip():
    req = make_request("python -m pip install flask")
    parsed = PackageActionParser.parse_action(req)
    assert parsed.is_package_action is True
    assert parsed.manager == "pip"
    assert len(parsed.packages) == 1
    assert parsed.packages[0].name == "flask"


def test_package_action_parser_cargo():
    req = make_request("cargo add tokio")
    parsed = PackageActionParser.parse_action(req)
    assert parsed.is_package_action is True
    assert parsed.manager == "cargo"
    assert parsed.packages[0].name == "tokio"


def test_package_action_parser_lockfile_edit():
    req = make_request(kind=ActionKind.FILE_EDIT, target_path="package-lock.json")
    parsed = PackageActionParser.parse_action(req)
    assert parsed.is_package_action is True
    assert parsed.is_lockfile_edit is True


# -----------------------------------------------------------------------------
# 3. Package Gate Core Security Evaluation
# -----------------------------------------------------------------------------

def test_package_gate_typosquat_warning():
    gate = PackageGate()
    req = make_request("pip install requsts")
    res = gate.evaluate(req)

    assert res is not None
    assert res.triggered is True
    assert res.rule_id == "R-PKG-TYPOSQUAT"
    assert res.severity == Severity.HIGH
    assert "requests" in res.summary
    assert len(res.reasons) >= 1
    assert "suspiciously close" in res.reasons[0].lower()
    assert "Warning reasons for 'requsts':" in res.why
    assert "requests" in res.safer_alternative


def test_package_gate_install_script_warning():
    gate = PackageGate()
    # colors-pro is registered with preinstall infostealer lifecycle script
    req = make_request("npm install colors-pro")
    res = gate.evaluate(req)

    assert res is not None
    assert res.triggered is True
    assert res.severity == Severity.HIGH
    # Should flag typosquat or install script in reasons
    assert any("lifecycle install scripts" in r.lower() or "close to popular" in r.lower() for r in res.reasons)
    assert res.details["has_install_script"] is True or res.details["is_typosquat"] is True


def test_package_gate_ignore_scripts_mitigation():
    gate = PackageGate()
    # Using a package whose ONLY registered flag is install script (e.g. node-sass)
    req_no_flag = make_request("npm install node-sass")
    res1 = gate.evaluate(req_no_flag)
    assert res1 is not None
    assert res1.details["has_install_script"] is True

    # When --ignore-scripts is provided, install script execution risk is neutralized
    req_with_flag = make_request("npm install node-sass --ignore-scripts")
    res2 = gate.evaluate(req_with_flag)
    assert res2 is None or res2.details["has_install_script"] is False


def test_package_gate_unknown_package_warning():
    gate = PackageGate()
    req = make_request("pip install totally-unheard-of-library-xyz")
    res = gate.evaluate(req)

    assert res is not None
    assert res.triggered is True
    assert res.rule_id == "R-PKG-UNKNOWN"
    assert res.severity == Severity.MEDIUM
    assert "does not exist in configured package knowledge" in res.why


def test_package_gate_very_new_version_warning():
    gate = PackageGate()
    # 0.0.1 is an initial unvetted version pattern
    req = make_request("pip install some-new-package==0.0.1")
    res = gate.evaluate(req)

    assert res is not None
    assert res.triggered is True
    assert any("very new" in r.lower() or "initial" in r.lower() for r in res.reasons)
    assert res.details["is_new_version"] is True


def test_package_gate_taint_escalation():
    gate = PackageGate()
    # Normal unknown package would be MEDIUM; with session taint, escalates to HIGH
    req = make_request(
        "pip install some-tool-abc",
        tainted=True,
        taint_source="README.md",
        taint_line=15,
    )
    res = gate.evaluate(req)
    assert res is not None
    assert res.severity == Severity.HIGH


# -----------------------------------------------------------------------------
# 4. Local Lockfile Inspector & Offline Operation
# -----------------------------------------------------------------------------

def test_lockfile_inspector_npm(tmp_path: Path):
    package_lock = tmp_path / "package-lock.json"
    package_lock.write_text(json.dumps({
        "name": "test-repo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "test-repo"},
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": "sha512-test"
            }
        }
    }), encoding="utf-8")

    inspector = LockfileInspector()
    locked = inspector.inspect_workspace(tmp_path)
    assert "lodash" in locked
    assert locked["lodash"].version == "4.17.21"
    assert locked["lodash"].lockfile_source == "package-lock.json"


def test_lockfile_inspector_requirements_txt(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.32.3\nflask==3.0.3\n", encoding="utf-8")

    inspector = LockfileInspector()
    locked = inspector.inspect_workspace(tmp_path)
    assert "requests" in locked
    assert locked["requests"].version == "2.32.3"
    assert "flask" in locked
    assert locked["flask"].version == "3.0.3"


def test_package_gate_pinned_in_lockfile_passes(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.32.3\n", encoding="utf-8")

    gate = PackageGate()
    req = make_request("pip install requests==2.32.3", cwd=str(tmp_path))
    res = gate.evaluate(req)
    # Clean verified package in local lockfile passes without warning
    assert res is None


def test_lockfile_tampering_detection(tmp_path: Path):
    bad_lock = tmp_path / "package-lock.json"
    bad_lock.write_text(json.dumps({
        "packages": {
            "node_modules/evil": {
                "version": "1.0.0",
                "resolved": "http://evil-unencrypted-repo.com/evil.tgz"
            }
        }
    }), encoding="utf-8")

    inspector = LockfileInspector()
    tampering = inspector.detect_lockfile_tampering(bad_lock)
    assert len(tampering) >= 1
    assert "Insecure registry URL" in tampering[0]

    gate = PackageGate()
    req = make_request(kind=ActionKind.FILE_EDIT, target_path="package-lock.json", cwd=str(tmp_path))
    res = gate.evaluate(req)
    assert res is not None
    assert res.rule_id == "R-PKG-LOCKFILE"
    assert res.severity == Severity.HIGH


# -----------------------------------------------------------------------------
# 5. Safe Allow-Once Authorizations
# -----------------------------------------------------------------------------

def test_allow_once_authorization_flow():
    allow_mgr = AllowOnceManager()
    gate = PackageGate(allow_once_mgr=allow_mgr)

    # 1. Initially flagged as suspicious typosquat
    req = make_request("pip install requsts", session_id="s_allow_1")
    res1 = gate.evaluate(req)
    assert res1 is not None
    assert res1.triggered is True
    assert res1.rule_id == "R-PKG-TYPOSQUAT"

    # 2. Grant allow-once exception for this specific package and session
    grant = gate.allow_once(package_name="requsts", session_id="s_allow_1", decider="biometric")
    assert grant.consumed is False
    assert gate.is_allowed_once("requsts", session_id="s_allow_1") is True

    # 3. Second evaluation consumes allow-once and passes cleanly
    res2 = gate.evaluate(req)
    assert res2 is None
    assert grant.consumed is True

    # 4. Third evaluation is flagged again (allow-once is single-use, not permanent whitelist)
    res3 = gate.evaluate(req)
    assert res3 is not None
    assert res3.triggered is True
    assert res3.rule_id == "R-PKG-TYPOSQUAT"


def test_allow_once_session_isolation():
    allow_mgr = AllowOnceManager()
    gate = PackageGate(allow_once_mgr=allow_mgr)

    # Grant allow-once strictly for session s_user_session
    gate.allow_once(package_name="requsts", session_id="s_user_session", decider="biometric")

    # Different session s_other_session attempts install: MUST be blocked
    req_other = make_request("pip install requsts", session_id="s_other_session")
    res = gate.evaluate(req_other)
    assert res is not None
    assert res.triggered is True


# -----------------------------------------------------------------------------
# 6. Integration with Risk Engine & Policy Evaluator
# -----------------------------------------------------------------------------

def test_policy_evaluator_package_gate_integration():
    evaluator = PolicyEvaluator()
    assert evaluator.package_gate is not None

    req = make_request("pip install requsts")
    # Quick allow must reject package install
    assert evaluator.is_quick_allow(req) is False

    assessment = evaluator.evaluate(req)
    assert assessment.severity == Severity.HIGH
    assert assessment.category == "package-install"
    assert "R-PKG-TYPOSQUAT" in assessment.rule_ids
    assert "requests" in assessment.summary


# -----------------------------------------------------------------------------
# 7. Integration with Daemon Server, Approval Flow & Audit Log
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_daemon_package_gate_allow_once_approval(tmp_path: Path):
    config = DaemonConfig(
        host="127.0.0.1",
        port=0,
        shared_secret="test-secret-pkg",
        audit_log_path=tmp_path / "audit.jsonl",
        receipt_output_path=tmp_path / "receipt.md",
        timeout_seconds=2,
        dev_mode=True,
    )
    session_mgr = SessionManager(tmp_path)
    session = session_mgr.create_session()
    audit_logger = AuditLogger(config.audit_log_path)
    evaluator = PolicyEvaluator()
    server = LeashDaemonServer(config, session_mgr, audit_logger, evaluator)

    req = ActionRequest(
        id="a_pkg_demo",
        session=session.session_id,
        ts=int(time.time()),
        nonce="nonce_pkg_1",
        kind=ActionKind.SHELL,
        command="pip install requsts",
        agent="demo-agent",
        cwd=str(tmp_path),
    )

    # Decider simulates Guard biometric approval with allow-once note
    async def decider(r: ActionRequest, a):
        return Decision(
            id=f"d_appr_{r.id}",
            action_id=r.id,
            session=r.session,
            ts=int(time.time()),
            nonce="nonce_dec_1",
            verdict=Verdict.ALLOW,
            by=DecidedBy.BIOMETRIC,
            note="Approved with allow-once",
        )

    server.register_local_decider(decider)

    decision = await server.submit_action(req)
    assert decision.verdict == Verdict.ALLOW
    assert decision.by == DecidedBy.BIOMETRIC

    # Verify that allow-once was registered on PackageGate
    assert evaluator.package_gate.is_allowed_once("requsts", session_id=session.session_id) is True

    # Verify structured package gate audit entry was recorded
    audit_records = audit_logger.read_session_events(session.session_id)
    pkg_events = [r for r in audit_records if r.get("event_type") == "package_gate_evaluation"]
    assert len(pkg_events) >= 1
    assert pkg_events[0]["target_path"] == "requsts"
    assert pkg_events[0]["metadata"]["allow_once"] is True

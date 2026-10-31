# ruff: noqa: F811 - pytest fixture params shadow the landed cross-module fixture import.
"""Fake-engine proxy transport mutants (F1-F6) + untrusted-client fixture.

Design L371-387 (roster), L402-403 (mutants detected, not clean failures),
L426-427 (fault mutants demonstrate the predicate), L472-476 (terminal vs
death vs crash semantics). Reuses the landed TerminalEngine fault-flag seam
and its attempt()/container_attempt() drivers (tests/test_proxy_terminal.py);
adds two NEW transport-mutant flags (ck_rv_flip, post_start_crash) following
that pattern. Scripted fake oracle (Q3): fixture-supplied observations; no
Docker, no network. The single fake-engine cell stands in for
candidate-proxy in every scripted verdict feed below.
"""

import subprocess
from pathlib import Path

import pytest

from p11lab import proxy_policy
from p11lab.docker import CommandResult
from test_proxy_lifecycle import client  # noqa: F401
from test_proxy_terminal import TerminalEngine, attempt, container_attempt


ROSTER = (
    "PX-AUTH",
    "PX-STATE",
    "PX-REPLAY",
    "PX-CLIENT-CRASH",
    "PX-DAEMON-DEATH",
    "PX-DAEMON-STOP",
    "PX-LIMIT",
)


class MutantEngine(TerminalEngine):
    """TerminalEngine plus two transport-mutant fault flags (landed pattern).

    ck_rv_flip: the consumer lane emits a flipped CK_RV observation line
    for PX-STATE instead of clean output (T9 injector).
    post_start_crash: the first CLI readiness probe reports SERVING and the
    daemon is dead from then on (T10 injector; death after readiness).
    """

    CK_RV_FLIP_LINE = "PX-STATE candidate search: CK_RV=0x00000006 (expected CKR_OK)"

    def __init__(self, manifest, *, ck_rv_flip=False, post_start_crash=False, **kwargs):
        super().__init__(manifest, **kwargs)
        self.ck_rv_flip = ck_rv_flip
        self.post_start_crash = post_start_crash
        self.crash_injected = False

    def execute(self, identity, *args):
        if not self.argv[identity]:
            if (
                self.ck_rv_flip
                and not self.consumer_timeout
                and self.consumer_signal is None
            ):
                return CommandResult(0, self.CK_RV_FLIP_LINE, "")
        if (
            self.post_start_crash
            and not self.crash_injected
            and self.argv[identity][:1] == ("cli",)
        ):
            self.crash_injected = True
            self.dead = True
            return CommandResult(0, "SERVING", "")
        return super().execute(identity, *args)


def clean_cells(**overrides):
    cells = {
        "direct": {
            "admitted": True,
            "complete": True,
            "attribution_usable": True,
            "findings": [],
        },
        "accepted-proxy": {
            "admitted": True,
            "complete": True,
            "terminal_evidence_complete": True,
        },
        "candidate-proxy": {
            "admitted": True,
            "complete": True,
            "terminal_evidence_complete": True,
        },
        "comparison": {"performed": True, "positive": True, "coverage_positive": True},
        "cancelled": False,
        "uploads_complete": True,
        "infrastructure_error": None,
    }
    aliases = {"accepted_proxy": "accepted-proxy", "candidate_proxy": "candidate-proxy"}
    for key, value in overrides.items():
        key = aliases.get(key, key)
        if isinstance(value, dict):
            cells[key].update(value)
        else:
            cells[key] = value
    return cells


def scripted_controls(engine, accepted_fail=()):
    """Q3 scripted fake oracle: engine fault flags become the candidate
    PX-STATE observation (stand-in control; the detection signal is the
    flipped CK_RV / unexpected_death fact, per T9/T10)."""
    controls = {}
    flipped = bool(
        getattr(engine, "ck_rv_flip", False) or getattr(engine, "crash_injected", False)
    )
    for control in ROSTER:
        candidate = "fail" if control == "PX-STATE" and flipped else "pass"
        controls[control] = {
            "accepted-proxy": "fail" if control in accepted_fail else "pass",
            "candidate-proxy": candidate,
        }
    return controls


def clean_budgets(within=True):
    return {"within_budget": within}


def test_f1_injected_ck_rv_mismatch_detected_via_transport(
    tmp_path, client, monkeypatch
):
    # T9 (design L402-403): mutant flips one control CK_RV on an otherwise
    # clean cell; verdict false via T.
    engine = MutantEngine(client.manifest, ck_rv_flip=True)
    outcome, receipt, evidence = container_attempt(
        tmp_path, client, monkeypatch, engine
    )
    assert outcome.exit_code == 0, "clean cell: mutant visible only via T"
    assert evidence["unexpected_death"] is False
    log = (outcome.receipt_path.parent / "application.stdout.log").read_text()
    assert MutantEngine.CK_RV_FLIP_LINE in log
    controls = scripted_controls(engine)
    assert controls["PX-STATE"]["candidate-proxy"] == "fail"
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), controls, clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": True,
        "typed_cause": "completed-negative",
    }
    axes = proxy_policy.proxy_axes_for(clean_cells(), controls, clean_budgets())
    assert axes["transport_controls_positive"] is False


def test_f2_injected_post_start_crash_detected_via_unexpected_death(
    tmp_path, client, monkeypatch
):
    # T10 (design L402-403 + L472-474): mutant kills the daemon after ready;
    # detected via unexpected_death + lifecycle fact (landed signal
    # run.py:876-878), verdict false with complete evidence.
    engine = MutantEngine(client.manifest, post_start_crash=True)
    result, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine)
    assert engine.crash_injected is True
    assert result.exit_code == 1
    assert receipt["app_returncode"] == 0
    assert evidence["unexpected_death"] is True
    assert evidence["stop_requested"] is False
    assert "daemon exited after readiness" in result.lifecycle_errors
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), scripted_controls(engine), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": True,
        "typed_cause": "completed-negative",
    }


def test_f3_clean_control_through_fake_engine_is_positive(
    tmp_path, client, monkeypatch
):
    # T1 (design L415): clean cell + all contracts met stays positive.
    engine = TerminalEngine(client.manifest)
    result, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine)
    assert result.exit_code == 0 and not result.lifecycle_errors
    assert evidence["unexpected_death"] is False
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), scripted_controls(engine), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": True,
        "exit_code": 0,
        "evidence_complete": True,
        "typed_cause": None,
    }


def test_f4_lost_log_mutant_is_incomplete_with_app_code_preserved(
    tmp_path, client, monkeypatch
):
    # T5 (design L472-473): lost terminal log; app code preserved
    # (landed precedent test_proxy_terminal.py:154-163).
    engine = TerminalEngine(client.manifest, logs_error=True)
    result, receipt, evidence = attempt(
        tmp_path, client, monkeypatch, engine, app_status=23
    )
    assert result.exit_code == 23 and receipt["app_returncode"] == 23
    assert evidence["logs"]["available"] is False
    cells = clean_cells(candidate_proxy={"terminal_evidence_complete": False})
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, scripted_controls(engine), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "terminal-evidence-unavailable",
    }


@pytest.mark.parametrize("candidate", ["pass", "fail"])
def test_f5_accepted_control_failure_is_unqualified_whatever_candidate_does(
    tmp_path, client, monkeypatch, candidate
):
    # T4 (design L399-400): accepted-control-fails is control-unqualified
    # regardless of the candidate outcome.
    engine = TerminalEngine(client.manifest)
    result, _, _ = attempt(tmp_path, client, monkeypatch, engine)
    assert result.exit_code == 0
    controls = scripted_controls(engine, accepted_fail=("PX-AUTH",))
    if candidate == "fail":
        controls["PX-AUTH"]["candidate-proxy"] = "fail"
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), controls, clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "control-unqualified",
    }


def test_f6_direct_cell_absent_is_attribution_unknown(tmp_path, client, monkeypatch):
    # T3 (design L467): direct-cell-absent mutant.
    engine = TerminalEngine(client.manifest)
    result, _, _ = attempt(tmp_path, client, monkeypatch, engine)
    assert result.exit_code == 0
    cells = clean_cells(
        direct={"admitted": False, "complete": False, "attribution_usable": False}
    )
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, scripted_controls(engine), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "attribution-unknown",
    }


def test_untrusted_client_fixture_is_committed_offline_material():
    # Q4: ONE offline-generated untrusted client cert, committed bytes at
    # tests/fixtures/proxy-tls/untrusted-client.pem (new dir; no TLS
    # fixture precedent). Self-signed, so no fresh evaluation CA trusts it.
    fixture = (
        Path(__file__).resolve().parent
        / "fixtures"
        / "proxy-tls"
        / "untrusted-client.pem"
    )
    assert fixture.is_file(), "Q4 fixture must be committed, never generated per-run"
    text = fixture.read_text()
    assert text.count("-----BEGIN CERTIFICATE-----") == 1
    assert text.count("-----END CERTIFICATE-----") == 1
    details = subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(fixture),
            "-noout",
            "-subject",
            "-issuer",
            "-ext",
            "extendedKeyUsage",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "p11lab-untrusted-client" in details
    assert "TLS Web Client Authentication" in details
    subject = next(line for line in details.splitlines() if line.startswith("subject="))
    issuer = next(line for line in details.splitlines() if line.startswith("issuer="))
    assert (
        subject.replace("subject=", "").strip() == issuer.replace("issuer=", "").strip()
    )
    subprocess.run(
        ["openssl", "x509", "-in", str(fixture), "-noout", "-checkend", "0"],
        capture_output=True,
        text=True,
        check=True,
    )

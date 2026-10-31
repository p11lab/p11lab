"""Gated caller-template + evidence-input surface contract (B-G2c).

Pins the successor template `examples/application-ci/action-gated.yml`
(copy-out idiom, gated contract difference, honest placeholders), the
three evidence inputs on `action.yml` and their forwarding into the
wrapper, and the byte-identity of the legacy template. Static checks
only: no network, no Docker, no GitHub.
"""
import hashlib
import importlib.util
import re
from pathlib import Path

import pytest

from p11lab import publish

ROOT = Path(__file__).resolve().parent.parent
LEGACY = ROOT / "examples/application-ci/action.yml"
GATED = ROOT / "examples/application-ci/action-gated.yml"
LEGACY_SHA256 = "0ae4d1a25d179c08a24de04985ab0a2457916a80ca2d340a7ad3e8b8a4727476"

EVIDENCE_INPUTS = ("transport-evidence-digest", "promotion-evidence-digest", "evidence-registry")


def _action_run_module():
    path = ROOT / "src/p11lab/data/delivery/action-run.py"
    spec = importlib.util.spec_from_file_location("action_run_gated_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_gated_template_states_contract_difference():
    text = GATED.read_text()
    assert "GATED" in text
    assert "examples/application-ci/action.yml" in text
    assert "copy to the caller's .github/workflows/" in text
    assert "intentionally incomplete" in text


def test_gated_template_placeholders_stay_honest():
    gated = GATED.read_text()
    legacy = LEGACY.read_text()
    for placeholder in ("REQUIRED_PUBLISHED_ACTION_COMMIT",
                        "REQUIRED_ELIGIBLE_HANDOFF_MANIFEST_SHA256"):
        assert placeholder in legacy and placeholder in gated
    for placeholder in ("REQUIRED_TRANSPORT_EVIDENCE_MANIFEST_SHA256",
                        "REQUIRED_PROMOTION_EVIDENCE_MANIFEST_SHA256"):
        assert placeholder in gated
        assert placeholder not in legacy
    assert "transport-evidence-digest: sha256:REQUIRED_TRANSPORT_EVIDENCE_MANIFEST_SHA256" in gated
    assert "promotion-evidence-digest: sha256:REQUIRED_PROMOTION_EVIDENCE_MANIFEST_SHA256" in gated
    assert "evidence-registry" not in gated


def test_gated_template_is_valid_caller_workflow():
    from test_external_ci_contract import _loads
    text = GATED.read_text()
    for old, new in (("REQUIRED_PUBLISHED_ACTION_COMMIT", "d" * 40),
                     ("REQUIRED_ELIGIBLE_HANDOFF_MANIFEST_SHA256", "e" * 64),
                     ("REQUIRED_TRANSPORT_EVIDENCE_MANIFEST_SHA256", "f" * 64),
                     ("REQUIRED_PROMOTION_EVIDENCE_MANIFEST_SHA256", "1" * 64)):
        assert old in text
        text = text.replace(old, new)
    doc = _loads(text)
    assert doc["jobs"]["application"]["runs-on"] == "ubuntu-24.04"
    steps = doc["jobs"]["application"]["steps"]
    provider = next(step for step in steps if step.get("id") == "provider")
    match = re.fullmatch(r"p11lab/p11lab@([0-9a-f]{40})", provider["uses"])
    assert match
    assert match.group(1) == "d" * 40
    with_block = provider["with"]
    assert with_block["environment"] == "softhsm2" and with_block["channel"] == "release"
    for key, digest in (("handoff-digest", "e" * 64),
                        ("transport-evidence-digest", "f" * 64),
                        ("promotion-evidence-digest", "1" * 64)):
        match = re.fullmatch(r"sha256:([0-9a-f]{64})", with_block[key])
        assert match
        assert match.group(1) == digest


def test_legacy_template_byte_identical():
    assert hashlib.sha256(LEGACY.read_bytes()).hexdigest() == LEGACY_SHA256


def test_action_yml_evidence_inputs_match_canonical_spec():
    parsed = publish.action_inputs_from_yml((ROOT / "action.yml").read_text())
    for name in EVIDENCE_INPUTS:
        assert parsed[name].get("required", False) is False
        assert parsed[name].get("default", "") == ""
        assert parsed[name]["description"].strip()
        assert publish.ACTION_INPUTS[name].get("required", False) is False
        assert publish.ACTION_INPUTS[name].get("default", "") == ""


def test_action_yml_forwards_evidence_inputs_to_wrapper():
    text = (ROOT / "action.yml").read_text()
    for env, flag in (("P11LAB_ACTION_TRANSPORT_EVIDENCE_DIGEST", "--transport-evidence-digest"),
                      ("P11LAB_ACTION_PROMOTION_EVIDENCE_DIGEST", "--promotion-evidence-digest"),
                      ("P11LAB_ACTION_EVIDENCE_REGISTRY", "--evidence-registry")):
        name = env.replace("P11LAB_ACTION_", "").replace("_", "-").lower()
        assert f"{env}: ${{{{ inputs.{name} }}}}" in text
        assert (flag + ' "$' + env + '"') in text


def test_wrapper_accepts_evidence_flags(tmp_path):
    module = _action_run_module()
    argv = ["--environment", "softhsm2", "--channel", "release", "--mode", "direct",
           "--registry", "127.0.0.1:5050/p11lab", "--handoff-digest", "sha256:" + "ab" * 32,
           "--command", "invalid JSON", "--timeout", "10",
           "--workspace", str(tmp_path), "--working-directory", ".",
           "--oras", "oras", "--run-dir", str(tmp_path / "attempt"),
           "--transport-evidence-digest", "sha256:" + "11" * 32,
           "--promotion-evidence-digest", "sha256:" + "22" * 32,
           "--evidence-registry", ""]
    assert module.main(argv) == 2


def test_evidence_inputs_validate_and_default():
    base = {"environment": "softhsm2", "channel": "release",
            "handoff-digest": "sha256:" + "ef" * 32, "command": '["app"]'}
    normalized = publish.validate_action_inputs(base)
    assert normalized["transport-evidence-digest"] == ""
    assert normalized["promotion-evidence-digest"] == ""
    assert normalized["evidence_registry"] == normalized["registry"] == "ghcr.io/p11lab/softhsm2"
    explicit = publish.validate_action_inputs(base | {"evidence-registry": "127.0.0.1:5050/p11lab-evidence"})
    assert explicit["evidence_registry"] == "127.0.0.1:5050/p11lab-evidence"
    with pytest.raises(ValueError, match="transport-evidence-digest must be sha256"):
        publish.validate_action_inputs(base | {"transport-evidence-digest": "latest"})
    with pytest.raises(ValueError, match="promotion-evidence-digest must be sha256"):
        publish.validate_action_inputs(base | {"promotion-evidence-digest": "sha256:xyz"})
    with pytest.raises(ValueError, match="evidence-registry must be a repository path"):
        publish.validate_action_inputs(base | {"evidence-registry": "not a repo!!"})

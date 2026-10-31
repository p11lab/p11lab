"""`p11lab round prepare` CLI pins; fixture transport only, no network."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
POLICY_ROOT = FIXTURES / "policy"


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env.pop("CI", None)
    env.pop("GITHUB_ACTIONS", None)
    return env


def _run(context, output_dir, output_json, cwd):
    return subprocess.run(
        [sys.executable, "-m", "p11lab", "round", "prepare",
         "--context", str(context), "--policy-root", str(POLICY_ROOT),
         "--output-dir", str(output_dir), "--output-json", str(output_json)],
        capture_output=True, text=True, env=_env(), cwd=cwd)


def _write_context(directory, name, mutation=None):
    context = json.loads((FIXTURES / "valid-context.json").read_bytes())
    if mutation is not None:
        mutation(context)
    path = directory / name
    path.write_text(json.dumps(context))
    return path


def test_prepare_cli_minimal_valid_context(tmp_path):
    output_dir = tmp_path / "output"
    output_json = tmp_path / "result.json"
    completed = _run(FIXTURES / "valid-context.json", output_dir, output_json, tmp_path)
    assert completed.returncode == 0, completed.stderr
    record = json.loads(output_json.read_text())
    assert record["authority"] == "local-fixture-non-authoritative"
    assert record["round_positive"] is False
    assert (output_dir / "dist.zip").is_file()
    assert (output_dir / "data" / "corpus.bin").is_file()
    assert (output_dir / "round-inputs.json").is_file()


def test_prepare_cli_empty_string_field_rejected(tmp_path):
    context = _write_context(tmp_path, "context.json", lambda c: c.update(data_root=""))
    completed = _run(context, tmp_path / "output", tmp_path / "result.json", tmp_path)
    assert completed.returncode == 2
    assert "invalid preparation context" in completed.stderr


def test_prepare_cli_non_string_field_rejected(tmp_path):
    context = _write_context(tmp_path, "context.json", lambda c: c.update(cache_file=5))
    completed = _run(context, tmp_path / "output", tmp_path / "result.json", tmp_path)
    assert completed.returncode == 2
    assert "invalid preparation context" in completed.stderr


def test_prepare_cli_relative_artifact_resolves_against_context_parent(tmp_path):
    ctxdir = tmp_path / "ctx"
    ctxdir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for name in ("fixture-dist.zip", "fixture-metadata.json"):
        shutil.copyfile(FIXTURES / name, ctxdir / name)
    shutil.copytree(FIXTURES / "input-data", ctxdir / "input-data")
    context = _write_context(ctxdir, "context.json")
    output_dir = tmp_path / "output"
    output_json = tmp_path / "result.json"
    completed = _run(context, output_dir, output_json, elsewhere)
    assert completed.returncode == 0, completed.stderr
    expected = str(context.parent / "fixture-dist.zip")
    assert not (elsewhere / "fixture-dist.zip").exists()
    assert (output_dir / "dist.zip").read_bytes() == Path(expected).read_bytes()
    assert json.loads(output_json.read_text())["dist"]["archive_sha256"] == hashlib.sha256(
        Path(expected).read_bytes()).hexdigest()

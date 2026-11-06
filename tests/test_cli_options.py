"""CLI surface batch (review H2, M7-cli, L9, L10, A7)."""
import pytest

from p11lab.cli import main


def test_expose_maps_blocked_verdict_to_exit_3(tmp_path, monkeypatch, capsys):
    import p11lab.publish as delivery

    monkeypatch.setattr(delivery, "expose",
                        lambda **kwargs: {"handoff": "h", "reference": "r", "status": "blocked"})
    code = main(["publish", "expose", "--admission", str(tmp_path / "a.json"),
                 "--pushed-digest", "a" * 64, "--pushed-tag", "t", "--pushed-size", "7",
                 "--registry", "example/x", "--output-dir", str(tmp_path)])
    assert code == 3
    assert '"blocked"' in capsys.readouterr().out


def test_expose_maps_eligible_verdict_to_exit_0(tmp_path, monkeypatch, capsys):
    import p11lab.publish as delivery

    monkeypatch.setattr(delivery, "expose",
                        lambda **kwargs: {"handoff": "h", "reference": "r", "status": "eligible"})
    code = main(["publish", "expose", "--admission", str(tmp_path / "a.json"),
                 "--pushed-digest", "a" * 64, "--pushed-tag", "t", "--pushed-size", "7",
                 "--registry", "example/x", "--output-dir", str(tmp_path)])
    assert code == 0


@pytest.mark.parametrize("argv", [
    ["install", "softhsm2", "--channel", "release", "--artifact", "a",
     "--sha256", "b" * 64, "--platform", "plan9/amd64", "--prefix", "p"],
    ["run", "softhsm2", "--channel", "release", "--artifact", "sha256:" + "c" * 64,
     "--platform", "x/y", "--output-dir", "o", "--", "true"],
])
def test_platform_choices_reject_unknown_values(argv, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as status:
        main(argv)
    assert status.value.code == 2


def test_role_choices_echo_bad_value(tmp_path, capsys):
    with pytest.raises(SystemExit) as status:
        main(["build", "softhsm2", "--channel", "release", "--role", "runtim",
              "--output-dir", str(tmp_path / "o")])
    assert status.value.code == 2
    assert "runtim" in capsys.readouterr().err


@pytest.mark.parametrize("timeout", ["0", "-5", "86401", "999999999"])
def test_timeout_bounds_rejected_early(tmp_path, capsys, timeout):
    code = main(["run", "softhsm2", "--channel", "release",
                 "--artifact", "sha256:" + "c" * 64,
                 "--output-dir", str(tmp_path / "o"), "--timeout", timeout,
                 "--", "true"])
    assert code == 2
    assert "--timeout must be 1..86400 seconds" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()


@pytest.mark.parametrize("timeout", ["1", "300", "86400"])
def test_timeout_bounds_accepted(tmp_path, monkeypatch, timeout):
    from p11lab import run as run_module
    from p11lab.models import RunResult

    seen = []
    monkeypatch.setattr(run_module, "run_application",
                        lambda spec: seen.append(spec) or RunResult(0, (), (), 0, tmp_path / "r"))
    code = main(["run", "softhsm2", "--channel", "release",
                 "--artifact", "sha256:" + "c" * 64,
                 "--output-dir", str(tmp_path / "o"), "--timeout", timeout,
                 "--", "true"])
    assert code == 0
    assert seen[0].timeout_seconds == int(timeout)


def test_publish_rejects_misrouted_flag(tmp_path, capsys):
    code = main(["publish", "seal-sources", "softhsm2", "--channel", "release",
                 "--resolved-dir", str(tmp_path), "--output-dir", str(tmp_path / "o"),
                 "--target", "debian13-amd64"])
    assert code == 2
    assert "--target is not a publish seal-sources option" in capsys.readouterr().err


def test_publish_rejects_misrouted_equals_flag(tmp_path, capsys):
    code = main(["publish", "show-handoff", "--handoff", str(tmp_path / "h.json"),
                 "--registry=example/x"])
    assert code == 2
    assert "--registry is not a publish show-handoff option" in capsys.readouterr().err


def test_publish_accepts_allowed_flags(tmp_path, capsys):
    # Allowed flags pass the A7 gate; the call then fails later in target
    # loading (proving the gate, not the operation, was satisfied).
    code = main(["publish", "seal-native", "nethsm", "--channel", "release",
                 "--target", "debian13-amd64", "--output-dir", str(tmp_path / "o")])
    assert code == 2
    assert "not a publish" not in capsys.readouterr().err


def test_gather_review_rejects_artifact_and_policy(tmp_path, capsys):
    code = main(["image", "gather-review", "--environment", "softhsm2", "--channel", "release",
                 "--artifact", "a.json", "--output-dir", str(tmp_path / "o")])
    assert code == 2
    assert "does not accept artifact or policy" in capsys.readouterr().err


def test_gather_review_requires_environment_and_channel(tmp_path, capsys):
    code = main(["image", "gather-review", "--environment", "softhsm2",
                 "--output-dir", str(tmp_path / "o")])
    assert code == 2
    assert "requires environment and channel" in capsys.readouterr().err


def test_gather_review_dispatches_with_packaged_lock(tmp_path, monkeypatch, capsys):
    import p11lab.review_inputs as gather

    seen = {}

    def stub(lock, output_dir, **kwargs):
        seen["lock_keys"] = sorted(lock)
        seen["output_dir"] = str(output_dir)
        return {"status": "complete"}

    monkeypatch.setattr(gather, "gather_review_inputs", stub)
    code = main(["image", "gather-review", "--environment", "softhsm2", "--channel", "release",
                 "--output-dir", str(tmp_path / "o")])
    assert code == 0
    assert "source_packages" in seen["lock_keys"] and "packages" in seen["lock_keys"]
    assert seen["output_dir"] == str(tmp_path / "o")
    assert '"complete"' in capsys.readouterr().out


def test_gather_review_passes_cache_dir(tmp_path, monkeypatch, capsys):
    import p11lab.review_inputs as gather

    seen = {}

    def stub(lock, output_dir, **kwargs):
        seen.update(kwargs)
        return {"status": "complete"}

    monkeypatch.setattr(gather, "gather_review_inputs", stub)
    code = main(["image", "gather-review", "--environment", "softhsm2", "--channel", "release",
                 "--output-dir", str(tmp_path / "o"), "--cache-dir", str(tmp_path / "c")])
    assert code == 0
    assert seen["cache_dir"] == tmp_path / "c"


def test_gather_review_cache_dir_defaults_to_none(tmp_path, monkeypatch, capsys):
    import p11lab.review_inputs as gather

    seen = {}

    def stub(lock, output_dir, **kwargs):
        seen.update(kwargs)
        return {"status": "complete"}

    monkeypatch.setattr(gather, "gather_review_inputs", stub)
    code = main(["image", "gather-review", "--environment", "softhsm2", "--channel", "release",
                 "--output-dir", str(tmp_path / "o")])
    assert code == 0
    assert seen["cache_dir"] is None


def test_image_other_operations_reject_cache_dir(tmp_path, capsys):
    code = main(["image", "prepare-tools", "--output-dir", str(tmp_path / "o"),
                 "--cache-dir", str(tmp_path / "c")])
    assert code == 2
    assert "does not accept cache-dir" in capsys.readouterr().err
    code = main(["image", "validate-local", "--artifact", "a.json", "--policy", "p.json",
                 "--output-dir", str(tmp_path / "o"), "--cache-dir", str(tmp_path / "c")])
    assert code == 2
    assert "does not accept cache-dir" in capsys.readouterr().err

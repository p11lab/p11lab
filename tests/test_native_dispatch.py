"""Per-target native dispatch + CLI proxy client bundle (review A1/M4/A2).

run/install route by environment through native.NATIVE_LIFECYCLES instead of
the SoftHSM-hardcoded path; proxy CLI builds a bundle-kind client artifact.
"""
import hashlib
import io
import json
import tarfile

import pytest

from p11lab.bundle import install_bundle
from p11lab.models import ArtifactRef, RunResult, RunSpec


def install_fixture_bouncyhsm(root):
    from p11lab.native import load_bouncyhsm_target

    lock = load_bouncyhsm_target("bouncyhsm", "release", "debian13-amd64")["native_lock"]
    files = {
        lock["module"]: b"fixture module",
        lock["lifecycle"]["probe"]: b"fixture probe",
        lock["lifecycle"]["server"]: b"fixture server",
    }
    manifest = {
        "schema_version": 1, "environment": "bouncyhsm", "channel": "release",
        "platform": "linux/amd64", "target": "debian13-amd64", "role": "native-runtime",
        "module": lock["module"], "lifecycle": lock["lifecycle"],
        "source": {"revision": lock["source"]["revision"]}, "toolchain": lock["toolchain"],
        "build": {"key": "fixture"}, "host_requirements": lock["host_requirements"],
        "tested_prerequisites": lock["tested_prerequisites"], "licenses": [],
        "source_references": [],
        "files": [{"path": p, "sha256": hashlib.sha256(d).hexdigest(), "size": len(d),
                   "mode": 0o755 if p.startswith("bin/") else 0o644, "role": "fixture"}
                  for p, d in files.items()],
    }
    archive = root / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as out:
        for name, data, mode in [("manifest.json", json.dumps(manifest).encode(), 0o644),
                                 *[("payload/" + r["path"], files[r["path"]], r["mode"])
                                   for r in manifest["files"]]]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = mode
            out.addfile(member, io.BytesIO(data))
    artifact = ArtifactRef("bundle", str(archive),
                           hashlib.sha256(archive.read_bytes()).hexdigest(), "linux/amd64")
    return install_bundle(artifact, root / "prefix", environment="bouncyhsm",
                          channel="release", platform="linux/amd64")


def test_native_lifecycle_table_shape():
    from p11lab import native

    assert set(native.NATIVE_LIFECYCLES) == {"softhsm2", "bouncyhsm"}
    assert set(native.NATIVE_CONFIGURATION) == set(native.NATIVE_LIFECYCLES)
    install, preflight, run = native.native_lifecycle("softhsm2")
    assert (install, preflight, run) == (native.install_native_bundle,
                                         native.preflight_native, native.run_native_softhsm)
    install, preflight, run = native.native_lifecycle("bouncyhsm")
    assert (install, preflight, run) == (native.install_bouncyhsm_bundle,
                                         native.preflight_bouncyhsm, native.run_native_bouncyhsm)
    with pytest.raises(ValueError, match="not packaged for environment"):
        native.native_lifecycle("nethsm")


def test_run_application_dispatches_bouncyhsm_native(tmp_path):
    from p11lab.run import run_application

    installed = install_fixture_bouncyhsm(tmp_path)
    spec = RunSpec("bouncyhsm", "release", "native", installed.artifact, "host",
                   None, None, ("true",), {"P11LAB_HTTP_PORT": "http"},
                   tmp_path / "out", tmp_path, 30, installed_prefix=installed.prefix)
    # BouncyHSM-specific validation proves the bouncyhsm lifecycle ran; the
    # pre-fix code misrouted into the SoftHSM catalogue loader instead.
    with pytest.raises(ValueError, match="P11LAB_HTTP_PORT must be a TCP port number"):
        run_application(spec)
    assert not spec.output_dir.exists()


def test_run_application_refuses_unpackaged_native_environment(tmp_path):
    from p11lab.run import run_application

    spec = RunSpec("nethsm", "release", "native",
                   ArtifactRef("bundle", "/nope", "a" * 64, "linux/amd64"), "host",
                   None, None, ("true",), {}, tmp_path / "out", tmp_path, 30)
    with pytest.raises(ValueError, match="not packaged for environment"):
        run_application(spec)
    assert not spec.output_dir.exists()


def test_cli_install_dispatches_lifecycle_and_reports_manifest_module(tmp_path, monkeypatch, capsys):
    from p11lab import native
    from p11lab.bundle import InstalledBundle
    from p11lab.cli import main

    seen = {}

    def fake_install(artifact, prefix, *, environment, channel):
        seen.update(artifact=artifact, prefix=prefix, environment=environment, channel=channel)
        return InstalledBundle(artifact, prefix, {"module": "lib/libBouncyHsm.Pkcs11.so"},
                               "a" * 64, prefix / ".p11lab-install.json", "b" * 64)

    monkeypatch.setattr(native, "native_lifecycle",
                        lambda environment: (fake_install, None, None) if environment == "bouncyhsm"
                        else (_ for _ in ()).throw(AssertionError("wrong environment")))
    archive = tmp_path / "client.tar.gz"
    archive.write_bytes(b"fixture")
    code = main(["install", "bouncyhsm", "--channel", "release", "--artifact", str(archive),
                 "--sha256", "c" * 64, "--platform", "linux/amd64",
                 "--prefix", str(tmp_path / "prefix")])
    assert code == 0
    assert seen["environment"] == "bouncyhsm" and seen["channel"] == "release"
    assert seen["artifact"].kind == "bundle" and seen["artifact"].sha256 == "c" * 64
    report = json.loads(capsys.readouterr().out)
    assert report["module"].endswith("payload/lib/libBouncyHsm.Pkcs11.so")
    assert report["configuration"] == native.NATIVE_CONFIGURATION["bouncyhsm"]


def test_cli_install_refuses_unpackaged_native_environment(tmp_path, capsys):
    from p11lab.cli import main

    code = main(["install", "nethsm", "--channel", "release", "--artifact", str(tmp_path),
                 "--sha256", "c" * 64, "--platform", "linux/amd64",
                 "--prefix", str(tmp_path / "prefix")])
    assert code == 2
    assert "not packaged for environment" in capsys.readouterr().err


IMAGE = "sha256:" + "d" * 64


def test_cli_proxy_builds_bundle_client_artifact(tmp_path, monkeypatch):
    from p11lab import run as run_module
    from p11lab.cli import main

    seen = []

    def application(spec):
        seen.append(spec)
        return RunResult(7, (), (), 7, tmp_path / "receipt.json")

    monkeypatch.setattr(run_module, "run_application", application)
    bundle = tmp_path / "client.tar.gz"
    bundle.write_bytes(b"fixture")
    code = main(["run", "softhsm2", "--channel", "release", "--mode", "proxy",
                 "--artifact", IMAGE, "--client-artifact", str(bundle),
                 "--client-sha256", "e" * 64, "--output-dir", str(tmp_path / "out"),
                 "--", "true"])
    assert code == 7
    client = seen[0].client_artifact
    assert client.kind == "bundle"
    assert client.reference == str(bundle.resolve())
    assert client.sha256 == "e" * 64 and client.platform == "linux/amd64"
    assert seen[0].execution_location == "host"


def test_cli_proxy_client_requires_sha256(tmp_path, capsys):
    from p11lab.cli import main

    code = main(["run", "softhsm2", "--channel", "release", "--mode", "proxy",
                 "--artifact", IMAGE, "--client-artifact", str(tmp_path / "c.tar.gz"),
                 "--output-dir", str(tmp_path / "out"), "--", "true"])
    assert code == 2
    assert "--client-sha256" in capsys.readouterr().err


def test_cli_client_sha256_rejected_outside_proxy(tmp_path, capsys):
    from p11lab.cli import main

    code = main(["run", "softhsm2", "--channel", "release", "--mode", "direct",
                 "--artifact", IMAGE, "--client-sha256", "e" * 64,
                 "--output-dir", str(tmp_path / "out"), "--", "true"])
    assert code == 2
    assert "--client-sha256" in capsys.readouterr().err


@pytest.mark.parametrize("execution,extra", [
    ({"module": "/m/softhsm", "configuration": "/c/softhsm2.conf"}, {"configuration": "/c/softhsm2.conf"}),
    ({"module": "/m/bouncy", "server": "/s", "probe": "/p"}, {}),
])
def test_cli_native_record_tolerates_lifecycle_receipt_shape(tmp_path, monkeypatch, capsys, execution, extra):
    from p11lab import run as run_module
    from p11lab.cli import main

    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"execution": execution}))
    monkeypatch.setattr(run_module, "run_application",
                        lambda spec: RunResult(0, (), (), 0, receipt))
    code = main(["run", "softhsm2", "--channel", "release", "--mode", "native",
                 "--artifact", str(tmp_path / "a.tar.gz"), "--sha256", "f" * 64,
                 "--output-dir", str(tmp_path / "out"), "--", "true"])
    assert code == 0
    record = json.loads(capsys.readouterr().out)
    assert record["module"] == execution["module"]
    assert ("configuration" in record) == bool(extra)
    assert all(record[k] == v for k, v in extra.items())


def test_native_target_lock_must_roster_declared_module(monkeypatch):
    from p11lab import catalog
    from p11lab.catalog import CatalogError

    real_json = catalog._json

    def tampered(asset):
        data = real_json(asset)
        if asset.name.endswith(".lock.json"):
            data = dict(data, binaries=[{"path": "lib/other.so", "sha256": "a" * 64}])
        return data

    monkeypatch.setattr(catalog, "_json", tampered)
    with pytest.raises(CatalogError, match="invalid native target contract"):
        catalog.load_native_target("softhsm2", "release", "debian13-amd64")


def test_native_target_loader_still_refuses_bouncyhsm_status():
    # Distribution stays fail-closed: bouncyhsm declares native
    # not-packaged, so the seal/admit loader path keeps refusing it while
    # local install/run dispatch through the bouncyhsm lifecycle.
    from p11lab import catalog
    from p11lab.catalog import CatalogError

    with pytest.raises(CatalogError, match="not-packaged"):
        catalog.load_native_target("bouncyhsm", "release", "debian13-amd64")


def test_bouncyhsm_native_locks_match_per_channel_source_revisions():
    from p11lab import native
    from p11lab.native import load_bouncyhsm_target

    for channel, target in (("release", "windows-amd64"), ("release", "debian13-amd64"),
                            ("rolling", "windows-amd64"), ("rolling", "debian13-amd64")):
        lock = load_bouncyhsm_target("bouncyhsm", channel, target)["native_lock"]
        assert lock["source"]["revision"] == native.BOUNCY_SOURCE_REVISIONS[channel]


def test_bouncyhsm_native_loader_rejects_cross_channel_revision(tmp_path, monkeypatch):
    import json
    from p11lab import catalog, native
    from p11lab.catalog import CatalogError
    from p11lab.native import load_bouncyhsm_target

    real = catalog.packaged_asset

    def mutate(name, revision):
        lock = json.loads(real("bouncyhsm", name).read_bytes())
        lock["source"]["revision"] = revision
        mutated = tmp_path / name
        mutated.write_text(json.dumps(lock))
        monkeypatch.setattr(catalog, "packaged_asset",
                            lambda e, n: mutated if n == name else real(e, n))

    mutate("release.windows-amd64.lock.json", native.BOUNCY_SOURCE_REVISIONS["rolling"])
    with pytest.raises(CatalogError, match="source revision mismatch"):
        load_bouncyhsm_target("bouncyhsm", "release", "windows-amd64")
    monkeypatch.undo()
    mutate("rolling.debian13-amd64.lock.json", native.BOUNCY_SOURCE_REVISIONS["release"])
    with pytest.raises(CatalogError, match="source revision mismatch"):
        load_bouncyhsm_target("bouncyhsm", "rolling", "debian13-amd64")

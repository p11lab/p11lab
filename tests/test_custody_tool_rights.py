"""Custody tool source checks; synthetic records do not confer real rights."""

import copy
import hashlib
import os
from dataclasses import asdict

import pytest

from p11lab import licenses, sources
from test_publish import admission_inventory


@pytest.fixture
def evaluator():
    value = os.environ.get('P11LAB_CUSTODY_TEST_EVALUATOR')
    if not value:
        pytest.skip('requires task-owned sealed evaluator')
    return value


def _tree_fixture(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "demo.txt").write_bytes(b"demo")
    return root


def test_actual_tree_is_reinspected_by_existing_source_collector_and_assessor(tmp_path):
    root = _tree_fixture(tmp_path)
    sealed = licenses.observe_custody_tree(root, platform="linux/amd64")
    artifact, observation = sealed.artifact(), sealed.observation()
    assert artifact.kind == "custody-tree"
    assert observation["files"][0]["sha256"] == hashlib.sha256(b"demo").hexdigest()
    (tmp_path / "review").mkdir()
    _, inventory = admission_inventory(tmp_path / "review")
    inventory["artifact"] = asdict(artifact)
    inventory["observation"] = observation
    evidence = tmp_path / "source-evidence"
    sources.collect_source_bundle(artifact, inventory, evidence)
    assert licenses.assess_distribution(artifact, evidence)["status"] == "eligible"
    (root / "demo.txt").write_bytes(b"changed")
    assert licenses.assess_distribution(artifact, evidence)["status"] == "blocked"


def test_tree_identity_tracks_links_modes_roster_and_is_root_independent(tmp_path):
    root = _tree_fixture(tmp_path)
    (root / "alias").symlink_to("demo.txt")
    first = licenses.observe_custody_tree(root, platform="linux/amd64")
    other = tmp_path / "other"
    other.mkdir()
    (other / "demo.txt").write_bytes(b"demo")
    (other / "alias").symlink_to("demo.txt")
    second = licenses.observe_custody_tree(other, platform="linux/amd64")
    assert first.artifact().sha256 == second.artifact().sha256
    (other / "demo.txt").chmod(0o700)
    assert licenses.observe_custody_tree(other, platform="linux/amd64").artifact().sha256 != first.artifact().sha256
    (other / "demo.txt").chmod(0o644)
    (other / "alias").unlink()
    (other / "alias").symlink_to("missing")
    assert licenses.observe_custody_tree(other, platform="linux/amd64").artifact().sha256 != first.artifact().sha256


def test_tree_inspection_rejects_foreign_identity_and_unsafe_file_types(tmp_path):
    from p11lab.models import ArtifactRef

    root = _tree_fixture(tmp_path)
    sealed = licenses.observe_custody_tree(root, platform="linux/amd64")
    actual = sealed.artifact()
    with pytest.raises(ValueError, match="identity"):
        licenses.inspect_artifact(ArtifactRef(actual.kind, actual.reference, "0" * 64, actual.platform))
    os.mkfifo(root / "fifo")
    with pytest.raises(ValueError, match="type"):
        licenses.observe_custody_tree(root, platform="linux/amd64")


def test_tree_source_rights_refuse_unreviewed_or_changed_grants(tmp_path):
    root = _tree_fixture(tmp_path)
    sealed = licenses.observe_custody_tree(root, platform="linux/amd64")
    artifact = sealed.artifact()
    (tmp_path / "review").mkdir()
    _, inventory = admission_inventory(tmp_path / "review")
    inventory["artifact"] = asdict(artifact)
    inventory["observation"] = sealed.observation()
    changed = copy.deepcopy(inventory)
    changed["reviews"][0]["grant_known"] = False
    with pytest.raises(ValueError, match="unreviewed"):
        sources.collect_source_bundle(artifact, changed, tmp_path / "no-grant")
    changed = copy.deepcopy(inventory)
    changed["content_reviews"] = []
    with pytest.raises(ValueError, match="unreviewed"):
        sources.collect_source_bundle(artifact, changed, tmp_path / "no-content-review")


def _contiguous_split_elf(name=b"libx.so"):
    import struct

    data = bytearray(0x700)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<QQ", data, 32, 64, 0x400)
    struct.pack_into("<HHHHH", data, 54, 56, 3, 64, 4, 1)
    for index, ph in enumerate([
        (1, 4, 0, 0x10000, 0, 0x200, 0x200, 0x1000),
        (1, 4, 0x200, 0x10200, 0, 0x200, 0x200, 0x1000),
        (2, 4, 0x120, 0x10120, 0, 64, 64, 8),
    ]):
        struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, *ph)
    strings = name + b"\0" + b"\0" * 8
    for index, item in enumerate([(1, 0), (5, 0x101F8), (10, len(strings)), (0, 0)]):
        struct.pack_into("<QQ", data, 0x120 + index * 16, *item)
    data[0x1F8:0x1F8 + len(strings)] = strings
    names = b"\0.shstrtab\0.dynstr\0.dynamic\0"
    data[0x500:0x500 + len(names)] = names
    data[0x600:0x600 + len(strings)] = strings
    struct.pack_into("<IIQQQQIIQQ", data, 0x440, 1, 3, 0, 0, 0x500, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x480, 11, 3, 0, 0x101F8, 0x600, len(strings), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x4C0, 19, 6, 0, 0x10120, 0x120, 64, 0, 0, 8, 16)
    return data


def test_elf_split_load_string_table_requires_unambiguous_identical_bytes():
    import struct

    valid = _contiguous_split_elf()
    assert licenses._needed(valid) == ["libx.so"]
    changed_section = bytearray(valid)
    changed_section[0x600] ^= 1
    with pytest.raises(ValueError):
        licenses._needed(changed_section)
    for second_address in (0x101FF, 0x10201):
        damaged = bytearray(valid)
        struct.pack_into("<Q", damaged, 64 + 56 + 16, second_address)
        with pytest.raises(ValueError):
            licenses._needed(damaged)


def test_tree_origin_dependency_is_explicit_and_root_confined(tmp_path):
    name = b"$ORIGIN/../lib/libthing.so"
    elf = _contiguous_split_elf(name)
    with pytest.raises(ValueError, match="unsupported dependency"):
        licenses._needed(elf)
    assert licenses._needed(elf, allow_origin=True) == [name.decode()]
    root = tmp_path / "tree"
    (root / "bin").mkdir(parents=True)
    (root / "bin/program").write_bytes(_contiguous_split_elf(b"$ORIGIN/../../escape.so"))
    with pytest.raises(ValueError, match="escapes custody tree"):
        licenses.observe_custody_tree(root, platform="linux/amd64")


def _configured_tree_policy(tmp_path, monkeypatch):
    from p11lab import delivery_authority, image_custody

    root = _tree_fixture(tmp_path)
    sealed = licenses.observe_custody_tree(root, platform="linux/amd64")
    (tmp_path / "review").mkdir()
    _, inventory = admission_inventory(tmp_path / "review")
    inventory["artifact"] = None
    inventory["observation"] = None
    inventory["build_key"] = None
    expected = sealed.observation()
    expected.pop("artifact")
    template = {"name": "checker-root", "kind": "custody-tree", "inventory": inventory,
                "expected": expected}
    policy = {"schema_version": 1, "components": [template]}
    monkeypatch.setattr(image_custody, "_installed_custody_policy", lambda: copy.deepcopy(policy))
    monkeypatch.setattr(delivery_authority, "load_profile", lambda *args, **kwargs: {"fixture": True})
    monkeypatch.setattr(delivery_authority, "_check_local_controller", lambda profile: None)
    return root, sealed, policy


def test_protected_template_materializes_actual_tree_and_reuses_source_checks(tmp_path, monkeypatch):
    from p11lab import image_custody

    _, sealed, _ = _configured_tree_policy(tmp_path, monkeypatch)
    result = image_custody.materialize_custody_component(
        "checker-root", sealed.artifact(), output_dir=tmp_path / "result"
    )
    assert result["status"] == "eligible-local-content"
    assert result["source_first_status"] == "not-yet-read-back"
    assert result["image_promotion_status"] == "blocked"
    assert (tmp_path / "result/evidence/source-companion.tar.gz").is_file()


def test_materializer_refuses_missing_or_caller_supplied_review_and_changed_tree(tmp_path, monkeypatch):
    from p11lab import image_custody

    root, sealed, policy = _configured_tree_policy(tmp_path, monkeypatch)
    original = copy.deepcopy(policy['components'])
    policy["components"] = []
    with pytest.raises(ValueError, match="protected custody component"):
        image_custody.materialize_custody_component("checker-root", sealed.artifact(), output_dir=tmp_path / "missing")
    policy["components"] = [{"name": "checker-root", "kind": "custody-tree", "inventory": {}, "expected": {}}]
    with pytest.raises(ValueError):
        image_custody.materialize_custody_component("checker-root", sealed.artifact(), output_dir=tmp_path / "bad")
    with pytest.raises(TypeError):
        image_custody.materialize_custody_component("checker-root", sealed.artifact(), output_dir=tmp_path / "bad", inventory={})
    policy["components"] = original
    (root / "demo.txt").write_bytes(b"modified")
    with pytest.raises(ValueError):
        image_custody.materialize_custody_component("checker-root", sealed.artifact(), output_dir=tmp_path / "altered")


@pytest.mark.parametrize("change", ["expected", "notice", "source", "grant"])
def test_materializer_refuses_incomplete_protected_review(tmp_path, monkeypatch, change):
    from p11lab import image_custody

    _, sealed, policy = _configured_tree_policy(tmp_path, monkeypatch)
    template = policy["components"][0]
    if change == "expected":
        template["expected"]["files"][0]["sha256"] = "0" * 64
    if change == "notice":
        template["inventory"]["reviews"][0]["notices"] = []
    if change == "source":
        template["inventory"]["sources"][0]["payloads"] = []
    if change == "grant":
        template["inventory"]["reviews"][0]["grant_known"] = False
    with pytest.raises(ValueError):
        image_custody.materialize_custody_component("checker-root", sealed.artifact(), output_dir=tmp_path / "blocked")


def test_image_review_projection_preserves_lower_layer_content_without_binding_runtime_id():
    from p11lab import image_custody

    observed = {"artifact": {"sha256": "a" * 64}, "files": [], "packages": [], "binaries": [],
                "linked_libraries": [], "link_method": "fixture", "distribution": {
                    "platform": "linux/amd64", "runtime_mount_files": [],
                    "hidden_layer_files": [{"layer": 0, "path": "/hidden", "sha256": "b" * 64, "size": 3}],
                    "whiteouts": [], "layers": [{"index": 0, "regular_file_bytes": 3, "sha256": "c" * 64}],
                    "config_sha256": "d" * 64, "archive_size_bytes": 100}}
    expected = image_custody._reviewed_content_projection(observed, "docker-local")
    changed_identity = copy.deepcopy(observed)
    changed_identity["artifact"]["sha256"] = "e" * 64
    changed_identity["distribution"]["config_sha256"] = "f" * 64
    assert image_custody._reviewed_content_projection(changed_identity, "docker-local") == expected
    changed_identity["distribution"]["hidden_layer_files"][0]["sha256"] = "0" * 64
    assert image_custody._reviewed_content_projection(changed_identity, "docker-local") != expected


def test_component_source_first_uses_exact_readback_and_refuses_changed_source(tmp_path, monkeypatch):
    import shutil
    from p11lab import image_custody, publish, source_transport
    from test_source_delivery import oci_manifest

    _, sealed, _ = _configured_tree_policy(tmp_path, monkeypatch)
    image_custody.materialize_custody_component("checker-root", sealed.artifact(), output_dir=tmp_path / "local")
    evidence = tmp_path / "local/evidence"
    manifest = oci_manifest(tmp_path / "manifest.json", evidence, publish.CONTENT_FILES)
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

    def local_transport(repository, digest, expected, *, artifact_type, output_dir):
        assert repository == "ghcr.io/p11lab/softhsm2"
        assert digest == manifest_sha
        output_dir.mkdir(parents=True)
        shutil.copyfile(manifest, output_dir / "manifest.json")
        (output_dir / "files").mkdir()
        for name in expected:
            shutil.copyfile(evidence / name, output_dir / "files" / name)
        (output_dir / "transport-journal.json").write_text('{"fixture":true}')

    monkeypatch.setattr(source_transport, "acquire", local_transport)
    result = image_custody.verify_custody_component_source(
        "checker-root", sealed.artifact(), evidence_dir=evidence,
        registry="ghcr.io/p11lab/softhsm2", manifest_sha256=manifest_sha,
        output_dir=tmp_path / "readback",
    )
    assert result["source_first_status"] == "verified-anonymous-source-readback"
    assert result["reference"] == "ghcr.io/p11lab/softhsm2@sha256:" + manifest_sha
    (evidence / "source-companion.tar.gz").write_bytes(b"changed")
    with pytest.raises(ValueError):
        image_custody.verify_custody_component_source(
            "checker-root", sealed.artifact(), evidence_dir=evidence,
            registry="ghcr.io/p11lab/softhsm2", manifest_sha256=manifest_sha,
            output_dir=tmp_path / "bad-readback",
        )


def test_component_source_rejects_same_job_self_paired_review(tmp_path, monkeypatch):
    import shutil
    from p11lab import image_custody, publish, source_transport
    from test_source_delivery import oci_manifest

    _, sealed, policy = _configured_tree_policy(tmp_path, monkeypatch)
    inventory = copy.deepcopy(policy["components"][0]["inventory"])
    inventory["artifact"] = asdict(sealed.artifact())
    inventory["observation"] = sealed.observation()
    inventory["reviews"][0]["chosen_route"] = "a different caller supplied declaration"
    evidence = tmp_path / "self-paired"
    sources.collect_source_bundle(sealed.artifact(), inventory, evidence)
    manifest = oci_manifest(tmp_path / "self-paired.json", evidence, publish.CONTENT_FILES)
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

    def local_transport(repository, digest, expected, *, artifact_type, output_dir):
        output_dir.mkdir(parents=True)
        shutil.copyfile(manifest, output_dir / "manifest.json")
        (output_dir / "files").mkdir()
        for name in expected:
            shutil.copyfile(evidence / name, output_dir / "files" / name)
        (output_dir / "transport-journal.json").write_text('{"fixture":true}')

    monkeypatch.setattr(source_transport, "acquire", local_transport)
    with pytest.raises(ValueError, match="review differs"):
        image_custody.verify_custody_component_source(
            "checker-root", sealed.artifact(), evidence_dir=evidence,
            registry="ghcr.io/p11lab/softhsm2", manifest_sha256=manifest_sha,
            output_dir=tmp_path / "readback-self-paired",
        )


def test_generated_evaluator_metadata_requires_actual_strict_receipt_and_protected_recipe(tmp_path, monkeypatch, evaluator):
    from p11lab import delivery_authority, image_custody

    sealed = licenses.observe_custody_evaluator_metadata(evaluator, platform="linux/amd64")
    observation = sealed.observation()
    assert sealed.artifact().kind == "custody-evaluator-metadata"
    assert observation["files"][0]["path"] == "/evaluator-build-receipt.json"
    assert observation["generated_metadata"]["receipt_sha256"] == sealed.artifact().sha256
    (tmp_path / "review").mkdir()
    _, inventory = admission_inventory(tmp_path / "review")
    inventory.update(artifact=None, observation=None, build_key=None)
    inventory["content_reviews"][0]["path"] = "/evaluator-build-receipt.json"
    inventory["content_reviews"][0]["sha256"] = None
    template = {"name": "evaluator-original", "kind": "custody-evaluator-metadata",
                "inventory": inventory, "expected": image_custody._reviewed_content_projection(observation, sealed.artifact().kind)}
    policy = {"schema_version": 1, "components": [template]}
    monkeypatch.setattr(image_custody, "_installed_custody_policy", lambda: copy.deepcopy(policy))
    monkeypatch.setattr(delivery_authority, "load_profile", lambda *args, **kwargs: {"fixture": True})
    monkeypatch.setattr(delivery_authority, "_check_local_controller", lambda profile: None)
    result = image_custody.materialize_custody_component("evaluator-original", sealed.artifact(), output_dir=tmp_path / "result")
    assert result["status"] == "eligible-local-content"
    assert result["source_first_status"] == "not-yet-read-back"
    policy["components"][0]["inventory"]["content_reviews"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        image_custody.materialize_custody_component("evaluator-original", sealed.artifact(), output_dir=tmp_path / "wrong-template")


def test_replayed_evaluator_metadata_rejects_caller_json_binding_before_file_access(tmp_path):
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef("custody-evaluator-metadata", str(tmp_path / "missing-receipt.json"), "0" * 64, "linux/amd64")
    with pytest.raises(TypeError, match="typed evaluator replay"):
        licenses.inspect_artifact(artifact, replay_binding={"authenticated": True})
    with pytest.raises(TypeError, match="typed evaluator replay"):
        licenses.assess_distribution(artifact, tmp_path / "missing", replay_binding={"authenticated": True})


def test_pack_tree_preserves_closed_actual_bytes_links_and_modes(tmp_path):
    import tarfile
    from p11lab import image_custody

    root = _tree_fixture(tmp_path)
    (root / "demo.txt").chmod(0o755)
    (root / "alias").symlink_to("demo.txt")
    (root / "subdir").mkdir()
    artifact = licenses.observe_custody_tree(root, platform="linux/amd64").artifact()
    archive = tmp_path / "tree.tar.gz"
    record = image_custody._pack_verified_tree(artifact, archive)
    assert record["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    with tarfile.open(archive, "r:gz") as saved:
        assert saved.getmember("demo.txt").mode == 0o755
        assert saved.extractfile("demo.txt").read() == b"demo"
        assert saved.getmember("alias").issym() and saved.getmember("alias").linkname == "demo.txt"
        assert saved.getmember("subdir").isdir()
    (root / "demo.txt").write_bytes(b"changed")
    with pytest.raises(ValueError, match="identity"):
        image_custody._pack_verified_tree(artifact, tmp_path / "changed.tar.gz")


def test_compress_preserves_verified_archive_bytes_and_refuses_input_alias(tmp_path):
    import gzip
    from p11lab import image_custody

    raw = tmp_path / "fixture.tar"
    raw.write_bytes(b"original inert archive bytes" * 100)
    target = tmp_path / "fixture.tar.gz"
    result = image_custody._gzip_verified_file(raw, target)
    assert result["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert gzip.decompress(target.read_bytes()) == raw.read_bytes()
    with pytest.raises(ValueError):
        image_custody._gzip_verified_file(raw, raw)


def test_tool_image_save_refuses_missing_engine_identity_before_transfer(tmp_path, monkeypatch):
    from p11lab import docker, image_custody, inspection_bounded
    from p11lab.models import ArtifactRef

    class MissingImage:
        env = {}

        def image(self, artifact):
            raise ValueError("image unavailable")

    called = []
    monkeypatch.setattr(docker, "Docker", lambda: MissingImage())
    monkeypatch.setattr(inspection_bounded, "bounded_stream", lambda *args: called.append(True))
    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    with pytest.raises(ValueError, match="image unavailable"):
        image_custody._save_verified_tool_image(artifact, tmp_path / "out")
    assert not called


def test_unpack_tree_roundtrip_and_refuses_altered_or_escaping_links(tmp_path):
    import io
    import tarfile
    from p11lab import image_custody

    root = _tree_fixture(tmp_path)
    (root / "alias").symlink_to("demo.txt")
    artifact = licenses.observe_custody_tree(root, platform="linux/amd64").artifact()
    archive = tmp_path / "tree.tar.gz"
    identity = image_custody._pack_verified_tree(artifact, archive)
    restored = image_custody._unpack_verified_tree(archive, identity, artifact.sha256, tmp_path / "restored")
    assert restored.sha256 == artifact.sha256
    assert (tmp_path / "restored/demo.txt").read_bytes() == b"demo"
    assert os.readlink(tmp_path / "restored/alias") == "demo.txt"
    unsafe = tmp_path / "unsafe.tar.gz"
    with tarfile.open(unsafe, "w:gz") as bundle:
        link = tarfile.TarInfo("escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        bundle.addfile(link)
        data = tarfile.TarInfo("demo.txt")
        data.size = 4
        bundle.addfile(data, io.BytesIO(b"demo"))
    expected = {"size": unsafe.stat().st_size, "sha256": hashlib.sha256(unsafe.read_bytes()).hexdigest()}
    with pytest.raises(ValueError, match="link"):
        image_custody._unpack_verified_tree(unsafe, expected, artifact.sha256, tmp_path / "unsafe-output")


def test_unpack_tree_rejects_archive_replaced_after_open(tmp_path, monkeypatch):
    import tarfile
    from p11lab import image_custody

    root = _tree_fixture(tmp_path)
    artifact = licenses.observe_custody_tree(root, platform="linux/amd64").artifact()
    archive = tmp_path / "tree.tar.gz"
    identity = image_custody._pack_verified_tree(artifact, archive)
    original_open = tarfile.open

    def swap_after_open(*args, **kwargs):
        archive.rename(tmp_path / "original.tar.gz")
        archive.write_bytes(b"replaced")
        return original_open(*args, **kwargs)

    monkeypatch.setattr(tarfile, "open", swap_after_open)
    with pytest.raises(ValueError, match="archive changed"):
        image_custody._unpack_verified_tree(archive, identity, artifact.sha256, tmp_path / "restored")


def test_component_rights_archive_keeps_exact_readback_records(tmp_path, monkeypatch):
    import shutil
    import tarfile
    from p11lab import image_custody, publish, source_transport
    from test_source_delivery import oci_manifest

    _, sealed, _ = _configured_tree_policy(tmp_path, monkeypatch)
    image_custody.materialize_custody_component("checker-root", sealed.artifact(), output_dir=tmp_path / "local")
    evidence = tmp_path / "local/evidence"
    manifest = oci_manifest(tmp_path / "manifest.json", evidence, publish.CONTENT_FILES)
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()

    def local_transport(repository, digest, expected, *, artifact_type, output_dir):
        output_dir.mkdir(parents=True)
        shutil.copyfile(manifest, output_dir / "manifest.json")
        (output_dir / "files").mkdir()
        for name in expected:
            shutil.copyfile(evidence / name, output_dir / "files" / name)
        (output_dir / "transport-journal.json").write_text('{"fixture":true}')

    monkeypatch.setattr(source_transport, "acquire", local_transport)
    root = tmp_path / "component-sources"
    root.mkdir()
    checked = image_custody.verify_custody_component_source("checker-root", sealed.artifact(), evidence_dir=evidence,
        registry="ghcr.io/p11lab/softhsm2", manifest_sha256=manifest_sha, output_dir=root / "source-checker-root")
    component = {"name": "checker-root", "source": checked}
    result = image_custody._pack_component_rights([component], root, tmp_path / "rights-tree", tmp_path / "rights.tar.gz")
    assert result["archive"]["sha256"] == hashlib.sha256((tmp_path / "rights.tar.gz").read_bytes()).hexdigest()
    with tarfile.open(tmp_path / "rights.tar.gz", "r:gz") as bundle:
        assert set(bundle.getnames()) == {"checker-root", "checker-root/source-companion.json", "checker-root/sbom.spdx.json",
            "checker-root/inventory.json", "checker-root/source-oci-manifest.json", "checker-root/source-transport-journal.json",
            "checker-root/content-readback-proof.json"}
    (root / "source-checker-root/source-oci/files/source-companion.json").write_bytes(b"changed")
    with pytest.raises(ValueError, match="record mismatch"):
        image_custody._pack_component_rights([component], root, tmp_path / "bad-tree", tmp_path / "bad.tar.gz")


def test_tree_unpack_rejects_oversized_pax_header_before_allocation(tmp_path):
    import gzip
    import tarfile
    from p11lab import image_custody

    info = tarfile.TarInfo("oversized-pax")
    info.type = tarfile.XHDTYPE
    info.size = 8 * 1024**2 + 1
    archive = tmp_path / "pax-bomb.tar.gz"
    archive.write_bytes(gzip.compress(info.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024))
    identity = {"size": archive.stat().st_size, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    with pytest.raises(ValueError, match="metadata"):
        image_custody._unpack_verified_tree(archive, identity, "0" * 64, tmp_path / "out")


def _pax_record(key, value):
    body = b" " + key + b"=" + value + b"\n"
    length = len(body) + 1
    while len(str(length)) + len(body) != length:
        length = len(str(length)) + len(body)
    return str(length).encode() + body


def _pax_header(payload):
    import tarfile

    entry = tarfile.TarInfo("pax")
    entry.type = tarfile.XHDTYPE
    entry.size = len(payload)
    return entry.tobuf(format=tarfile.USTAR_FORMAT) + payload + b"\0" * ((-len(payload)) % 512)


def test_tree_unpack_rejects_aggregate_metadata_and_ambiguous_headers(tmp_path, monkeypatch):
    import gzip
    import tarfile
    from p11lab import image_custody

    one = _pax_record(b"path", b"demo.txt")
    two = _pax_record(b"linkpath", b"demo.txt")
    end = tarfile.TarInfo("demo.txt").tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024
    archive = tmp_path / "metadata.tar.gz"
    archive.write_bytes(gzip.compress(_pax_header(one) + _pax_header(two) + end))
    record = {"size": archive.stat().st_size, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    monkeypatch.setattr(image_custody, "_TAR_METADATA_TOTAL_LIMIT", len(one) + len(two) - 1)
    with pytest.raises(ValueError, match="aggregate metadata"):
        image_custody._unpack_verified_tree(archive, record, "0" * 64, tmp_path / "over-limit")
    monkeypatch.setattr(image_custody, "_TAR_METADATA_TOTAL_LIMIT", 64 * 1024**2)
    archive.write_bytes(gzip.compress(_pax_header(one + one) + end))
    record = {"size": archive.stat().st_size, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    with pytest.raises(ValueError, match="duplicate"):
        image_custody._unpack_verified_tree(archive, record, "0" * 64, tmp_path / "duplicate")


def test_tree_unpack_limits_total_decompressed_stream(tmp_path, monkeypatch):
    from p11lab import image_custody

    root = _tree_fixture(tmp_path)
    artifact = licenses.observe_custody_tree(root, platform="linux/amd64").artifact()
    archive = tmp_path / "tree.tar.gz"
    record = image_custody._pack_verified_tree(artifact, archive)
    monkeypatch.setattr(image_custody, "_TAR_STREAM_LIMIT", 4096)
    with pytest.raises(ValueError, match="stream byte"):
        image_custody._unpack_verified_tree(archive, record, artifact.sha256, tmp_path / "out")


def test_tree_unpack_rejects_conflicting_consecutive_metadata_records(tmp_path):
    import gzip
    import tarfile
    from p11lab import image_custody

    one = _pax_record(b"path", b"demo.txt")
    two = _pax_record(b"path", b"other.txt")
    end = tarfile.TarInfo("demo.txt").tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024
    archive = tmp_path / "conflict.tar.gz"
    archive.write_bytes(gzip.compress(_pax_header(one) + _pax_header(two) + end))
    record = {"size": archive.stat().st_size, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    with pytest.raises(ValueError, match="ambiguous"):
        image_custody._unpack_verified_tree(archive, record, "0" * 64, tmp_path / "out")


def test_tree_unpack_accepts_own_long_pax_path_and_link(tmp_path):
    from p11lab import image_custody

    root = tmp_path / "tree"
    directory = root / ("d" * 120)
    directory.mkdir(parents=True)
    name = "f" * 120
    (directory / name).write_bytes(b"reviewed bytes")
    (root / "alias").symlink_to("d" * 120 + "/" + name)
    artifact = licenses.observe_custody_tree(root, platform="linux/amd64").artifact()
    archive = tmp_path / "tree.tar.gz"
    record = image_custody._pack_verified_tree(artifact, archive)
    restored = image_custody._unpack_verified_tree(archive, record, artifact.sha256, tmp_path / "restored")
    assert restored.sha256 == artifact.sha256
    assert (tmp_path / "restored" / ("d" * 120) / name).read_bytes() == b"reviewed bytes"


def test_tool_archive_observes_complete_content_topology_and_ignores_tar_timestamp(tmp_path):
    import io
    import tarfile
    from p11lab import image_custody

    def make(path, *, mtime, data=b"demo"):
        with tarfile.open(path, "w") as bundle:
            directory = tarfile.TarInfo("./bin")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.mtime = mtime
            bundle.addfile(directory)
            file = tarfile.TarInfo("./bin/app")
            file.mode = 0o755
            file.size = len(data)
            file.mtime = mtime
            bundle.addfile(file, io.BytesIO(data))
            link = tarfile.TarInfo("./bin/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "app"
            bundle.addfile(link)
            hard = tarfile.TarInfo("./bin/hard")
            hard.type = tarfile.LNKTYPE
            hard.linkname = "./bin/app"
            bundle.addfile(hard)
            device = tarfile.TarInfo("./dev-null")
            device.type = tarfile.CHRTYPE
            device.devmajor, device.devminor = 1, 3
            bundle.addfile(device)

    first, second = tmp_path / "one.tar", tmp_path / "two.tar"
    make(first, mtime=1)
    make(second, mtime=2)
    one = image_custody._observe_tool_archive(first)
    two = image_custody._observe_tool_archive(second)
    assert one["members"] == two["members"]
    assert one["archive"] != two["archive"]
    assert {row["type"] for row in one["members"]} == {"directory", "file", "symlink", "hardlink", "character"}
    changed = tmp_path / "changed.tar"
    make(changed, mtime=1, data=b"evil")
    assert image_custody._observe_tool_archive(changed)["members"] != one["members"]


def test_tool_archive_review_requires_expected_member_and_existing_source_grant(tmp_path):
    import io
    import tarfile
    from p11lab import image_custody

    root = tmp_path / "tree"
    root.mkdir()
    archive = root / "snapshot.tar"
    with tarfile.open(archive, "w") as bundle:
        item = tarfile.TarInfo("bin/app")
        item.mode = 0o755
        item.size = 4
        bundle.addfile(item, io.BytesIO(b"demo"))
    observed = image_custody._observe_tool_archive(archive)
    artifact = licenses.observe_custody_tree(root, platform="linux/amd64").artifact()
    (tmp_path / "review").mkdir()
    _, inventory = admission_inventory(tmp_path / "review")
    spec = {"path": "snapshot.tar", "members": observed["members"],
            "content_reviews": [{"path": "/bin/app", "sha256": hashlib.sha256(b"demo").hexdigest(),
                                 "source": "demo=1", "status": "reviewed"}]}
    assert image_custody._check_tool_archive_review(artifact, spec, inventory) == observed["archive"]
    changed = copy.deepcopy(spec)
    changed["members"][0]["mode"] = 0o600
    with pytest.raises(ValueError, match="expected"):
        image_custody._check_tool_archive_review(artifact, changed, inventory)
    changed = copy.deepcopy(spec)
    changed["content_reviews"] = []
    with pytest.raises(ValueError, match="unreviewed"):
        image_custody._check_tool_archive_review(artifact, changed, inventory)
    changed_inventory = copy.deepcopy(inventory)
    changed_inventory["reviews"][0]["grant_known"] = False
    with pytest.raises(ValueError, match="unreviewed"):
        image_custody._check_tool_archive_review(artifact, spec, changed_inventory)


def test_dynamic_tool_archive_projection_keeps_every_other_content_binding(tmp_path):
    from p11lab import image_custody

    root = _tree_fixture(tmp_path)
    (root / "snapshot.tar").write_bytes(b"archive bytes")
    (root / "manifest.json").write_bytes(b"metadata bytes")
    observed = licenses.observe_custody_tree(root, platform="linux/amd64").observation()
    by_path = {row["path"]: row for row in observed["files"]}
    dynamic = {path: by_path[path]["sha256"] for path in ("/snapshot.tar", "/manifest.json")}
    projected = image_custody._reviewed_content_projection(observed, "custody-tree", dynamic)
    for path in dynamic:
        row = next(row for row in projected["files"] if row["path"] == path)
        assert row["sha256"] is None and row["size"] is None
    changed = copy.deepcopy(observed)
    next(row for row in changed["files"] if row["path"] == "/demo.txt")["sha256"] = "0" * 64
    assert image_custody._reviewed_content_projection(changed, "custody-tree", dynamic) != projected
    with pytest.raises(ValueError, match="dynamic"):
        image_custody._reviewed_content_projection(observed, "custody-tree", {"/snapshot.tar": "0" * 64})


def test_generated_tool_metadata_uses_closed_owner_template_and_typed_fields():
    from p11lab import image_custody

    template = {"schema_version": 2, "status": "installed-local-only",
                "created": {"$p11lab_observed": "timestamp"},
                "engine": {"$p11lab_observed": "sha256ref"}}
    actual = {"schema_version": 2, "status": "installed-local-only", "created": "2026-10-28T23:06:47Z",
              "engine": "sha256:" + "a" * 64}
    image_custody._check_generated_tool_metadata(actual, template)
    for changed in (actual | {"extra": "unknown"}, actual | {"created": "not a time"},
                    actual | {"engine": "latest"}, actual | {"status": "reviewed"}):
        with pytest.raises(ValueError):
            image_custody._check_generated_tool_metadata(changed, template)
    with pytest.raises(ValueError):
        image_custody._check_generated_tool_metadata("anything", {"$p11lab_observed": "unrestricted"})


def test_protected_dynamic_tool_archive_still_rejects_changed_binary_member(tmp_path, monkeypatch):
    import io
    import json
    import shutil
    import tarfile
    from p11lab import delivery_authority, image_custody, publish, source_transport, tool_builds
    from test_source_delivery import oci_manifest

    root = tmp_path / "tree"
    root.mkdir()
    archive = root / "snapshot.tar"

    def write_archive(data):
        with tarfile.open(archive, "w") as bundle:
            item = tarfile.TarInfo("bin/app")
            item.mode = 0o755
            item.size = len(data)
            bundle.addfile(item, io.BytesIO(data))

    def write_manifest():
        record = {"size": archive.stat().st_size, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        value = {"schema_version": 2, "toolset": "checker", "evidence": {"snapshot.tar": record},
                 "producer_resources": {"driver": {"sha256": "d" * 64}}}
        (root / "manifest.json").write_text(json.dumps(value, sort_keys=True))
        return value

    write_archive(b"demo")
    manifest = write_manifest()
    artifact = licenses.observe_custody_tree(root, platform="linux/amd64").artifact()
    observed = licenses.inspect_artifact(artifact)
    dynamic = {row["path"]: row["sha256"] for row in observed["files"]}
    (tmp_path / "review").mkdir()
    _, inventory = admission_inventory(tmp_path / "review")
    inventory.update(artifact=None, observation=None, build_key=None)
    inventory["content_reviews"] = [{"path": path, "sha256": None, "source": "demo=1", "status": "reviewed"}
                                    for path in sorted(dynamic)]
    spec = {"path": "snapshot.tar", "members": image_custody._observe_tool_archive(archive)["members"],
            "content_reviews": [{"path": "/bin/app", "sha256": hashlib.sha256(b"demo").hexdigest(),
                                 "source": "demo=1", "status": "reviewed"}]}
    manifest_template = copy.deepcopy(manifest)
    manifest_template["evidence"]["snapshot.tar"]["sha256"] = {"$p11lab_observed": "sha256"}
    template = {"name": "checker-root", "kind": "custody-tree", "inventory": inventory,
                "expected": image_custody._reviewed_content_projection(observed, "custody-tree", dynamic),
                "archives": [spec], "generated_metadata": {"path": "manifest.json", "renderer_sha256": "d" * 64,
                                                               "template": manifest_template}}
    monkeypatch.setattr(image_custody, "_installed_custody_policy", lambda: {"schema_version": 1, "components": [copy.deepcopy(template)]})
    monkeypatch.setattr(delivery_authority, "load_profile", lambda *args, **kwargs: {"fixture": True})
    monkeypatch.setattr(delivery_authority, "_check_local_controller", lambda profile: None)
    monkeypatch.setattr(tool_builds, "verify_tool_build", lambda *args, **kwargs: json.loads((root / "manifest.json").read_bytes()))
    config = {"root": str(root), "input_receipt": str(tmp_path / "inputs.json"),
              "manifest_sha256": dynamic["/manifest.json"]}
    result = image_custody.materialize_custody_component("checker-root", artifact, output_dir=tmp_path / "ok", tool_config=config)
    assert result["status"] == "eligible-local-content"
    evidence = tmp_path / "ok/evidence"
    source_manifest = oci_manifest(tmp_path / "source-manifest.json", evidence, publish.CONTENT_FILES)
    source_sha = hashlib.sha256(source_manifest.read_bytes()).hexdigest()

    def local_transport(repository, digest, expected, *, artifact_type, output_dir):
        output_dir.mkdir(parents=True)
        shutil.copyfile(source_manifest, output_dir / "manifest.json")
        (output_dir / "files").mkdir()
        for name in expected:
            shutil.copyfile(evidence / name, output_dir / "files" / name)
        (output_dir / "transport-journal.json").write_text('{"fixture":true}')

    monkeypatch.setattr(source_transport, "acquire", local_transport)
    checked = image_custody.verify_custody_component_source("checker-root", artifact, evidence_dir=evidence,
        registry="ghcr.io/p11lab/softhsm2", manifest_sha256=source_sha, output_dir=tmp_path / "readback", tool_config=config)
    assert checked["source_first_status"] == "verified-anonymous-source-readback"
    write_archive(b"evil")
    write_manifest()
    changed = licenses.observe_custody_tree(root, platform="linux/amd64").artifact()
    config["manifest_sha256"] = hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="expected member closure"):
        image_custody.materialize_custody_component("checker-root", changed, output_dir=tmp_path / "blocked", tool_config=config)


def test_restore_inert_tool_image_checks_actual_archive_graph_before_load(tmp_path, monkeypatch):
    import io
    import json
    import tarfile
    from pathlib import Path
    from p11lab import docker, image_custody
    from p11lab.models import ArtifactRef

    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as contents:
        item = tarfile.TarInfo("fixture.txt")
        item.size = 1
        contents.addfile(item, io.BytesIO(b"x"))
    blob = layer.getvalue()
    layer_id = "sha256:" + hashlib.sha256(blob).hexdigest()
    config = json.dumps({"rootfs": {"type": "layers", "diff_ids": [layer_id]},
                         "os": "linux", "architecture": "amd64"}).encode()
    manifest = json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode()
    raw = tmp_path / "original.tar"
    with tarfile.open(raw, "w") as saved:
        for name, data in (("manifest.json", manifest), ("config.json", config), ("layer.tar", blob)):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            saved.addfile(item, io.BytesIO(data))
    archive = tmp_path / "original.tar.gz"
    record = image_custody._gzip_verified_file(raw, archive)
    digest = hashlib.sha256(config).hexdigest()
    artifact = ArtifactRef("docker-local", "sha256:" + digest, digest, "linux/amd64")
    seen = []

    class FakeDocker:
        env = {"DOCKER_HOST": "unix:///fixture"}

        def command(self, argv, timeout=15, **kwargs):
            assert argv[:3] == ["image", "load", "--input"]
            seen.append(Path(argv[3]).read_bytes())
            return docker.CommandResult(0, "loaded fixture", "")

        def image(self, value):
            assert value == artifact
            return {"Id": value.reference, "Os": "linux", "Architecture": "amd64", "RootFS": {"Layers": [layer_id]}}

    monkeypatch.setattr(docker, "Docker", FakeDocker)
    result = image_custody._restore_component_image(archive, record, artifact, tmp_path / "restore")
    assert result["engine_id"] == artifact.reference
    assert seen == [raw.read_bytes()]
    archive.write_bytes(b"changed")
    with pytest.raises(ValueError, match="archive identity"):
        image_custody._restore_component_image(archive, record, artifact, tmp_path / "bad")
    assert len(seen) == 1


def test_synthetic_configured_producer_rechecks_all_real_component_source_verifiers(tmp_path, monkeypatch, evaluator):
    """Local orchestration fixture; source D, image engine and transport are synthetic."""
    import json
    import shutil
    from pathlib import Path
    from p11lab import delivery_authority, image_custody, publish, source_transport
    from p11lab.checker import load_profile
    from p11lab.models import ArtifactRef
    from p11lab.round_core.evaluator_replay import observe_local_evaluator
    from p11lab.round_core.tool_identity import verified_evaluator_identity
    from test_image_custody import _completed_factory_fixture
    from test_source_delivery import oci_manifest

    raw, plan = os.environ.get('P11LAB_CUSTODY_TEST_RAW'), os.environ.get('P11LAB_CUSTODY_TEST_PLAN')
    if not raw or not plan:
        pytest.skip('requires retained checker originals')
    _completed_factory_fixture(tmp_path, monkeypatch)
    profile = delivery_authority.load_profile('softhsm2', 'release')
    root = Path(evaluator)
    seal = verified_evaluator_identity(root)['receipt_sha256']
    raw_root = tmp_path / 'raw-input/checker'
    raw_root.mkdir(parents=True)
    shutil.copyfile(raw, raw_root / 'report.jsonl')
    initial = observe_local_evaluator(root, seal, set(load_profile()['sources']), raw_root.parent,
                                      Path(plan), tmp_path / 'initial-observation').as_dict()
    artifact = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    components, templates, image_observations = {}, [], {}
    original_inspect = licenses.inspect_artifact
    for index, (name, kind) in enumerate(image_custody.COMPONENTS.items()):
        basedir = tmp_path / ('component-' + name)
        basedir.mkdir()
        if kind == 'custody-evaluator-metadata':
            sealed = licenses.observe_custody_evaluator_metadata(root, platform='linux/amd64')
            selected, observation = sealed.artifact(), sealed.observation()
        elif kind == 'custody-tree':
            tree = basedir / 'tree'
            tree.mkdir()
            (tree / 'demo.txt').write_bytes(b'demo')
            sealed = licenses.observe_custody_tree(tree, platform='linux/amd64')
            selected, observation = sealed.artifact(), sealed.observation()
        else:
            digest = f'{index + 1:064x}'
            selected = ArtifactRef('docker-local', 'sha256:' + digest, digest, 'linux/amd64')
            observation = {'artifact': asdict(selected), 'packages': [], 'binaries': [], 'linked_libraries': [],
                'files': [{'path': '/demo.txt', 'sha256': hashlib.sha256(b'demo').hexdigest(), 'size': 4, 'mode': 420, 'package': None}],
                'link_method': 'synthetic', 'distribution': {'platform': 'linux/amd64', 'runtime_mount_files': [],
                    'hidden_layer_files': [], 'whiteouts': [], 'layers': [], 'config_sha256': digest, 'archive_size_bytes': 1}}
            image_observations[digest] = observation
        _, inventory = admission_inventory(basedir)
        inventory.update(artifact=None, observation=None, build_key=None)
        if kind == 'custody-evaluator-metadata':
            inventory['content_reviews'][0].update(path='/evaluator-build-receipt.json', sha256=None)
        components[name] = selected
        templates.append({'name': name, 'kind': kind, 'inventory': inventory,
                          'expected': image_custody._reviewed_content_projection(observation, kind)})

    def inspect(selected, **kwargs):
        if selected.kind == 'docker-local':
            return copy.deepcopy(image_observations[selected.sha256])
        return original_inspect(selected, **kwargs)

    monkeypatch.setattr(licenses, 'inspect_artifact', inspect)
    monkeypatch.setattr(image_custody, '_installed_custody_policy', lambda: {'schema_version': 1, 'components': copy.deepcopy(templates)})
    sources_by_digest, component_sources = {}, {}
    for name, selected in components.items():
        out = tmp_path / ('local-' + name)
        image_custody.materialize_custody_component(name, selected, output_dir=out)
        evidence = out / 'evidence'
        manifest = oci_manifest(tmp_path / (name + '-manifest.json'), evidence, publish.CONTENT_FILES)
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        sources_by_digest[digest] = (manifest, evidence)
        component_sources[name] = {'evidence_dir': str(evidence), 'manifest_sha256': digest}

    def local_transport(repository, digest, expected, *, artifact_type, output_dir):
        assert repository == 'ghcr.io/p11lab/softhsm2'
        manifest, evidence = sources_by_digest[digest]
        output_dir.mkdir(parents=True)
        shutil.copyfile(manifest, output_dir / 'manifest.json')
        (output_dir / 'files').mkdir()
        for name in expected:
            shutil.copyfile(evidence / name, output_dir / 'files' / name)
        (output_dir / 'transport-journal.json').write_text('{"fixture":true}')

    monkeypatch.setattr(source_transport, 'acquire', local_transport)
    monkeypatch.setattr(image_custody, '_producer_component_artifacts', lambda *args: components)
    monkeypatch.setattr(delivery_authority, '_authenticate_live_run', lambda *args, **kwargs: {'fixture': True})
    facts = {'validation': {'package_sha256': 'b' * 64}, 'fixture': 'synthetic source facts'}
    monkeypatch.setattr(delivery_authority, '_source_facts', lambda **kwargs: facts)
    identity = {'run_id': 100, 'attempt': 1, 'job': profile['job']}
    attested = delivery_authority._make_context('softhsm2', 'release', profile, identity, facts)

    def active_context(**kwargs):
        kwargs['output_dir'].mkdir()
        (kwargs['output_dir'] / 'source-context.json').write_text(json.dumps(attested))
        return attested

    monkeypatch.setattr(delivery_authority, 'verify_active_context', active_context)

    def compositions(archive, digest, candidate, *, evaluator_inputs_dir=None):
        if evaluator_inputs_dir is not None:
            destination = Path(evaluator_inputs_dir)
            (destination / 'checker-input/checker').mkdir(parents=True)
            (destination / 'original').mkdir()
            shutil.copyfile(raw, destination / 'checker-input/checker/report.jsonl')
            shutil.copyfile(plan, destination / 'frozen-plan.json')
            (destination / 'original/planner.json').write_text(json.dumps(initial['planner']))
            (destination / 'original/admission.json').write_text(json.dumps(initial['admission']))
            shutil.copyfile(tmp_path / 'initial-observation/admission/ledger.jsonl', destination / 'original/ledger.jsonl')
        return {'checker': components['checker-derived'], 'consumer': components['consumer-derived']}

    monkeypatch.setattr(image_custody, 'read_validation_compositions', compositions)
    policy = {'tools': {name: {'root': str(tmp_path), 'input_receipt': str(tmp_path / 'receipt'), 'manifest_sha256': 'c' * 64}
                         for name in ('checker', 'consumer', 'oracle')},
              'evaluator': {'root': str(root), 'receipt_sha256': seal}, 'control_base_revision': 'b' * 40}
    kwargs = dict(environment='softhsm2', channel='release', artifact=artifact, evidence_dir=tmp_path / 'provider-evidence',
        validation_dir=tmp_path / 'validation', build_receipt=tmp_path / 'build', sealed_dir=tmp_path / 'seal',
        registry='ghcr.io/p11lab/softhsm2', seal_digest='c' * 64, content_digest='d' * 64,
        context_path=tmp_path / 'context', bundle_path=tmp_path / 'bundle', executable=tmp_path / 'gh',
        trusted_root=tmp_path / 'trusted-root', run_id=100, attempt=1, token='fixture', validation_policy=policy,
        component_sources=component_sources)
    result = image_custody.verify_custody_producer(output_dir=tmp_path / 'producer', **kwargs).as_dict()
    assert len(result['components']) == len(image_custody.COMPONENTS)
    assert result['image_promotable'] is False
    assert result['evaluator']['planner']['files'] == initial['planner']['files']
    assert result['evaluator']['planner']['stdout_sha256'] != initial['planner']['stdout_sha256']
    assert result['evaluator']['admission'] == initial['admission']
    changed = Path(component_sources['consumer-inputs']['evidence_dir']) / 'source-companion.tar.gz'
    changed.write_bytes(b'changed')
    with pytest.raises(ValueError, match='source bytes changed'):
        image_custody.verify_custody_producer(output_dir=tmp_path / 'producer-changed', **kwargs)


def test_consumer_dependency_waiver_refuses_untyped_and_unrelated_artifacts(tmp_path):
    """An external-image dependency needs a typed, scoped witness, never JSON."""
    from p11lab.models import ArtifactRef

    root = _tree_fixture(tmp_path)
    observed = licenses.observe_custody_tree(root, platform="linux/amd64")
    (tmp_path / "consumer-review").mkdir()
    _, inventory = admission_inventory(tmp_path / "consumer-review")
    inventory["artifact"] = asdict(observed.artifact())
    inventory["observation"] = observed.observation()
    with pytest.raises(TypeError, match="typed"):
        licenses.validate_inventory(observed.artifact(), inventory, consumer_binding={"phase": "readback"})
    other = ArtifactRef("bundle", str(root), "a" * 64, "linux/amd64")
    with pytest.raises(TypeError, match="typed"):
        licenses.validate_inventory(other, inventory, consumer_binding={"phase": "local"})


def test_real_consumer_image_binding_phases_and_refusals(tmp_path, monkeypatch):
    """Opt-in local fixture: real tool/image/source validators, fictional rights."""
    import json
    import shutil
    from pathlib import Path
    from p11lab import delivery_authority, image_custody, source_transport
    from test_image_custody import _completed_factory_fixture
    from test_source_delivery import oci_manifest

    fixture = os.environ.get("P11LAB_CV1_FIXTURE")
    if not fixture:
        pytest.skip("requires retained actual tool images and explicitly synthetic source fixture")
    fixture = Path(fixture)
    authority = tmp_path / "fake-authority"
    authority.mkdir()
    _completed_factory_fixture(authority, monkeypatch)
    policy = json.loads((fixture / "cv1-materialize/FROZEN-SYNTHETIC-POLICY.json").read_bytes())
    validation = json.loads(Path(os.environ["P11LAB_CV1_POLICY"]).read_bytes())
    tool = validation["tools"]["consumer"]
    manifest = json.loads((Path(tool["root"]) / "manifest.json").read_bytes())
    root = licenses.observe_custody_tree(Path(tool["root"]), platform="linux/amd64").artifact()
    image_row = next(row for row in policy["components"] if row["name"] == "consumer-image")
    root_row = next(row for row in policy["components"] if row["name"] == "consumer-root")
    product = manifest["products"][0]
    contract = {"schema_version": 1, "kind": "consumer-image-external-prerequisite",
                "image_path": "/usr/local/bin/p11lab-smoke",
                "tree_paths": ["/product/p11lab-smoke", "/runtime/p11lab-smoke"],
                "product_sha256": product["sha256"], "product_size": product["size"],
                "product_mode": 0o755, "tree_modes": {"/product/p11lab-smoke": 0o755, "/runtime/p11lab-smoke": 0o644},
                "elf_closure": manifest["elf_closure"],
                "image_source_review_sha256": delivery_authority._review_digest(image_row["inventory"])}
    root_row["inventory"]["external_image_prerequisite"] = copy.deepcopy(contract)
    root_row["inventory"]["external_image_source"] = None
    monkeypatch.setattr(image_custody, "_installed_custody_policy", lambda: copy.deepcopy(policy))
    evidence = fixture / "cv1-materialize/consumer-image/evidence"
    local = image_custody._consumer_image_binding(root, tool, evidence, tmp_path / "local-binding")
    assert local.as_dict()["phase"] == "local-only"
    assert local.as_dict()["covered_tree_links"] == licenses.observe_custody_tree(Path(tool["root"]), platform="linux/amd64").observation()["linked_libraries"]
    result = image_custody.materialize_custody_component("consumer-root", root, output_dir=tmp_path / "local-root",
                                                          tool_config=tool, consumer_binding=local)
    assert result["status"] == "eligible-local-content"
    with pytest.raises(ValueError, match="phase"):
        image_custody.verify_custody_component_source("consumer-root", root, evidence_dir=tmp_path / "local-root/evidence",
            registry="ghcr.io/p11lab/softhsm2", manifest_sha256="c" * 64, output_dir=tmp_path / "wrong-phase", consumer_binding=local)
    from p11lab import publish
    manifest_path = oci_manifest(tmp_path / "image-source-manifest.json", evidence, publish.CONTENT_FILES)
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    root_evidence = tmp_path / "local-root/evidence"
    root_manifest = oci_manifest(tmp_path / "root-source-manifest.json", root_evidence, publish.CONTENT_FILES)
    root_digest = hashlib.sha256(root_manifest.read_bytes()).hexdigest()
    fixture_sources = {digest: (manifest_path, evidence), root_digest: (root_manifest, root_evidence)}

    def transport(repository, actual_digest, expected, *, artifact_type, output_dir):
        assert repository == "ghcr.io/p11lab/softhsm2"
        selected_manifest, selected_evidence = fixture_sources[actual_digest]
        output_dir.mkdir(parents=True)
        shutil.copyfile(selected_manifest, output_dir / "manifest.json")
        (output_dir / "files").mkdir()
        for name in expected:
            shutil.copyfile(selected_evidence / name, output_dir / "files" / name)
        (output_dir / "transport-journal.json").write_text('{"fixture":true}')

    monkeypatch.setattr(source_transport, "acquire", transport)
    remote = image_custody._consumer_image_binding(root, tool, evidence, tmp_path / "readback-binding",
        registry="ghcr.io/p11lab/softhsm2", manifest_sha256=digest)
    assert remote.as_dict()["phase"] == "source-readback"
    assert remote.as_dict()["source"]["manifest_sha256"] == digest
    assert remote.as_dict()["source"]["receipt_sha256"] == local.as_dict()["source"]["receipt_sha256"]
    checked = image_custody.verify_custody_component_source("consumer-root", root, evidence_dir=root_evidence,
        registry="ghcr.io/p11lab/softhsm2", manifest_sha256=root_digest, output_dir=tmp_path / "root-readback",
        tool_config=tool, consumer_binding=remote)
    assert checked["source_first_status"] == "verified-anonymous-source-readback"
    inventoried = json.loads((root_evidence / "files/inventory.json").read_bytes())
    altered_source = copy.deepcopy(inventoried)
    altered_source["external_image_source"]["source"]["receipt_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="source identity"):
        remote.check(root, altered_source)
    altered_image = copy.deepcopy(inventoried)
    altered_image["external_image_source"]["image"]["reference"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="source identity"):
        remote.check(root, altered_image)
    with pytest.raises(ValueError, match="phase"):
        image_custody.materialize_custody_component("consumer-root", root, output_dir=tmp_path / "remote-in-local",
                                                    tool_config=tool, consumer_binding=remote)
    altered = copy.deepcopy(tool)
    altered["manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        image_custody._consumer_image_binding(root, altered, evidence, tmp_path / "wrong-tool")
    root_row["inventory"]["external_image_prerequisite"]["product_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="product"):
        image_custody._consumer_image_binding(root, tool, evidence, tmp_path / "wrong-product")
    root_row["inventory"]["external_image_prerequisite"] = copy.deepcopy(contract)
    library = next(name for name in contract["elf_closure"] if name.endswith("libc.so.6"))
    root_row["inventory"]["external_image_prerequisite"]["elf_closure"][library]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="closure"):
        image_custody._consumer_image_binding(root, tool, evidence, tmp_path / "wrong-library")
    root_row["inventory"]["external_image_prerequisite"] = copy.deepcopy(contract)
    root_row["inventory"]["external_image_prerequisite"]["tree_modes"]["/runtime/p11lab-smoke"] = 0o755
    with pytest.raises(ValueError, match="protected consumer image prerequisite"):
        image_custody._consumer_image_binding(root, tool, evidence, tmp_path / "wrong-mode")
    root_row["inventory"]["external_image_prerequisite"] = copy.deepcopy(contract)
    bad = tmp_path / "bad-source"
    shutil.copytree(evidence, bad)
    (bad / "source-companion.tar.gz").write_bytes(b"altered synthetic source")
    with pytest.raises(ValueError):
        image_custody._consumer_image_binding(root, tool, bad, tmp_path / "bad-source-binding")


def test_component_inventory_parser_uses_declared_16_mib_bound_and_rejects_duplicates(tmp_path):
    from p11lab import image_custody

    path = tmp_path / "inventory.json"
    path.write_bytes(b'{"fixture":"' + b'x' * (2 * 1024 * 1024) + b'"}')
    assert len(image_custody._read_component_inventory(path)["fixture"]) == 2 * 1024 * 1024
    path.write_bytes(b'{"item":1,"item":2}')
    with pytest.raises(ValueError):
        image_custody._read_component_inventory(path)
    path.write_bytes(b' ' * (16 * 1024 * 1024 + 1))
    with pytest.raises(ValueError):
        image_custody._read_component_inventory(path)


def test_self_contained_consumer_contract_requires_witness_at_both_entrypoints(tmp_path, monkeypatch):
    from p11lab import image_custody

    _, sealed, policy = _configured_tree_policy(tmp_path, monkeypatch)
    template = policy["components"][0]
    template["name"] = "consumer-root"
    template["inventory"]["external_image_prerequisite"] = {"fixture": "protected contract"}
    with pytest.raises(ValueError, match="consumer image.*binding"):
        image_custody.materialize_custody_component("consumer-root", sealed.artifact(), output_dir=tmp_path / "local")
    with pytest.raises(ValueError, match="consumer image.*binding"):
        image_custody.verify_custody_component_source("consumer-root", sealed.artifact(),
            evidence_dir=tmp_path / "absent", registry="ghcr.io/p11lab/softhsm2", manifest_sha256="a" * 64,
            output_dir=tmp_path / "readback")


def _sharded_custody_policy_fixture(tmp_path, monkeypatch):
    import json
    from p11lab import image_custody

    package = tmp_path / "package"
    root = package / "data/ci/delivery"
    shards = root / "custody-components"
    shards.mkdir(parents=True)
    rows = []
    for name, kind in sorted(image_custody.COMPONENTS.items()):
        row = {"name": name, "kind": kind, "inventory": {}, "expected": {}}
        raw = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        (shards / (name + ".json")).write_bytes(raw)
        rows.append({"name": name, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)})
    index = {"schema_version": 2, "components": rows}
    (root / "custody-policy.json").write_text(json.dumps(index))
    monkeypatch.setattr(image_custody, "_custody_policy_root", lambda: root)
    return package, root, index


def test_sharded_policy_real_loader_and_graph_bind_exact_resources(tmp_path, monkeypatch):
    import json
    from p11lab import custody_authority, delivery_authority, image_custody
    from test_image_custody import _completed_factory_fixture

    package, root, index = _sharded_custody_policy_fixture(tmp_path, monkeypatch)
    policy = image_custody._installed_custody_policy()
    assert policy["schema_version"] == 1
    assert [row["name"] for row in policy["components"]] == sorted(image_custody.COMPONENTS)
    identity = delivery_authority._controller_digest(package)
    shard = root / "custody-components" / (index["components"][0]["name"] + ".json")
    original = shard.read_bytes()
    shard.write_bytes(original + b" ")
    assert delivery_authority._controller_digest(package) != identity
    with pytest.raises(ValueError):
        image_custody._installed_custody_policy()
    shard.write_bytes(original)
    assert delivery_authority._controller_digest(package) == identity
    auth = tmp_path / "authority"
    auth.mkdir()
    _completed_factory_fixture(auth, monkeypatch)
    profile = delivery_authority.load_profile("softhsm2", "release")
    for row in index["components"]:
        profile["graph"].append({"path": "src/p11lab/data/ci/delivery/custody-components/" + row["name"] + ".json",
                                 "sha256": row["sha256"]})
    custody_authority._require_custody_graph(profile)
    profile["graph"][-1]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="shard"):
        custody_authority._require_custody_graph(profile)
    assert json.loads((root / "custody-policy.json").read_bytes()) == index


@pytest.mark.parametrize("damage", ["missing", "extra", "alias", "size", "hash", "duplicate", "index_duplicate", "aggregate"])
def test_sharded_policy_loader_refuses_untrusted_roster_and_bytes(tmp_path, monkeypatch, damage):
    import json
    from p11lab import image_custody

    _, root, index = _sharded_custody_policy_fixture(tmp_path, monkeypatch)
    first = index["components"][0]
    path = root / "custody-components" / (first["name"] + ".json")
    if damage == "missing":
        path.unlink()
    elif damage == "extra":
        (path.parent / "extra.json").write_bytes(b"{}")
    elif damage == "alias":
        first["name"] = "../other"
    elif damage == "size":
        first["size_bytes"] += 1
    elif damage == "hash":
        first["sha256"] = "0" * 64
    elif damage == "duplicate":
        raw = b'{"name":"x","name":"x"}'
        path.write_bytes(raw)
        first.update(sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))
    elif damage == "index_duplicate":
        (root / "custody-policy.json").write_bytes(b'{"schema_version":2,"schema_version":2,"components":[]}')
    else:
        for row in index["components"]:
            row["size_bytes"] = 16 * 1024 * 1024
    if damage != "index_duplicate":
        (root / "custody-policy.json").write_text(json.dumps(index))
    with pytest.raises((ValueError, OSError)):
        image_custody._installed_custody_policy()


def test_measured_synthetic_policy_uses_real_bounded_shard_loader(tmp_path, monkeypatch):
    import json
    from pathlib import Path
    from p11lab import custody_authority, delivery_authority, image_custody
    from test_image_custody import _completed_factory_fixture

    fixture = os.environ.get("P11LAB_CV1_FIXTURE")
    if not fixture:
        pytest.skip("requires measured fictional component policy")
    expected = json.loads((Path(fixture) / "cv1-connected-final-2/FROZEN-SYNTHETIC-POLICY.json").read_bytes())
    from shutil import copytree, ignore_patterns
    package = tmp_path / "package"
    copytree(Path(image_custody.__file__).parent, package, ignore=ignore_patterns("__pycache__", "*.pyc"))
    root = package / "data/ci/delivery"
    shards = root / "custody-components"
    shards.mkdir(parents=True)
    entries = []
    for row in sorted(expected["components"], key=lambda item: item["name"]):
        raw = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        (shards / (row["name"] + ".json")).write_bytes(raw)
        entries.append({"name": row["name"], "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    index_raw = json.dumps({"schema_version": 2, "components": entries}, sort_keys=True).encode()
    (root / "custody-policy.json").write_bytes(index_raw)
    monkeypatch.setattr(image_custody, "_custody_policy_root", lambda: root)
    actual = image_custody._installed_custody_policy()
    assert actual == {"schema_version": 1, "components": sorted(expected["components"], key=lambda item: item["name"])}
    assert sum(item["size_bytes"] for item in entries) > 16 * 1024 * 1024
    assert max(item["size_bytes"] for item in entries) > 2 * 1024 * 1024
    digest = delivery_authority._controller_digest(package)
    graph = [{"path": "src/p11lab/data/ci/delivery/custody-policy.json", "sha256": hashlib.sha256(index_raw).hexdigest()}]
    graph.extend({"path": "src/p11lab/data/ci/delivery/custody-components/" + item["name"] + ".json", "sha256": item["sha256"]} for item in entries)
    monkeypatch.setattr(delivery_authority, "_installed_control_file", lambda name: (package / name.removeprefix("src/p11lab/")).read_bytes())
    import io
    from p11lab.round_core import artifacts
    class Response(io.BytesIO):
        status = 200
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    class Opener:
        def open(self, request, timeout):
            assert request.headers.get("Accept") == "application/vnd.github.raw+json"
            return Response((shards / request.full_url.split("?")[0].rsplit("/", 1)[1]).read_bytes())
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    transport = artifacts.GitHubTransport("p11lab/controller", "fixture-token-must-not-appear")
    journal = tmp_path / "graph-journal.json"
    delivery_authority._check_controller_graph(graph, lambda name: (package / name.removeprefix("src/p11lab/")).read_bytes(),
                                                transport=transport, revision="a" * 40, shard_journal=journal)
    diagnostic = json.loads(journal.read_bytes())
    assert diagnostic["category"] == "complete" and diagnostic["worker_reaped"] is True
    assert diagnostic["cleanup"] == "confirmed" and len(diagnostic["files"]) == 12
    assert all(row["expected_sha256"] == row["actual_sha256"] and row["http_status"] == 200 for row in diagnostic["files"])
    assert "fixture-token-must-not-appear" not in journal.read_text()
    authority = tmp_path / "authority"
    authority.mkdir()
    _completed_factory_fixture(authority, monkeypatch)
    profile = delivery_authority.load_profile("softhsm2", "release")
    profile["graph"].extend(graph[1:])
    custody_authority._require_custody_graph(profile)
    altered = shards / (entries[0]["name"] + ".json")
    altered.write_bytes(altered.read_bytes() + b" ")
    assert delivery_authority._controller_digest(package) != digest
    with pytest.raises(ValueError):
        image_custody._installed_custody_policy()


def test_raw_custody_source_transport_exact_roster_and_bounds(tmp_path, monkeypatch):
    import io
    from p11lab import image_custody
    from p11lab.proxy_supervisor import ProxyWorkerError
    from p11lab.round_core import artifacts

    _, _, index = _sharded_custody_policy_fixture(tmp_path, monkeypatch)
    records = [{"path": "src/p11lab/data/ci/delivery/custody-components/" + row["name"] + ".json",
                "sha256": row["sha256"], "size_bytes": row["size_bytes"]} for row in index["components"]]
    root = tmp_path / "package/data/ci/delivery/custody-components"
    bodies = {(root / (row["name"] + ".json")).name: (root / (row["name"] + ".json")).read_bytes() for row in index["components"]}
    name = index["components"][0]["name"] + ".json"
    bodies[name] = b'{"padding":"' + b'x' * (2 * 1024 * 1024) + b'"}'
    records[0].update(size_bytes=len(bodies[name]), sha256=hashlib.sha256(bodies[name]).hexdigest())
    class Response(io.BytesIO):
        status = 200
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    class Opener:
        def open(self, request, timeout):
            assert request.headers.get("Accept") == "application/vnd.github.raw+json"
            assert request.headers.get("Authorization") == "Bearer private-fixture-token"
            assert request.full_url.startswith("https://api.github.com/repos/p11lab/controller/contents/")
            assert request.full_url.endswith("?ref=" + "a" * 40)
            return Response(bodies[request.full_url.split("?")[0].rsplit("/", 1)[1]])
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = artifacts.GitHubTransport("p11lab/controller", "private-fixture-token")
    journal = tmp_path / "success-journal.json"
    result = client.source_custody_shards("a" * 40, records, journal_path=journal)
    import json
    recorded = json.loads(journal.read_bytes())
    assert len(recorded["files"]) == len(image_custody.COMPONENTS)
    assert recorded["worker_reaped"] is True and recorded["cleanup"] == "confirmed"
    assert recorded["authentication"] == "actions-read-token" and "private-fixture-token" not in journal.read_text()
    assert result.bytes_for(records[0]["path"]) == bodies[name]
    assert result.facts()["selectors"] == records
    changed = copy.deepcopy(records)
    changed[0]["sha256"] = "0" * 64
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, changed)
    changed = copy.deepcopy(records)
    changed[0]["size_bytes"] -= 1
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, changed)
    changed = copy.deepcopy(records)
    changed[0]["size_bytes"] += 1
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, changed)
    changed = copy.deepcopy(records)
    changed[0]["path"] = "src/p11lab/data/ci/delivery/custody-components/../evil.json"
    with pytest.raises(ValueError):
        client.source_custody_shards("a" * 40, changed)
    with pytest.raises(ValueError):
        client.source_custody_shards("main", records)
    changed = copy.deepcopy(records)
    changed[0] = copy.deepcopy(changed[1])
    with pytest.raises(ValueError):
        client.source_custody_shards("a" * 40, changed)
    changed = copy.deepcopy(records)
    changed[0]["size_bytes"] = 16 * 1024 * 1024 + 1
    with pytest.raises(ValueError):
        client.source_custody_shards("a" * 40, changed)
    from dataclasses import FrozenInstanceError
    with pytest.raises(FrozenInstanceError):
        result._bytes = ()
    changed = copy.deepcopy(records)
    for row in changed:
        row["size_bytes"] = 16 * 1024 * 1024
    with pytest.raises(ValueError):
        client.source_custody_shards("a" * 40, changed)
    class Redirect(Response):
        status = 302
    class RedirectOpener:
        def open(self, request, timeout): return Redirect(b"")
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: RedirectOpener())
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, records, journal_path=tmp_path / "redirect-journal.json")
    assert json.loads((tmp_path / "redirect-journal.json").read_bytes())["files"][0]["http_status"] == 302


def test_raw_shard_transport_refuses_partial_oversize_lfs_and_preserves_ordinary_cap(tmp_path, monkeypatch):
    import base64
    import io
    import json
    from p11lab.proxy_supervisor import ProxyWorkerError
    from p11lab.round_core import artifacts

    _, root, index = _sharded_custody_policy_fixture(tmp_path, monkeypatch)
    records = [{"path": "src/p11lab/data/ci/delivery/custody-components/" + row["name"] + ".json",
                "sha256": row["sha256"], "size_bytes": row["size_bytes"]} for row in index["components"]]
    client = artifacts.GitHubTransport("p11lab/controller", "fixture")
    body = (root / "custody-components" / (index["components"][0]["name"] + ".json")).read_bytes()
    class Response(io.BytesIO):
        status = 200
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
        def read(self, size=-1):
            assert 0 < size <= 65536
            return super().read(size)
    class Opener:
        def __init__(self, data): self.data = data
        def open(self, request, timeout): return Response(self.data)
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener(body[:-1]))
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, records)
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener(body + b"x"))
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, records)
    pointer = b"version https://git-lfs.github.com/spec/v1\n"
    selected = copy.deepcopy(records)
    selected[0].update(size_bytes=len(pointer), sha256=hashlib.sha256(pointer).hexdigest())
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener(pointer))
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, selected)
    class Broken(Response):
        def read(self, size=-1): raise ConnectionResetError("fixture interrupted")
    class BrokenOpener:
        def open(self, request, timeout): return Broken(b"")
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: BrokenOpener())
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, records)
    class PartialOpener:
        count = 0
        def open(self, request, timeout):
            self.count += 1
            return Response(body) if self.count == 1 else Broken(b"")
    partial = PartialOpener()
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: partial)
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, records, journal_path=tmp_path / "partial-journal.json")
    partial_journal = json.loads((tmp_path / "partial-journal.json").read_bytes())
    assert len(partial_journal["files"]) == 2 and partial_journal["worker_category"] == "network"
    clock = [0.0]
    class Slow(Response):
        def read(self, size=-1):
            clock[0] = 121.0
            return super().read(size)
    class SlowOpener:
        def open(self, request, timeout): return Slow(body)
    monkeypatch.setattr(artifacts.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: SlowOpener())
    with pytest.raises(ProxyWorkerError):
        client.source_custody_shards("a" * 40, records)
    ordinary = {"type": "file", "encoding": "base64", "content": base64.b64encode(b"x" * (1024 * 1024 + 1)).decode()}
    monkeypatch.setattr(client, "_request", lambda *args: (200, {}, json.dumps(ordinary).encode()))
    with pytest.raises(ValueError, match="source file byte bound"):
        client.source_file("a" * 40, "src/p11lab/ordinary.py")


@pytest.mark.parametrize("blocked", ["dns", "drip"])
def test_raw_shard_worker_kills_reaps_and_removes_owned_files_on_block(tmp_path, monkeypatch, blocked):
    import io
    import json
    import time
    from pathlib import Path
    from p11lab.proxy_supervisor import ProxyDeadlineExceeded
    from p11lab.round_core import artifacts

    _, root, index = _sharded_custody_policy_fixture(tmp_path, monkeypatch)
    records = [{"path": "src/p11lab/data/ci/delivery/custody-components/" + row["name"] + ".json",
                "sha256": row["sha256"], "size_bytes": row["size_bytes"]} for row in index["components"]]
    body = (root / "custody-components" / (index["components"][0]["name"] + ".json")).read_bytes()
    import ctypes
    import socket
    marker = tmp_path / "native-block-entered"
    def native_block():
        marker.write_text(blocked)
        ctypes.CDLL(None).poll(None, 0, 10000)
    class Response(io.BytesIO):
        status = 200
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
        def read(self, size=-1):
            if self.tell() > 0:
                native_block()
            return super().read(1)
    class Opener:
        def open(self, request, timeout): return Response(body)
    if blocked == "dns":
        def blocked_dns(*args, **kwargs):
            native_block()
            raise AssertionError("resolver returned")
        monkeypatch.setattr(socket, "getaddrinfo", blocked_dns)
    else:
        monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    monkeypatch.setattr(artifacts, "_CUSTODY_SHARD_TIMEOUT", 0.3)
    client = artifacts.GitHubTransport("p11lab/controller", "fixture-token")
    journal = tmp_path / "worker-journal.json"
    started = time.monotonic()
    with pytest.raises(ProxyDeadlineExceeded) as caught:
        client.source_custody_shards("a" * 40, records, journal_path=journal)
    assert time.monotonic() - started < 5
    assert caught.value.worker_reaped is True and caught.value.worker_pid > 0
    result = json.loads(journal.read_bytes())
    assert result["category"] == "timeout" and result["worker_reaped"] is True
    assert marker.read_text() == blocked
    if blocked == "drip":
        assert result["files"][0]["actual_size_bytes"] == 1
    assert result["cleanup"] == "confirmed" and not Path(result["temporary_directory"]).exists()
    with pytest.raises(ProcessLookupError):
        os.kill(caught.value.worker_pid, 0)


def test_nested_raw_shard_worker_refuses_without_losing_outer_deadline(tmp_path, monkeypatch):
    import json
    import time
    from p11lab.proxy_supervisor import ProxyWorkerError, run_proxy_worker
    from p11lab.round_core import artifacts

    _, _, index = _sharded_custody_policy_fixture(tmp_path, monkeypatch)
    records = [{"path": "src/p11lab/data/ci/delivery/custody-components/" + row["name"] + ".json",
                "sha256": row["sha256"], "size_bytes": row["size_bytes"]} for row in index["components"]]
    client = artifacts.GitHubTransport("p11lab/controller", "fixture")
    journal = tmp_path / "nested-journal.json"
    with pytest.raises(ProxyWorkerError):
        run_proxy_worker(lambda: client.source_custody_shards("a" * 40, records, journal_path=journal).facts(),
                         deadline=time.monotonic() + 5, include_witness=True)
    record = json.loads(journal.read_bytes())
    assert record["category"] == "nested-witness-unsupported" and record["worker_pid"] == 0
    assert record["cleanup"] == "confirmed"

"""Regenerate provider-free fixtures using an explicitly supplied sealed evaluator.

Usage: python generate.py EVALUATOR_ROOT. No provider or network activity. The
symbolic provider/derivative identities originate in the accepted axis fixtures;
local source/wheel stand-ins are byte backed and are not production tool pins.
"""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

from p11lab.round_core.inputs import SealedToolInputs

ROOT = Path(__file__).parent
PUBLIC = """
import dataclasses,json,sys
from pathlib import Path
from pkcs11_check.core.report_log import iter_report_log_records
from pkcs11_check.core.evidence import export_ledger,load_ledger,compile_obligations,ShardExpectation,PredeclaredRoster,admit_lane,shard_digest
root=Path(sys.argv[1]);identity=json.loads((root/'identity.json').read_bytes())
identity={key:str(value) for key,value in identity.items()}
invalid=0
def bad():
 global invalid
 invalid+=1
with (root/'ledger.jsonl').open('w') as sink:
 export_ledger(iter_report_log_records(root/'raw/report.jsonl',on_invalid=bad),identity,sink,reader_invalid_lines=lambda:invalid)
header,rows=load_ledger(root/'ledger.jsonl')
(root/'header.json').write_text(json.dumps(dict(dataclasses.asdict(header),record='header'),sort_keys=True,separators=(',',':')))
ob=json.loads((root/'obligations.json').read_bytes())
verdict=admit_lane(header,rows,PredeclaredRoster(identity['lane'],{identity['shard_id']:ShardExpectation(len(rows),shard_digest(rows))}),compile_obligations(ob['catalog'],ob['profile']))
if not verdict.admitted:raise ValueError(verdict.failures)
print(json.dumps(dataclasses.asdict(verdict)))
"""


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded(value))


def rows(root):
    return sorted(
        [
            {
                "path": p.relative_to(root).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha(p.read_bytes()),
            }
            for p in root.rglob("*")
            if p.is_file()
        ],
        key=lambda row: row["path"],
    )


def generate(evaluator):
    tools = SealedToolInputs.from_evaluator(evaluator)
    provenance = {
        "scope": "synthetic-provider-free",
        "evaluator_receipt_sha256": tools.receipt_sha256,
        "cases": {},
    }
    for axis in ("checker-direct", "checker", "image", "proxy"):
        seed = json.loads(
            (
                ROOT.parents[1]
                / "rounds/fixtures/authority"
                / f"{axis}-authorized.json"
            ).read_bytes()
        )
        envelope = deepcopy(seed["protected_expected"])
        controls = {
            key: {"synthetic": True, "control": key}
            for key in envelope["frozen_controls"]
        }
        envelope["frozen_controls"] = {
            key: sha(encoded(value)) for key, value in controls.items()
        }
        if axis == "checker":
            envelope["lane"] = "checker-softhsm2-proxy-linux-amd64-smoke-v1"
            envelope["protected"]["selected_lane"] = envelope["lane"]
        if axis == "image":
            for endpoint in envelope["endpoints"].values():
                endpoint["artifacts"]["proxy"] = None
        endpoint_roots = {}
        observations = {}
        for role in ("baseline", "candidate"):
            root = ROOT / axis / role
            root.mkdir(parents=True, exist_ok=True)
            endpoint_roots[role] = root
            endpoint = envelope["endpoints"][role]
            endpoint["frozen_controls"] = deepcopy(envelope["frozen_controls"])
            for key, value in controls.items():
                write(root, "controls/" + key + ".json", value)
            if axis == "image":
                endpoint["artifacts"]["checker"]["source_sha"] = (
                    "9df03bd8b811966fa7856394b19e3f57ffcd8a40"
                )
            catalog = [
                "/executor/tests/test_a.py::test_one",
                "/executor/tests/test_b.py::test_two",
            ]
            selected = catalog[:1]
            endpoint.update(
                catalog=catalog,
                selected=selected,
                observed_selected=selected,
                unselected={catalog[1]: "protected-profile-exclusion"},
            )
            for key in ("catalog", "selected"):
                endpoint["evidence"][key + "_sha256"] = sha(encoded(endpoint[key]))
                write(root, key + ".json", {key: endpoint[key]})
            stream = {
                "path": "raw/report.jsonl",
                "attempt": "outer1",
                "shard_id": "outer1/shard0",
                "selected": selected,
            }
            records = [
                {"$report_type": "SessionStart"},
                {
                    "$report_type": "IsolatedUnitReport",
                    "target": selected[0],
                    "attempt": 0,
                },
                {
                    "$report_type": "TestReport",
                    "nodeid": selected[0],
                    "when": "call",
                    "outcome": "failed",
                    "duration": 0.01,
                    "user_properties": [],
                },
                {"$report_type": "SessionFinish", "exitstatus": 1},
            ]
            raw = b"\n".join(encoded(record) for record in records) + b"\n"
            (root / "raw").mkdir(exist_ok=True)
            (root / "raw/report.jsonl").write_bytes(raw)
            write(root, "raw-manifest.json", {"streams": [stream]})
            write(
                root,
                "obligations.json",
                {"catalog": dict.fromkeys(catalog, {}), "profile": {"cases": selected}},
            )
            write(
                root,
                "coverage.json",
                {
                    "mechanism_coverage": {
                        state + "_names": []
                        for state in (
                            "advertised",
                            "accepted",
                            "attempted",
                            "rejected_cleanly",
                            "skipped_by_capability",
                            "crashed",
                            "timeout",
                            "selected",
                            "selection_rejected",
                            "invoked",
                        )
                    }
                },
            )
            write(
                root,
                "installed-manifest.json",
                {
                    "synthetic": True,
                    "role": role if axis.startswith("checker") else "fixed-executor",
                    "source_sha": endpoint["artifacts"]["checker"]["source_sha"],
                },
            )
            endpoint["artifacts"]["checker"]["installed_manifest_sha256"] = sha(
                (root / "installed-manifest.json").read_bytes()
            )
            wheel = (
                b"provider-free synthetic wheel stand-in "
                + endpoint["artifacts"]["checker"]["source_sha"].encode()
            )
            (root / "checker.whl").write_bytes(wheel)
            endpoint["artifacts"]["checker"]["wheel_sha256"] = sha(wheel)
            source = io.BytesIO()
            with tarfile.open(fileobj=source, mode="w") as archive:
                content = (
                    b"synthetic source "
                    + endpoint["artifacts"]["checker"]["source_sha"].encode()
                )
                member = tarfile.TarInfo("source.txt")
                member.size = len(content)
                member.mtime = 0
                archive.addfile(member, io.BytesIO(content))
            (root / "source.tar").write_bytes(source.getvalue())
            write(
                root,
                "build-manifest.json",
                {
                    "synthetic": True,
                    "artifacts": endpoint["artifacts"],
                    "evaluator_sha": envelope["protected"]["evaluator_sha"],
                },
            )
            endpoint["sidecar"] = {
                key: sha((root / path).read_bytes())
                for key, path in [
                    ("build_manifest_sha256", "build-manifest.json"),
                    ("installed_manifest_sha256", "installed-manifest.json"),
                    ("source_archive_sha256", "source.tar"),
                ]
            }
            write(root, "sidecar.json", endpoint["sidecar"])
            write(root, "artifacts.json", endpoint["artifacts"])
            identity = dict(
                endpoint["header"],
                lane=envelope["lane"],
                corpus_hash=envelope["frozen_controls"]["dataset"],
                framework_sha=endpoint["artifacts"]["checker"]["source_sha"],
                raw_stream_sha256=sha(raw),
                raw_stream_bytes=len(raw),
                planned_collection_hash=endpoint["evidence"]["selected_sha256"],
                planned_count=len(selected),
                shard_id=stream["shard_id"],
            )
            write(root, "identity.json", identity)
            result = subprocess.run(
                [
                    str(evaluator / "evaluator-install/bin/python3"),
                    "-I",
                    "-B",
                    "-c",
                    PUBLIC,
                    str(root.resolve()),
                ],
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(evaluator / "home"),
                    "LD_LIBRARY_PATH": str(evaluator / "python/lib"),
                    "LANG": "C.UTF-8",
                },
                check=True,
                capture_output=True,
                text=True,
            )
            (root / "identity.json").unlink()
            endpoint["header"] = json.loads((root / "header.json").read_bytes())
            for key in ("ledger", "coverage", "raw_manifest", "obligations"):
                name = key.replace("_", "-") + (
                    ".jsonl" if key == "ledger" else ".json"
                )
                endpoint["evidence"][key + "_sha256"] = sha((root / name).read_bytes())
            observations[role] = {"files": rows(root), "streams": [stream]}
            provenance["cases"][axis + "/" + role] = json.loads(result.stdout)
        envelope["catalog_union"] = catalog
        envelope["selected_union"] = selected
        # Image/proxy unchanged checker installation must remain byte-identical.
        write(ROOT / axis, "envelope.json", envelope)
        write(
            ROOT / axis,
            "witness.json",
            {
                "schema_version": 1,
                "scope": "local-controller",
                "endpoints": observations,
            },
        )
    write(ROOT, "provenance.json", provenance)


if __name__ == "__main__":
    generate(Path(sys.argv[1]).resolve())

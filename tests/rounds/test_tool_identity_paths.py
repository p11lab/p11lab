"""W01 output paths stay portable without changing verified identity."""

from pathlib import Path

import pytest

from p11lab.round_core import inputs


def test_non_ascii_output_root_reaches_receipt_validation(tmp_path):
    root = tmp_path / "café-root"
    root.mkdir()
    (root / "evaluator-build-receipt.json").write_bytes(b"not json")
    with pytest.raises(ValueError) as error:
        inputs.verified_evaluator_identity(root)
    assert "unsafe W01 output path" not in str(error.value)


def test_output_root_allowlist_pins_tier1_boundary():
    from p11lab.round_core.tool_identity import _output_root_allowed

    allowed = [
        "/out/caf\u00e9",
        "/out/\u65e5\u672c\u8a9e",
        "/out/a~+%@:,.Z-9_",
        "/x/y.z_a-b/c+d~e@f%g:h,i",
    ]
    refused = [
        "/out/with space",
        "/out/tab\tx",
        "/out/new\nline",
        "/out/return\rx",
        "/out/nul\x00x",
        "/out/bell\x01x",
        "/out/del\x7fx",
        "/out/back\\slash",
        "relative/path",
        "",
        "/",
    ]
    for raw in allowed:
        assert _output_root_allowed(Path(raw)) is True, raw
    for raw in refused:
        assert _output_root_allowed(Path(raw)) is False, raw


def test_spaced_output_root_stays_refused(tmp_path):
    root = tmp_path / "with space"
    root.mkdir()
    (root / "evaluator-build-receipt.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="unsafe W01 output path"):
        inputs.verified_evaluator_identity(root)


def test_launcher_projection_is_stable_across_non_ascii_roots(tmp_path):
    import hashlib

    from p11lab.round_core.tool_identity import _command_arg, _inventory

    def row(root):
        path = root / "build-env/bin/tool"
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = b"#!" + str(root / "build-env/bin/python3").encode() + b"\nprint(1)\n"
        path.write_bytes(raw)
        return {
            "path": "build-env/bin/tool",
            "size": len(raw),
            "mode": 0o644,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    first = tmp_path / "root-a"
    second = tmp_path / "root-caf\u00e9"
    assert _inventory(first, [row(first)], "build-env") == _inventory(
        second, [row(second)], "build-env"
    )
    assert _command_arg(str(first / "x"), first) == _command_arg(
        str(second / "x"), second
    )


def test_record_round_trip_covers_non_ascii_root_launcher(tmp_path):
    import base64
    import hashlib

    from p11lab.round_core.tool_identity import _inventory

    def inspect(root):
        binary = root / "build-env/bin/tool"
        binary.parent.mkdir(parents=True)
        raw = (
            b"#!" + str(root / "build-env/bin/python3").encode() + b"\nprint(1)\n"
        )
        binary.write_bytes(raw)
        record = (
            root
            / "build-env/lib/python3.12/site-packages/tool-1.0.dist-info/RECORD"
        )
        record.parent.mkdir(parents=True)
        digest = "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(raw).digest()
        ).rstrip(b"=").decode()
        record.write_text(f"../../../bin/tool,{digest},{len(raw)}\n")
        rows = [
            {
                "path": str(item.relative_to(root)),
                "size": item.stat().st_size,
                "mode": 0o644,
                "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
            }
            for item in (binary, record)
        ]
        return _inventory(root, rows, "build-env")

    assert inspect(tmp_path / "a") == inspect(tmp_path / "caf\u00e9")

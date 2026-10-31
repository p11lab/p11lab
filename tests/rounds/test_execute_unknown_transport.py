"""Unknown-transport regression pins (joint re-check D2).

`execute.py` rejects unknown transports directly with ValueError
(usage error → CLI exit 2, no row) before any transport dispatch;
`prepare_inputs` carries its own identical check downstream. These
pins lock the direct-gate behavior and the no-artifacts property.
"""

import json
from pathlib import Path


def _write_context(path: Path, transport: str) -> Path:
    context_path = path / "context.json"
    context_path.write_text(json.dumps({"transport": transport,
                                         "tier": "pr-smoke"}))
    return context_path


def test_unknown_transport_raises_before_dispatch(tmp_path):
    from p11lab.rounds import execute

    context_path = _write_context(tmp_path, "bogus")
    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir()
    output_dir = tmp_path / "out"
    output_json = tmp_path / "row.json"
    try:
        execute(context_path, None, evaluator_root, output_dir,
                output_json, None)
    except ValueError as error:
        assert str(error) == "unknown transport"
    else:  # pragma: no cover - must raise
        raise AssertionError("unknown transport executed")
    assert not output_json.exists()
    assert list(output_dir.iterdir()) == []


def test_unknown_transport_cli_exits_2(tmp_path):
    from p11lab.cli import main

    context_path = _write_context(tmp_path, "bogus")
    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir()
    output_dir = tmp_path / "out"
    output_json = tmp_path / "row.json"
    assert main(["round", "execute", "--context", str(context_path),
                 "--evaluator-root", str(evaluator_root),
                 "--output-dir", str(output_dir),
                 "--output-json", str(output_json)]) == 2
    assert not output_json.exists()

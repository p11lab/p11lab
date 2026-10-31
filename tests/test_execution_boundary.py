"""M09 execution-boundary static pins (M07-INPUTS-M1 consequence).

Pins the codified host/test boundary in ``docs/execution-boundary.md``:
no ``shell=True`` call keywords and no ``eval``/``exec``/``__import__``
calls in ``src/p11lab``, and no DeprecationWarning-ignore filter in the
pytest config or test decorators. Static AST/config checks ONLY: no
Docker, network, or execution.

Method: ``ast.walk`` over every ``*.py`` file under ``src/p11lab``
(pins 1-2) and ``tests/`` (pin 3 decorators), plus a ``tomllib`` parse
of ``pyproject.toml`` ``[tool.pytest.ini_options]`` ``filterwarnings``
(pin 3 config). All scans are zero-tolerance: any site fails.
"""

import ast
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "p11lab"
TESTS = ROOT / "tests"
PYPROJECT = ROOT / "pyproject.toml"

# `round_core/bootstrap.py` carries a gate STRING-literal name set
# ({'getattr', 'setattr', 'vars', 'dir', 'eval', 'exec', '__import__'}) —
# data, not calls. Pin 2 walks Call funcs only, so that literal set is
# out of scope by construction and must stay a literal set.
_DYNAMIC_EXEC_NAMES = frozenset({"eval", "exec", "__import__"})

_FILTERWARNINGS_DECORATORS = frozenset(
    {"pytest.mark.filterwarnings", "mark.filterwarnings"}
)


def _parse(path):
    try:
        return ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        raise AssertionError("unparseable %s: %s" % (path, exc))


def shell_true_sites(src_dir=SRC):
    """Every ``shell=True`` call keyword under ``src_dir`` (H-ALLOW-3)."""
    sites = []
    for path in sorted(src_dir.rglob("*.py")):
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "shell":
                    continue
                value = keyword.value
                if isinstance(value, ast.Constant) and value.value is True:
                    sites.append("%s:%d" % (path, node.lineno))
    return sites


def test_no_shell_true_in_src():
    sites = shell_true_sites()
    assert not sites, "shell=True call sites: " + ", ".join(sites)


def dynamic_exec_sites(src_dir=SRC):
    """Every ``eval``/``exec``/``__import__`` call under ``src_dir``."""
    sites = []
    for path in sorted(src_dir.rglob("*.py")):
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in _DYNAMIC_EXEC_NAMES:
                sites.append("%s:%d" % (path, node.lineno))
    return sites


def test_no_dynamic_exec_in_src():
    sites = dynamic_exec_sites()
    assert not sites, "dynamic-exec call sites: " + ", ".join(sites)


def _is_deprecation_ignore(entry):
    action = entry.strip().split(":", 1)[0].strip().lower()
    return action == "ignore" and "deprecationwarning" in entry.lower()


def config_ignore_entries(pyproject_path=PYPROJECT):
    """DeprecationWarning-ignore entries in the pytest config (T-1)."""
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)
    tool = data.get("tool", {})
    pytest_cfg = tool.get("pytest", {}) if isinstance(tool, dict) else {}
    ini = pytest_cfg.get("ini_options", {}) if isinstance(pytest_cfg, dict) else {}
    entries = ini.get("filterwarnings", []) if isinstance(ini, dict) else []
    if isinstance(entries, str):
        entries = [entries]
    return [
        entry
        for entry in entries
        if isinstance(entry, str) and _is_deprecation_ignore(entry)
    ]


def _dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    parts.reverse()
    return ".".join(parts)


def decorator_ignore_sites(tests_dir=TESTS):
    """Tests decorated to ignore DeprecationWarning (T-1).

    Decorator-position matching only: the pin's own pattern strings live
    in this file's body, never in decorator position, so it cannot
    self-match.
    """
    sites = []
    for path in sorted(tests_dir.rglob("*.py")):
        for node in ast.walk(_parse(path)):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                if _dotted_name(decorator.func) not in _FILTERWARNINGS_DECORATORS:
                    continue
                values = [arg for arg in decorator.args]
                values.extend(kw.value for kw in decorator.keywords)
                strings = [
                    value.value
                    for value in values
                    if isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ]
                if any(_is_deprecation_ignore(text) for text in strings):
                    sites.append("%s:%d" % (path, decorator.lineno))
    return sites


def test_no_deprecation_warning_ignore():
    config_hits = config_ignore_entries()
    assert not config_hits, (
        "DeprecationWarning-ignore filterwarnings entries: "
        + ", ".join(config_hits)
    )
    decorator_hits = decorator_ignore_sites()
    assert not decorator_hits, (
        "DeprecationWarning-ignore decorators: " + ", ".join(decorator_hits)
    )

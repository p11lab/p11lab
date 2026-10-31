"""Offline candidate build/install/startup using the shared owned Docker lifecycle.

Candidate execution has no controller environment, Docker socket or upload path.
This Python wheel producer does not implement the sealed Rust/proxy build leg.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import gzip
import io
import json
from pathlib import Path
import shutil
import signal
import tarfile
import tempfile
import threading
import tomllib
from typing import Callable
from uuid import uuid4
import zipfile

from p11lab.docker import Docker, DockerError
from p11lab.models import ArtifactRef
from p11lab.process import supervised_exec
from . import JsonObject
from .bootstrap import inventory, sha256
from .evidence import (
    StoppedProducer,
    inspect_wheel,
    read_products,
    verify_candidate_product,
)
from .inputs import (
    FrozenCandidateContext,
    canonical,
    digest,
    read_source_archive,
    safe_path,
)

_SOURCE_LIMIT = 32 * 1024 * 1024


_SOURCE_STREAM_LIMIT = 40 * 1024 * 1024
_SOURCE_METADATA_LIMIT = 1024 * 1024
_SOURCE_METADATA_RECORD_LIMIT = 64 * 1024


def _pax_fields(raw: bytes) -> dict[str, str]:
    """Parse bounded ordinary Git/PAX metadata before tarfile can interpret it."""
    fields: dict[str, str] = {}
    offset = 0
    allowed = {
        "comment",
        "path",
        "linkpath",
        "mtime",
        "atime",
        "ctime",
        "uid",
        "gid",
        "uname",
        "gname",
        "hdrcharset",
    }
    while offset < len(raw):
        space = raw.find(b" ", offset, offset + 8)
        if space == -1 or not raw[offset:space].isdigit():
            raise ValueError("invalid source PAX metadata length")
        length = int(raw[offset:space])
        end = offset + length
        if (
            length <= space - offset + 1
            or end > len(raw)
            or raw[end - 1 : end] != b"\n"
        ):
            raise ValueError("invalid source PAX metadata record")
        key, separator, value = raw[space + 1 : end - 1].partition(b"=")
        name = key.decode("ascii")
        if name == "size":
            # Fixed tar headers cover every admitted payload size. PAX size
            # precedence across nested headers must never change frame offsets.
            raise ValueError("source PAX size metadata unsupported")
        if not separator or name not in allowed or name in fields:
            raise ValueError("unsupported/duplicate source PAX metadata")
        fields[name] = value.decode("utf-8")
        if name in {"path", "linkpath"} and len(value) > 4096:
            raise ValueError("source metadata path bound")
        offset = end
    return fields


def _tar_number(field: bytes) -> int:
    """Decode one fixed-width tar integer without invoking an archive parser."""
    if field[0] == 0x80:
        return int.from_bytes(field[1:], "big")
    value = field.strip(b"\0 ")
    if not value:
        return 0
    if any(byte < 48 or byte > 55 for byte in value):
        raise ValueError("invalid fixed source tar integer")
    return int(value, 8)


def _preflight_source_tar(raw: bytes) -> bytes:
    """Bound compressed/expanded bytes and frame metadata before generic parsing.

    Only plain/gzip tar and ordinary reviewed Git/PAX/GNU long-name metadata are
    supported. Sparse/unknown extensions and every PAX size key are rejected so the
    generic parser cannot enter payload bytes this frame pass did not inspect.
    """
    stream = (
        gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb")
        if raw.startswith(b"\x1f\x8b")
        else io.BytesIO(raw)
    )
    output = bytearray()
    counts = {"payload": 0, "metadata": 0, "records": 0, "extensions": 0}

    def read(size: int) -> bytes:
        if size > _SOURCE_STREAM_LIMIT - len(output):
            raise ValueError("source decompressed stream bound")
        content = bytearray()
        while len(content) < size:
            block = stream.read(min(65536, size - len(content)))
            if not block:
                break
            content.extend(block)
        output.extend(content)
        return bytes(content)

    try:
        while True:
            header = read(512)
            if len(header) != 512:
                raise ValueError("truncated source tar stream")
            if not any(header):
                # Tar padding/concatenated gzip members count toward total stream.
                while True:
                    remaining = _SOURCE_STREAM_LIMIT - len(output)
                    block = stream.read(min(65536, remaining + 1))
                    if not block:
                        break
                    if len(block) > remaining:
                        raise ValueError("source decompressed stream bound")
                    if any(block):
                        raise ValueError("nonzero source tar trailing stream")
                    output.extend(block)
                break
            counts["records"] += 1
            if counts["records"] > 10000:
                raise ValueError("source tar record bound")
            try:
                size = _tar_number(header[124:136])
                checksum = _tar_number(header[148:156])
                checksum_bytes = header[:148] + b" " * 8 + header[156:]
                valid_checksums = (
                    sum(checksum_bytes),
                    sum(byte if byte < 128 else byte - 256 for byte in checksum_bytes),
                )
            except ValueError as error:
                raise ValueError("invalid fixed source tar header") from error
            if size < 0 or checksum not in valid_checksums:
                raise ValueError("invalid fixed source tar header")
            kind = header[156:157]
            if kind in (b"x", b"g", b"L", b"K"):
                counts["metadata"] += size
                counts["extensions"] += 1
                if (
                    size > _SOURCE_METADATA_RECORD_LIMIT
                    or counts["metadata"] > _SOURCE_METADATA_LIMIT
                    or counts["extensions"] > 8
                ):
                    raise ValueError("source extended metadata bound")
            elif kind in (b"0", b"\0", b"5"):
                counts["extensions"] = 0
                if kind == b"5" and size:
                    raise ValueError("source directory payload")
                counts["payload"] += size
                if counts["payload"] > _SOURCE_LIMIT:
                    raise ValueError("source payload bound")
            else:
                raise ValueError("unsafe source tar type/link")
            payload = read((size + 511) // 512 * 512)
            if len(payload) != (size + 511) // 512 * 512:
                raise ValueError("truncated source tar payload")
            if kind in (b"x", b"g"):
                _pax_fields(payload[:size])
            elif kind in (b"L", b"K") and size > 4096:
                raise ValueError("source metadata long-name bound")
    finally:
        stream.close()
    return bytes(output)


def _source_content(archive: Path | bytes) -> list[tuple[str, bytes, int]]:
    raw = read_source_archive(archive) if isinstance(archive, Path) else archive
    expanded = _preflight_source_tar(raw)
    total = 0
    result = []
    names: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as bundle:
        for member in bundle:
            name = safe_path(member.name.removesuffix("/"))
            if name in names or len(names) >= 10000 or ".git" in Path(name).parts:
                raise ValueError("duplicate/excess/unsafe source membership")
            names.add(name)
            if member.isdir():
                continue
            if not member.isfile() or member.mode not in (0o400, 0o444, 0o644, 0o755):
                raise ValueError("unsafe source type/link/mode")
            total += member.size
            if total > _SOURCE_LIMIT:
                raise ValueError("source expansion bound")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError("missing source bytes")
            with stream:
                content = stream.read(_SOURCE_LIMIT + 1)
            if len(content) != member.size:
                raise ValueError("source size mismatch")
            result.append((name, content, member.mode))
    result.sort()
    if not result:
        raise ValueError("empty source archive")
    return result


def _source_members(content: list[tuple[str, bytes, int]]) -> tuple[bytes, ...]:
    return tuple(
        canonical(
            {
                "path": p,
                "sha256": hashlib.sha256(b).hexdigest(),
                "size": len(b),
                "mode": m,
            }
        )
        for p, b, m in content
    )


def inspect_source_archive(archive: Path) -> tuple[bytes, ...]:
    """Produce bounded exact source membership before backend metadata."""
    return _source_members(_source_content(archive))


def _source_tree_from_content(files: list[tuple[str, bytes, int]]) -> str:
    tree: dict = {}
    for name, content, mode in files:
        parts = name.split("/")
        directory = tree
        for part in parts[:-1]:
            child = directory.setdefault(part, {})
            if not isinstance(child, dict):
                raise ValueError("source file/directory collision")
            directory = child
        if parts[-1] in directory:
            raise ValueError("source path collision")
        blob = hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\0" + content
        ).digest()
        directory[parts[-1]] = (b"100755" if mode & 0o111 else b"100644", blob)

    def encode(directory: dict) -> bytes:
        items = []
        for name, value in directory.items():
            mode, oid = (b"40000", encode(value)) if isinstance(value, dict) else value
            items.append(
                (
                    name.encode() + (b"/" if mode == b"40000" else b""),
                    mode + b" " + name.encode() + b"\0" + oid,
                )
            )
        content = b"".join(row for _, row in sorted(items))
        return hashlib.sha1(
            b"tree " + str(len(content)).encode() + b"\0" + content
        ).digest()

    return encode(tree).hex()


def source_tree(archive: Path) -> str:
    """Reconstruct a Git tree from one bounded immutable archive snapshot."""
    return _source_tree_from_content(_source_content(archive))


@dataclass(frozen=True)
class SandboxPolicy:
    wheel_filename: str
    build_reports: tuple[str, ...] = ()
    startup_reports: tuple[str, ...] = ()
    timeout_seconds: int = 60
    max_output_bytes: int = 96 * 1024 * 1024

    def validate(self) -> None:
        if safe_path(self.wheel_filename) != Path(
            self.wheel_filename
        ).name or not self.wheel_filename.endswith(".whl"):
            raise ValueError("invalid selected wheel filename")
        for roster in (self.build_reports, self.startup_reports):
            if len(roster) != len(set(roster)) or len(roster) > 32:
                raise ValueError("invalid report roster")
            for name in roster:
                if safe_path(name) != Path(name).name or not name.endswith(".json"):
                    raise ValueError("invalid report name")
        if (
            type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 300
            or type(self.max_output_bytes) is not int
            or not 1024 <= self.max_output_bytes <= 128 * 1024 * 1024
        ):
            raise ValueError("invalid sandbox bounds")


# This trusted driver is shipped with the producer. All candidate backend, pip
# installation, .pth site processing and startup execute only inside Docker.
_DRIVER = r"""import json,os,resource,subprocess,sys
from pathlib import Path
phase=sys.argv[1]
ctx=json.loads(Path('/inputs/context.json').read_bytes())
resource.setrlimit(resource.RLIMIT_FSIZE,(ctx['policy']['max_output_bytes'],ctx['policy']['max_output_bytes']))
python='/inputs/python/bin/python3'
env={'PATH':'/usr/bin:/bin','HOME':'/scratch/home','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
     'LD_LIBRARY_PATH':'/inputs/python/lib','PYTHONDONTWRITEBYTECODE':'1',
     'PIP_CONFIG_FILE':'/dev/null','PIP_DISABLE_PIP_VERSION_CHECK':'1','PIP_NO_INPUT':'1',
     'SOURCE_DATE_EPOCH':str(ctx['source_date_epoch'])}
def call(args):
    # Inherit pipes: host capture drains continuously with bounded retention.
    result=subprocess.run(args,env=env,check=False)
    if result.returncode: raise SystemExit(result.returncode)
call([python,'-I','-B','-m','venv','--without-pip','/scratch/env'])
venv='/scratch/env/bin/python3'
if phase=='startup':
    site=Path('/scratch/env/lib/python3.12/site-packages')
    site.mkdir(parents=True,exist_ok=True)
    (site/'protected-producer.pth').write_text("import site; site.addsitedir('/installed/site')\n")
    call([venv,'-I','-B','-c',"print('candidate site startup completed',flush=True)"])
else:
    bootstrap="import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
    pip=next(w['filename'] for w in ctx['tools']['wheels'] if w['name']=='pip')
    call([venv,'-I','-B','-c',bootstrap,'/inputs/wheels/'+pip,'install','--no-index','--no-compile',
          '--find-links','/inputs/wheels','--require-hashes','-r','/inputs/build.lock'])
    if phase=='build':
        call([venv,'-I','-B','-m','build','--wheel','--no-isolation','--outdir','/out','/inputs/source'])
    elif phase=='install':
        call([venv,'-I','-B','-m','pip','install','--no-index','--no-deps','--no-compile',
              '--target','/out/site','/product/'+ctx['policy']['wheel_filename']])
    else: raise SystemExit('unknown protected stage')
"""


def check_startup_diagnostics(stderr: str, *, stderr_truncated: bool = False) -> None:
    """Reject sealed CPython's caught .pth errors, retaining native RC/logs.

    CPython 3.12 site prints these diagnostics and can still exit zero. A bounded
    prefix is incomplete evidence when truncated, even if it contains no marker.
    This observes native startup failures; it does not attest honest candidate code.
    """
    if stderr_truncated:
        raise ValueError("candidate installed site processing evidence incomplete")
    if "Error processing line " in stderr or "Remainder of file ignored" in stderr:
        raise ValueError(
            "candidate installed site processing failed: native .pth diagnostic"
        )


def _stage(context: FrozenCandidateContext, root: Path, policy: SandboxPolicy) -> None:
    value = context.as_dict()
    if (
        list(context.tools.requirements) != value["tools"]["requirements"]
        or context.tools.receipt_sha256 != value["tools"]["receipt_sha256"]
        or list(context.tools.python_members)
        != [canonical(r) for r in value["tools"]["python_members"]]
        or list(context.tools.wheels)
        != [canonical(r) for r in value["tools"]["wheels"]]
    ):
        raise ValueError("sealed tool context drift")
    # One bounded controller-owned immutable snapshot feeds every source check
    # and materialization; caller path replacement cannot change executed bytes.
    snapshot = read_source_archive(context.source.archive)
    if hashlib.sha256(snapshot).hexdigest() != value["source"]["archive_sha256"]:
        raise ValueError("actual source archive mismatch")
    content = _source_content(snapshot)
    members = _source_members(content)
    if (
        list(context.source.members)
        != [canonical(r) for r in value["source"]["members"]]
        or members != context.source.members
        or _source_tree_from_content(content) != value["source"]["tree"]
    ):
        raise ValueError("actual source tree/membership mismatch")
    source = root / "source"
    source.mkdir()
    source.chmod(0o755)
    for name, data, mode in content:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    for directory in source.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)
    final_members = read_products(
        source,
        tuple(row["path"] for row in value["source"]["members"]),
        max_bytes=_SOURCE_LIMIT,
    )
    if [canonical(row) for row in final_members] != list(members):
        raise ValueError("materialized source membership/bytes/modes mismatch")
    metadata = tomllib.loads((source / "pyproject.toml").read_text())
    build = metadata.get("build-system")
    if type(build) is not dict or set(build) - {
        "requires",
        "build-backend",
        "backend-path",
    }:
        raise ValueError("unknown candidate build metadata")
    requirements = build.get("requires")
    if type(requirements) is not list or any(
        type(r) is not str or r not in context.tools.requirements for r in requirements
    ):
        raise ValueError("unsealed build requirements")
    if type(build.get("build-backend")) is not str:
        raise ValueError("missing build backend")
    backend_paths = build.get("backend-path", [])
    if type(backend_paths) is not list:
        raise ValueError("invalid backend path roster")
    for backend_path in backend_paths:
        if backend_path != ".":
            safe_path(backend_path)
    # Copies eliminate external writer aliases. Internal portable-Python symlinks
    # are permitted only within its sealed closure; source/output links are not.
    shutil.copytree(context.tools.root / "python", root / "python", symlinks=True)
    for path in (root / "python").rglob("*"):
        if path.is_symlink() and not path.resolve().is_relative_to(
            (root / "python").resolve()
        ):
            raise ValueError("sealed Python link escapes closure")
    if inventory(root, root / "python") != value["tools"]["python_members"]:
        raise ValueError("sealed Python inventory mismatch")
    # Host directories may carry private workspace ACL/modes. File bytes/modes
    # remain sealed; directory traversal is explicit for the distinct sandbox UID.
    (root / "python").chmod(0o755)
    for directory in (root / "python").rglob("*"):
        if directory.is_dir() and not directory.is_symlink():
            directory.chmod(0o755)
    wheels = root / "wheels"
    wheels.mkdir()
    specs = value["tools"]["wheels"]
    if len(specs) != len({w["filename"] for w in specs}) or not any(
        w["name"] == "pip" for w in specs
    ):
        raise ValueError("sealed wheel roster")
    for spec in specs:
        filename = safe_path(spec["filename"])
        if Path(filename).name != filename:
            raise ValueError("unsafe sealed wheel filename")
        original = context.tools.root / "downloads/build-wheels" / filename
        shutil.copyfile(original, wheels / filename)
        if (
            sha256(wheels / filename) != spec["sha256"]
            or (wheels / filename).stat().st_size != spec["size"]
        ):
            raise ValueError("sealed wheel bytes mismatch")
    if hashlib.sha256(context.tools.lock).hexdigest() != value["tools"]["lock_sha256"]:
        raise ValueError("sealed lock mismatch")
    (root / "build.lock").write_bytes(context.tools.lock)
    # Lock and wheel inventory must be the exact same reviewed dependency roster.
    wanted = "".join(
        f"{w['name']}=={w['version']} --hash=sha256:{w['sha256']}\n" for w in specs
    ).encode()
    if [
        line
        for line in context.tools.lock.splitlines()
        if line and not line.startswith(b"#")
    ] != wanted.splitlines():
        raise ValueError("sealed dependency lock/roster mismatch")
    (root / "driver.py").write_text(_DRIVER)
    (root / "context.json").write_bytes(canonical({**value, "policy": asdict(policy)}))
    root.chmod(0o755)


def _inspection(engine: Docker, identity: str, labels: dict[str, str]) -> JsonObject:
    values = json.loads(engine.command(["container", "inspect", identity]).stdout)
    result: JsonObject = values[0]
    if result.get("Id") != identity or any(
        result.get("Config", {}).get("Labels", {}).get(k) != v
        for k, v in labels.items()
    ):
        raise DockerError("candidate ownership inspection mismatch")
    return result


def _installed_roster(wheel: Path) -> tuple[str, ...]:
    with zipfile.ZipFile(wheel) as archive:
        names = [i.filename for i in archive.infolist() if not i.is_dir()]
        if any(".data/" in n for n in names):
            raise ValueError("wheel data relocation needs a reviewed producer contract")
        metadata = next(
            n.rsplit("/", 1)[0] for n in names if n.endswith(".dist-info/METADATA")
        )
        paths = set(names) | {
            metadata + "/" + n for n in ("INSTALLER", "REQUESTED", "direct_url.json")
        }
        entrypoints = metadata + "/entry_points.txt"
        if entrypoints in names:
            import configparser

            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(archive.read(entrypoints).decode())
            for section in ("console_scripts", "gui_scripts"):
                for script in parser[section] if parser.has_section(section) else ():
                    if safe_path(script) != Path(script).name:
                        raise ValueError("unsafe wheel script name")
                    paths.add("bin/" + script)
    return tuple(sorted("site/" + n for n in paths))


def _verify_installed(wheel: Path, root: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            if member.is_dir() or member.filename.endswith(".dist-info/RECORD"):
                continue
            if hashlib.sha256(archive.read(member)).hexdigest() != sha256(
                root / "site" / member.filename
            ):
                raise ValueError("installed bytes differ from frozen wheel")


def readback_tar(
    raw: bytes, destination: Path, expected_paths: tuple[str, ...], *, max_bytes: int
) -> None:
    """Validate the complete bounded Docker-copy tar before writing any member."""
    if len(raw) > max_bytes + 16 * 1024 * 1024:
        raise ValueError("readback tar byte bound")
    files: list[tuple[str, bytes, int]] = []
    directories: set[str] = set()
    names: set[str] = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            if member.name in (".", "./") and member.isdir():
                continue
            name = safe_path(member.name.removeprefix("./").removesuffix("/"))
            if name in names or len(names) >= 10000 or len(Path(name).parts) > 32:
                raise ValueError("duplicate/excess readback roster")
            names.add(name)
            if member.isdir():
                if member.mode & 0o7000:
                    raise ValueError("unsafe output directory mode")
                directories.add(name)
                continue
            if not member.isfile() or member.mode not in (0o444, 0o644, 0o555, 0o755):
                raise ValueError("unsafe output type/link/mode")
            total += member.size
            if total > max_bytes:
                raise ValueError("output byte bound")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("missing readback bytes")
            with stream:
                content = stream.read(max_bytes + 1)
            if len(content) != member.size:
                raise ValueError("readback size mismatch")
            files.append((name, content, member.mode))
    if sorted(p for p, _, _ in files) != sorted(expected_paths):
        raise ValueError("output roster mismatch")
    wanted_dirs = {
        str(p) for name in expected_paths for p in Path(name).parents if str(p) != "."
    }
    if directories != wanted_dirs:
        raise ValueError("output directory roster mismatch")
    if (
        destination.is_symlink()
        or not destination.is_dir()
        or any(destination.iterdir())
    ):
        raise ValueError("readback requires an empty owned destination")
    destination.chmod(0o755)
    for directory in sorted(wanted_dirs, key=lambda name: len(Path(name).parts)):
        path = destination / directory
        path.mkdir(exist_ok=True)
        path.chmod(0o755)
    # All aliases/types/rosters/lengths were checked before the first write.
    for name, content, mode in files:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
        path.chmod(mode)


class _OutputVolume:
    """Owned hard-limited tmpfs; a trusted sleeper retains it after candidate stop."""

    def __init__(
        self,
        engine: Docker,
        image: str,
        labels: dict[str, str],
        name: str,
        max_bytes: int,
        record: JsonObject,
    ):
        self.engine, self.image, self.labels = engine, image, labels
        self.name, self.max_bytes, self.record = name, max_bytes, record
        self.volume: str | None = None
        self.holder: str | None = None

    def open(self) -> None:
        options = {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": f"size={self.max_bytes},nr_inodes=10000,mode=1777,uid=65532,gid=65532",
        }
        args = ["volume", "create", "--name", self.name, "--driver", "local"]
        for key, value in self.labels.items():
            args += ["--label", key + "=" + value]
        for key, value in options.items():
            args += ["--opt", key + "=" + value]
        try:
            if self.engine.command(args).stdout.strip() != self.name:
                raise DockerError("unexpected candidate volume identity")
            self.volume = self.name
        except (DockerError, OSError) as error:
            recovery = self.engine._creation_failure("volume", self.name, self.labels)
            if recovery.resource:
                self.volume = recovery.resource[1]
            self.record["uncertain_resource"] = recovery.uncertain_resource
            raise recovery from error
        observed = json.loads(
            self.engine.command(["volume", "inspect", self.name]).stdout
        )[0]
        self.record["volume_inspection"] = observed
        if (
            observed.get("Name") != self.name
            or observed.get("Driver") != "local"
            or observed.get("Options") != options
            or any(
                observed.get("Labels", {}).get(k) != v for k, v in self.labels.items()
            )
        ):
            raise DockerError("candidate tmpfs quota/ownership mismatch")
        holder_options = [
            "--pull=never",
            "--user",
            "65532:65532",
            "--read-only",
            "--network",
            "none",
            "--ipc",
            "private",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            "4",
            "--memory",
            "16m",
            "--memory-swap",
            "16m",
            "--cpus",
            "0.1",
            "--log-driver",
            "none",
            "--mount",
            f"type=volume,src={self.name},dst=/out,readonly",
            "--entrypoint",
            "/bin/sleep",
        ]
        try:
            self.holder = self.engine.create(
                self.image, ["600"], holder_options, self.labels, self.name + "-holder"
            )
        except DockerError as error:
            if error.resource and error.resource[0] == "container":
                self.holder = error.resource[1]
            self.record["uncertain_resource"] = error.uncertain_resource
            raise
        self.record["holder_id"] = self.holder
        before = _inspection(self.engine, self.holder, self.labels)
        self.record["holder_inspection"] = before
        if (
            before.get("Image") != self.image
            or before.get("Config", {}).get("User") != "65532:65532"
            or before.get("Config", {}).get("Entrypoint") != ["/bin/sleep"]
            or before.get("HostConfig", {}).get("PidMode") not in ("", "private")
        ):
            raise DockerError("untrusted output holder configuration")
        self.engine.command(["start", self.holder])

    def readback(
        self,
        destination: Path,
        expected: tuple[str, ...],
        interrupted: Callable[[], int | None],
    ) -> None:
        if self.holder is None:
            raise DockerError("missing owned output holder")
        holder = _inspection(self.engine, self.holder, self.labels)
        if holder.get("State", {}).get("Running") is not True:
            raise DockerError("trusted output holder stopped before readback")
        limit = self.max_bytes + 16 * 1024 * 1024
        status, timed_out, owner, facts = supervised_exec(
            ["docker", "cp", self.holder + ":/out/.", "-"],
            cwd=destination,
            env=self.engine.env,
            timeout=15,
            interrupted=interrupted,
            limit=limit,
        )
        raw = bytes(owner.capture.buffers[0])
        self.record["readback"] = {
            "returncode": status,
            "timed_out": timed_out,
            **facts,
            "raw_size": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "stderr": bytes(owner.capture.buffers[1])[:65536].decode(
                "utf-8", "replace"
            ),
        }
        (destination.parent / (destination.name + "-output.tar")).write_bytes(raw)
        if (
            status
            or timed_out
            or facts["stdout_truncated"]
            or facts["stderr_truncated"]
            or facts["supervision_errors"]
            or facts["stragglers_remaining"]
            or not facts["drain_complete"]
        ):
            raise DockerError("bounded candidate output copy failed")
        readback_tar(raw, destination, expected, max_bytes=self.max_bytes)

    def close(self) -> list[str]:
        errors = []
        if self.holder:
            try:
                self.engine.stop(self.holder, self.labels)
                self.record["holder_stopped"] = _inspection(
                    self.engine, self.holder, self.labels
                )
            except Exception as error:
                errors.append("output holder stop: " + str(error))
            try:
                self.engine.remove("container", self.holder, self.labels)
                self.record["holder_cleanup"] = "removed-exact-owned-container"
                self.holder = None
            except Exception as error:
                errors.append("output holder remove: " + str(error))
        if self.volume:
            try:
                self.engine.remove("volume", self.volume, self.labels)
                self.record["volume_cleanup"] = "removed-exact-owned-volume"
                self.volume = None
            except Exception as error:
                errors.append("output volume remove: " + str(error))
        return errors


def produce_candidate(
    frozen_context: FrozenCandidateContext,
    sandbox_policy: SandboxPolicy,
    output_dir: Path,
    *,
    engine: Docker | None = None,
    interrupted: Callable[[], int | None] | None = None,
) -> JsonObject:
    """Produce an untrusted wheel and installed closure under protected local control.

    Every attempt needs a fresh output directory. Failures retain bounded logs and
    exact cleanup outcomes; no retry, upload, provider verdict or CI authority.
    """
    if (
        type(frozen_context) is not FrozenCandidateContext
        or type(sandbox_policy) is not SandboxPolicy
    ):
        raise TypeError("typed frozen context and sandbox policy required")
    policy = sandbox_policy
    policy.validate()
    output_dir = output_dir.absolute()
    output_dir.mkdir(parents=True, exist_ok=False)
    engine = engine or Docker()
    value = frozen_context.as_dict()
    context_hash = hashlib.sha256(frozen_context.serialized).hexdigest()
    result: JsonObject = {
        "schema_version": 1,
        "scope": "local-controller",
        "context_sha256": context_hash,
        "status": "incomplete",
        "stages": [],
        "cleanup_errors": [],
        "qualification": False,
    }
    (output_dir / "protected-context.json").write_bytes(frozen_context.serialized)
    nonce = uuid4().hex
    labels = {"p11lab.candidate": nonce, "p11lab.context": context_hash}
    owned: str | None = None
    output_sandbox: _OutputVolume | None = None
    stop_state: dict[str, int | None] = {"signal": None}
    old_handlers: dict = {}

    def receive(signum: int, frame: object) -> None:
        stop_state["signal"] = stop_state["signal"] or signum

    def cancelled() -> int | None:
        return stop_state["signal"] or (interrupted() if interrupted else None)

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, receive)
    stage_root = Path(tempfile.mkdtemp(prefix="p11lab-candidate-"))
    try:
        _stage(frozen_context, stage_root, policy)
        original_names = [
            "context.json",
            *("source/" + row["path"] for row in value["source"]["members"]),
        ]
        originals = {name: sha256(stage_root / name) for name in original_names}
        result["protected_originals_before"] = originals
        artifact = ArtifactRef(
            "image",
            value["builder"]["image"],
            value["builder"]["image"][7:],
            "linux/amd64",
        )
        image = engine.image(artifact)
        if digest(image.get("Config")) != value["builder"]["config_sha256"]:
            raise ValueError("builder config identity mismatch")
        if image.get("RootFS", {}).get("Layers") != value["builder"][
            "layers"
        ] or image.get("Config", {}).get("Volumes"):
            raise ValueError("builder layer identity/implicit volume mismatch")
        # Docker preserves image ENV even with --env additions. Only inert base
        # metadata is permitted; executable-path and credential variables fail.
        if any(
            e.split("=", 1)[0] not in {"PATH", "LANG", "LC_ALL", "TZ"}
            for e in image.get("Config", {}).get("Env", [])
        ):
            raise ValueError("unreviewed inherited builder environment")
        result["builder_inspection"] = image
        wheel = output_dir / "build" / policy.wheel_filename
        installed_manifest: list[JsonObject] | None = None
        for phase in ("build", "install", "startup"):
            if cancelled():
                raise InterruptedError("candidate attempt cancelled")
            product = output_dir / phase
            product.mkdir(mode=0o755)
            record: JsonObject = {
                "phase": phase,
                "name": "p11lab-candidate-" + nonce + "-" + phase,
            }
            result["stages"].append(record)
            output_sandbox = _OutputVolume(
                engine,
                artifact.reference,
                labels,
                record["name"] + "-output",
                policy.max_output_bytes,
                record,
            )
            output_sandbox.open()
            options = [
                "--pull=never",
                "--user",
                "65532:65532",
                "--read-only",
                "--network",
                "none",
                "--ipc",
                "private",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges=true",
                "--pids-limit",
                "64",
                "--memory",
                "384m",
                "--memory-swap",
                "384m",
                "--cpus",
                "1",
                "--ulimit",
                "nofile=256:256",
                "--log-driver",
                "none",
                "--workdir",
                "/scratch",
                "--tmpfs",
                "/scratch:rw,nosuid,nodev,mode=1777,size=192m",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=16m",
                "--env",
                "HOME=/scratch/home",
                "--env",
                "PATH=/usr/bin:/bin",
                "--env",
                "LANG=C.UTF-8",
                "--env",
                "LD_LIBRARY_PATH=/inputs/python/lib",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--mount",
                f"type=bind,src={stage_root},dst=/inputs,readonly",
                "--mount",
                f"type=volume,src={output_sandbox.name},dst=/out",
                "--entrypoint",
                "/inputs/python/bin/python3",
            ]
            if phase == "install":
                options += [
                    "--mount",
                    f"type=bind,src={wheel.parent},dst=/product,readonly",
                ]
            if phase == "startup":
                # Independent second hash immediately before immutable installation mount.
                if (
                    read_products(
                        output_dir / "install",
                        tuple(r["path"] for r in installed_manifest or []),
                        max_bytes=policy.max_output_bytes,
                    )
                    != installed_manifest
                ):
                    raise ValueError("installed bytes drift before startup")
                options += [
                    "--mount",
                    f"type=bind,src={output_dir / 'install'},dst=/installed,readonly",
                ]
            try:
                owned = engine.create(
                    artifact.reference,
                    ["-I", "-B", "/inputs/driver.py", phase],
                    options,
                    labels,
                    record["name"],
                )
            except DockerError as error:
                if error.resource and error.resource[0] == "container":
                    owned = error.resource[1]
                record["uncertain_resource"] = error.uncertain_resource
                raise
            record["container_id"] = owned
            record["inspect_before"] = _inspection(engine, owned, labels)
            if record["inspect_before"].get("HostConfig", {}).get("PidMode") not in (
                "",
                "private",
            ):
                raise DockerError("candidate PID namespace is not private")
            execution = engine.execute(owned, policy.timeout_seconds, cancelled)
            record["execution"] = asdict(execution)
            # Docker CLI timeout is insufficient. Stop exactly owned cgroup before
            # reading a single candidate byte, then independently inspect PID=0.
            engine.stop(owned, labels)
            stopped = _inspection(engine, owned, labels)
            record["inspect_stopped"] = stopped
            if stopped["State"]["Running"] or stopped["State"]["Pid"] != 0:
                raise DockerError("candidate still running before readback")
            record["stopped_before_readback"] = True
            if execution.returncode or execution.timed_out or cancelled():
                raise ValueError("candidate execution failed/timeout/cancelled")
            if phase == "startup":
                check_startup_diagnostics(
                    execution.stderr,
                    stderr_truncated=execution.stdout_truncated
                    or execution.stderr_truncated,
                )
            if execution.stdout_truncated or execution.stderr_truncated:
                raise ValueError("candidate log limit exceeded")
            expected = (
                (policy.wheel_filename, *policy.build_reports)
                if phase == "build"
                else _installed_roster(wheel)
                if phase == "install"
                else policy.startup_reports
            )
            witness = StoppedProducer(
                context_hash,
                owned,
                tuple(labels.items()),
                canonical(stopped),
                tuple(expected),
                policy.max_output_bytes,
            )
            output_sandbox.readback(product, tuple(expected), cancelled)
            record["product"] = verify_candidate_product(
                frozen_context, product, witness
            )
            if phase == "build":
                record["wheel_metadata"] = inspect_wheel(
                    wheel, sealed_requirements=frozen_context.tools.requirements
                )
            if phase == "install":
                _verify_installed(wheel, product)
                installed_manifest = record["product"]["files"]
            engine.remove("container", owned, labels)
            record["cleanup"] = "removed-exact-owned-container"
            owned = None
            result["cleanup_errors"].extend(output_sandbox.close())
            output_sandbox = None
            if result["cleanup_errors"]:
                raise DockerError("candidate output cleanup incomplete")
        result["status"] = "produced"
    except (Exception, KeyboardInterrupt) as error:
        result["error"] = type(error).__name__ + ": " + str(error)
        result["status"] = "infrastructure-error"
    finally:
        if owned:
            try:
                engine.stop(owned, labels)
                result["terminal_inspection"] = _inspection(engine, owned, labels)
            except Exception as error:
                result["cleanup_errors"].append("stop: " + str(error))
            try:
                engine.remove("container", owned, labels)
                result["terminal_cleanup"] = "removed-exact-owned-container"
            except Exception as error:
                result["cleanup_errors"].append("remove: " + str(error))
        if output_sandbox is not None:
            result["cleanup_errors"].extend(output_sandbox.close())
        if "protected_originals_before" in result:
            result["protected_originals_after"] = {
                n: sha256(stage_root / n) for n in result["protected_originals_before"]
            }
            if (
                result["protected_originals_after"]
                != result["protected_originals_before"]
            ):
                result["status"] = "infrastructure-error"
                result["error"] = "protected controller originals changed"
        shutil.rmtree(stage_root)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        if result["cleanup_errors"]:
            result["status"] = "infrastructure-error"
        result["interrupted_signal"] = cancelled()
        (output_dir / "producer-observation.json").write_bytes(
            canonical(result) + b"\n"
        )
    return result

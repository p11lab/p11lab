"""Bounded inert inspection of candidate-produced bytes, after owned execution stops."""

from __future__ import annotations

from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import os
from pathlib import Path
import stat
import zipfile

from . import JsonObject
from .inputs import FrozenCandidateContext, digest, load_json, safe_path


@dataclass(frozen=True)
class StoppedProducer:
    """Controller witness; candidate JSON is never accepted as this witness."""

    context_sha256: str
    container_id: str
    labels: tuple[tuple[str, str], ...]
    inspection: bytes
    expected_paths: tuple[str, ...]
    max_bytes: int


def read_products(
    root: Path,
    expected_paths: tuple[str, ...] | None,
    *,
    max_bytes: int = 96 * 1024 * 1024,
    max_files: int = 10000,
) -> list[JsonObject]:
    """Read regular single-link files only; reject aliases, special files and drift."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe output root")
    rows: list[JsonObject] = []
    counts = {"bytes": 0, "entries": 0}
    directories: set[str] = set()

    def visit(directory: Path, depth: int) -> None:
        if depth > 32:
            raise ValueError("output depth bound")
        with os.scandir(directory) as entries:
            for entry in entries:
                counts["entries"] += 1
                if counts["entries"] > max_files:
                    raise ValueError("output roster bound")
                path = Path(entry.path)
                name = safe_path(path.relative_to(root).as_posix())
                details = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(details.st_mode):
                    directories.add(name)
                    if details.st_mode & 0o7000:
                        raise ValueError("unsafe directory mode")
                    visit(path, depth + 1)
                    continue
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_nlink != 1
                    or details.st_mode & 0o7000
                ):
                    raise ValueError("unsafe output type/link/mode")
                counts["bytes"] += details.st_size
                if counts["bytes"] > max_bytes or len(rows) >= max_files:
                    raise ValueError("output byte/roster bound")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    actual = os.fstat(stream.fileno())
                    if (
                        actual.st_ino != details.st_ino
                        or actual.st_dev != details.st_dev
                        or not stat.S_ISREG(actual.st_mode)
                    ):
                        raise ValueError("output changed during readback")
                    value = hashlib.file_digest(stream, "sha256").hexdigest()
                rows.append(
                    {
                        "path": name,
                        "size": details.st_size,
                        "mode": stat.S_IMODE(details.st_mode),
                        "sha256": value,
                    }
                )

    visit(root, 0)
    rows.sort(key=lambda r: r["path"])
    if expected_paths is not None and [r["path"] for r in rows] != sorted(
        expected_paths
    ):
        raise ValueError("output roster mismatch")
    if expected_paths is not None:
        wanted_directories = {
            str(parent)
            for name in expected_paths
            for parent in Path(name).parents
            if str(parent) != "."
        }
        if directories != wanted_directories:
            raise ValueError("output directory roster mismatch")
    return rows


def inspect_wheel(
    path: Path,
    *,
    max_bytes: int = 32 * 1024 * 1024,
    sealed_requirements: tuple[str, ...] = (),
) -> JsonObject:
    """Parse ZIP and package metadata as data, without backend/import/installation."""
    total = 0
    names: set[str] = set()
    metadata = []
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            name = safe_path(member.filename.removesuffix("/"))
            if name in names or len(names) >= 10000:
                raise ValueError("duplicate/excess wheel member")
            names.add(name)
            mode = member.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (
                kind not in (0, stat.S_IFREG, stat.S_IFDIR)
                or mode & 0o7000
                or member.flag_bits & 1
            ):
                raise ValueError("unsafe wheel member type/mode")
            total += member.file_size
            if total > max_bytes:
                raise ValueError("wheel expansion bound")
            if member.is_dir():
                continue
            with archive.open(member) as stream:
                content = stream.read(max_bytes + 1)
                if len(content) != member.file_size:
                    raise ValueError("wheel size mismatch")
            if name.endswith(".dist-info/METADATA"):
                metadata.append(BytesParser().parsebytes(content))
        if len(metadata) != 1:
            raise ValueError("wheel metadata roster")
        package = metadata[0]
        if not package.get("Name") or not package.get("Version"):
            raise ValueError("missing wheel metadata")
        requirements = package.get_all("Requires-Dist", [])
        if any(requirement not in sealed_requirements for requirement in requirements):
            raise ValueError("unsealed runtime requirement")
    return {
        "name": package["Name"],
        "version": package["Version"],
        "members": sorted(names),
        "requires_dist": requirements,
        "expanded_bytes": total,
    }


def verify_candidate_product(
    frozen_context: FrozenCandidateContext,
    product_paths: Path,
    producer_observation: StoppedProducer,
) -> JsonObject:
    """Bind actual bytes to a controller witness, never candidate-supplied hashes."""
    if (
        type(frozen_context) is not FrozenCandidateContext
        or type(producer_observation) is not StoppedProducer
    ):
        raise TypeError("protected context and controller stop witness required")
    witness = producer_observation
    observed = load_json(witness.inspection)
    if (
        witness.context_sha256 != hashlib.sha256(frozen_context.serialized).hexdigest()
        or observed.get("Id") != witness.container_id
        or observed.get("State", {}).get("Running") is not False
        or observed.get("State", {}).get("Pid") != 0
        or any(
            observed.get("Config", {}).get("Labels", {}).get(k) != v
            for k, v in witness.labels
        )
    ):
        raise ValueError("missing exact owned stopped execution")
    rows = read_products(
        product_paths, witness.expected_paths, max_bytes=witness.max_bytes
    )
    return {
        "schema_version": 1,
        "scope": "local-controller-observation",
        "context_sha256": witness.context_sha256,
        "container_id": witness.container_id,
        "files": rows,
        "manifest_sha256": digest(rows),
        "inspection_sha256": hashlib.sha256(witness.inspection).hexdigest(),
        "qualification": False,
    }

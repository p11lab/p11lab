"""Controller-owned candidate inputs and the shared ComparisonEnvelopeV1 schema.

Constructors express protected local selection, never authenticate candidate JSON.
CI acquisition must introduce independently authenticated control-plane metadata.
This module does not admit endpoints or compare evaluator results.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
import re
import zipfile
from typing import Any, Callable

from . import JsonObject

SHA = re.compile(r"[0-9a-f]{64}")
REV = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
AXES = {"checker", "image", "proxy"}


SOURCE_ARCHIVE_LIMIT = 40 * 1024 * 1024

# Selected policy for inert, qualification-only custody.  This is deliberately
# separate from source archives and comparison snapshots.
CUSTODY_ZIP_LIMIT = 1024 * 1024 * 1024
CUSTODY_MEMBER_LIMIT = 512 * 1024 * 1024
CUSTODY_TOTAL_LIMIT = 1024 * 1024 * 1024
CUSTODY_ENTRY_LIMIT = 10000
CUSTODY_CENTRAL_DIRECTORY_LIMIT = 8 * 1024 * 1024


def _preflight_custody_zip(source, file_size: int) -> None:
    """Count central entries by bounded reads before zipfile allocates them."""
    tail_size = min(file_size, 65557)
    source.seek(file_size - tail_size)
    tail = source.read(tail_size)
    offset = len(tail)
    while True:
        offset = tail.rfind(b'PK\x05\x06', 0, offset)
        if offset < 0:
            raise ValueError('missing custody ZIP end record')
        if len(tail) - offset >= 22:
            end = struct.unpack_from('<4s4H2IH', tail, offset)
            if offset + 22 + end[-1] == len(tail):
                break
    _, disk, start_disk, disk_count, count, directory_size, directory_offset, _ = end
    end_offset = file_size - tail_size + offset
    if (disk, start_disk) != (0, 0) or disk_count != count:
        raise ValueError('multi-disk custody ZIP unsupported')
    if count == 0xffff or directory_size == 0xffffffff or directory_offset == 0xffffffff:
        if end_offset < 20:
            raise ValueError('invalid custody ZIP64 locator')
        source.seek(end_offset - 20)
        locator = source.read(20)
        signature, disk, zip64_offset, disks = struct.unpack('<4sIQI', locator)
        if signature != b'PK\x06\x07' or disk != 0 or disks != 1 or zip64_offset + 56 > end_offset - 20:
            raise ValueError('invalid custody ZIP64 locator')
        source.seek(zip64_offset)
        record = source.read(56)
        if len(record) != 56:
            raise ValueError('truncated custody ZIP64 record')
        sig, record_size, _, _, disk, start_disk, disk_count, count, directory_size, directory_offset = struct.unpack('<4sQHHIIQQQQ', record)
        if (sig != b'PK\x06\x06' or record_size < 44 or zip64_offset + 12 + record_size != end_offset - 20
                or disk != 0 or start_disk != 0 or disk_count != count):
            raise ValueError('invalid custody ZIP64 record')
        end_offset = zip64_offset
    if count > CUSTODY_ENTRY_LIMIT:
        raise ValueError('custody ZIP entry bound')
    if directory_size > CUSTODY_CENTRAL_DIRECTORY_LIMIT:
        raise ValueError('custody ZIP central directory byte bound')
    if directory_offset + directory_size != end_offset:
        raise ValueError('invalid custody ZIP central directory bounds')
    source.seek(directory_offset)
    actual = 0
    while source.tell() < end_offset:
        header = source.read(46)
        if len(header) != 46:
            raise ValueError('truncated custody ZIP central directory')
        fields = struct.unpack('<4s6H3I5H2I', header)
        if fields[0] != b'PK\x01\x02':
            raise ValueError('invalid custody ZIP central entry')
        actual += 1
        if actual > CUSTODY_ENTRY_LIMIT:
            raise ValueError('custody ZIP entry bound')
        next_offset = source.tell() + fields[10] + fields[11] + fields[12]
        if next_offset > end_offset:
            raise ValueError('invalid custody ZIP central entry length')
        source.seek(next_offset)
    if source.tell() != end_offset or actual != count:
        raise ValueError('custody ZIP central entry count mismatch')
    source.seek(0)


def extract_custody_archive(path: Path, expected: JsonObject, destination: Path) -> None:
    """Extract a previously authenticated custody ZIP against a closed roster.

    Roster authentication is the caller's responsibility. Partial output on
    failure is an incomplete attempt and is never an admitted product.
    """
    if type(expected) is not dict or not 1 <= len(expected) <= CUSTODY_ENTRY_LIMIT:
        raise ValueError('invalid custody roster')
    for name, item in expected.items():
        safe_path(name)
        if (type(item) is not dict or set(item) != {'size', 'sha256'}
                or type(item['size']) is not int or not 0 <= item['size'] <= CUSTODY_MEMBER_LIMIT
                or type(item['sha256']) is not str or not SHA.fullmatch(item['sha256'])):
            raise ValueError('invalid custody roster entry')
    if sum(item['size'] for item in expected.values()) > CUSTODY_TOTAL_LIMIT:
        raise ValueError('custody extracted byte bound')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > CUSTODY_ZIP_LIMIT:
            raise ValueError('unsafe custody ZIP')
        _preflight_custody_zip(source, info.st_size)
        destination.mkdir(parents=False, exist_ok=False)
        seen: set[str] = set()
        try:
            with zipfile.ZipFile(source) as archive:
                members = archive.infolist()
                if len(members) != len(expected) or len(members) > CUSTODY_ENTRY_LIMIT:
                    raise ValueError('custody ZIP roster mismatch')
                for member in members:
                    name = safe_path(member.filename)
                    mode = member.external_attr >> 16
                    if (member.orig_filename != name or name in seen or name not in expected or member.is_dir()
                            or (member.create_system == 0 and member.external_attr & 0x10)
                            or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or member.flag_bits & 1
                            or member.file_size != expected[name]['size']):
                        raise ValueError('custody ZIP member mismatch')
                    seen.add(name)
                    target = destination.joinpath(*name.split('/'))
                    target.parent.mkdir(parents=True, exist_ok=True)
                    digest = hashlib.sha256()
                    size = 0
                    with archive.open(member) as item, target.open('xb') as output:
                        while block := item.read(65536):
                            size += len(block)
                            if size > expected[name]['size']:
                                raise ValueError('custody ZIP member overflow')
                            digest.update(block)
                            output.write(block)
                    if size != expected[name]['size'] or digest.hexdigest() != expected[name]['sha256']:
                        raise ValueError('custody ZIP member digest mismatch')
                if seen != set(expected):
                    raise ValueError('custody ZIP roster mismatch')
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError) as error:
            raise ValueError('invalid custody ZIP') from error


def read_source_archive(path: Path) -> bytes:
    """Take one bounded, regular-file snapshot; caller paths never feed parsers."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError("invalid source archive file") from error
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > SOURCE_ARCHIVE_LIMIT:
            raise ValueError("source archive type/byte bound")
        raw = stream.read(SOURCE_ARCHIVE_LIMIT + 1)
    if len(raw) > SOURCE_ARCHIVE_LIMIT:
        raise ValueError("source archive byte bound")
    return raw


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def load_json(raw: bytes, *, max_bytes: int = 2 * 1024 * 1024) -> JsonObject:
    """Bound and reject ambiguous JSON before interpreting any identity fields."""
    if len(raw) > max_bytes:
        raise ValueError("JSON byte bound exceeded")

    def pairs(items: list[tuple[str, Any]]) -> JsonObject:
        result: JsonObject = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise ValueError("nonfinite JSON number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("invalid JSON encoding/depth") from error
    if type(value) is not dict:
        raise ValueError("expected JSON object")
    return value


def safe_path(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or "\x00" in value
        or PurePosixPath(value).is_absolute()
        or ".." in PurePosixPath(value).parts
        or str(PurePosixPath(value)) != value
        or value == "."
    ):
        raise ValueError("unsafe/noncanonical path")
    return value


def verify_candidate_archive(path: Path, expected: JsonObject) -> dict[str, bytes]:
    """Verify an opaque ZIP against an independently supplied closed roster.

    This only checks bytes and archive structure; it does not authenticate the
    roster, producer, source revision or execution environment.
    """
    if type(expected) is not dict or not expected or len(expected) > 10000:
        raise ValueError("invalid archive roster")
    for name, entry in expected.items():
        safe_path(name)
        if (type(entry) is not dict or set(entry) != {"size", "sha256"}
                or type(entry["size"]) is not int or not 0 <= entry["size"] <= SOURCE_ARCHIVE_LIMIT
                or type(entry["sha256"]) is not str or not SHA.fullmatch(entry["sha256"])):
            raise ValueError("invalid archive roster entry")
    if sum(entry["size"] for entry in expected.values()) > SOURCE_ARCHIVE_LIMIT:
        raise ValueError("archive expanded byte bound")
    raw = read_source_archive(path)
    result: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for member in archive.infolist():
                name = safe_path(member.filename)
                mode = member.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if (name in result or name not in expected or member.is_dir()
                        or kind not in (0, stat.S_IFREG) or member.flag_bits & 1
                        or member.file_size != expected[name]["size"]):
                    raise ValueError("archive member mismatch")
                data = archive.read(member)
                if hashlib.sha256(data).hexdigest() != expected[name]["sha256"]:
                    raise ValueError("archive member digest mismatch")
                result[name] = data
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError("invalid candidate archive") from error
    if set(result) != set(expected):
        raise ValueError("missing archive member")
    return result


def inspect_opaque_wheel(raw: bytes) -> None:
    """Bound and inspect all wheel members without importing wheel contents."""
    if len(raw) > SOURCE_ARCHIVE_LIMIT:
        raise ValueError("wheel compressed byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            seen: set[str] = set()
            total = 0
            entries = archive.infolist()
            if not entries or len(entries) > 10000:
                raise ValueError("wheel member count")
            for entry in entries:
                name = safe_path(entry.filename.removesuffix("/"))
                kind = stat.S_IFMT(entry.external_attr >> 16)
                if name in seen or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError("wheel member collision/type")
                seen.add(name)
                if entry.is_dir():
                    if kind not in (0, stat.S_IFDIR):
                        raise ValueError("wheel directory type mismatch")
                    continue
                if kind == stat.S_IFDIR:
                    raise ValueError("wheel file type mismatch")
                total += entry.file_size
                if total > SOURCE_ARCHIVE_LIMIT:
                    raise ValueError("wheel expansion bound")
                with archive.open(entry) as stream:
                    count = 0
                    while block := stream.read(65536):
                        count += len(block)
                        if count > entry.file_size:
                            raise ValueError("wheel size mismatch")
                    if count != entry.file_size:
                        raise ValueError("wheel size mismatch")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError("invalid wheel archive") from error


def select_run_artifact(identity: JsonObject, attempt: JsonObject,
                        jobs: JsonObject, listing: JsonObject, *, name: str | None = None) -> JsonObject:
    """Check REST metadata consistency; callers must authenticate its source.

    GitHub's artifact object does not identify the uploader job. Time and job
    matching here are necessary consistency checks, never producer proof.
    """
    try:
        identifiers = (identity["run_id"], identity["attempt"], identity["workflow_id"],
                       identity["repository_id"], attempt["id"], attempt["run_attempt"],
                       attempt["workflow_id"], attempt["repository"]["id"])
        if any(type(item) is not int or item <= 0 for item in identifiers):
            raise ValueError("invalid run identifier")
        if (attempt["id"] != identity["run_id"]
                or attempt["run_attempt"] != identity["attempt"]
                or attempt["head_sha"] != identity["run_head_sha"]
                or attempt["workflow_id"] != identity["workflow_id"]
                or attempt["repository"]["id"] != identity["repository_id"]
                or not REV.fullmatch(identity["candidate_sha"])):
            raise ValueError("run identity mismatch")
        job_rows = jobs["jobs"]
        if (type(job_rows) is not list or jobs["total_count"] != len(job_rows)
                or len(job_rows) > 100):
            raise ValueError("incomplete job listing")
        producer = [row for row in job_rows if row["name"] == identity["producer_job"]]
        if len(producer) != 1:
            raise ValueError("missing or ambiguous producer")
        job = producer[0]
        if (type(job["run_id"]) is not int or job["run_id"] != identity["run_id"]
                or job["head_sha"] != identity["run_head_sha"]
                or job["conclusion"] != "success"):
            raise ValueError("producer job mismatch")
        rows = listing["artifacts"]
        if (type(rows) is not list or listing["total_count"] != len(rows)
                or len(rows) > 100):
            raise ValueError("incomplete artifact listing")
        if name is None:
            name = f'p11lab-framework-dist-{identity["candidate_sha"]}-{identity["attempt"]}'
        selected = [row for row in rows if row["name"] == name]
        if len(selected) != 1:
            raise ValueError("rerun_requires_producer or ambiguous artifact")
        artifact = selected[0]
        workflow_run = artifact["workflow_run"]
        if (type(workflow_run["id"]) is not int
                or type(workflow_run["repository_id"]) is not int
                or workflow_run["id"] != identity["run_id"]
                or workflow_run["repository_id"] != identity["repository_id"]
                or workflow_run["head_sha"] != identity["run_head_sha"]
                or artifact["expired"] is not False
                or type(artifact["id"]) is not int or artifact["id"] <= 0
                or type(artifact["size_in_bytes"]) is not int
                or not 0 < artifact["size_in_bytes"] <= SOURCE_ARCHIVE_LIMIT):
            raise ValueError("artifact identity mismatch")
        def timestamp(value: str) -> datetime:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if result.tzinfo is None:
                raise ValueError("timestamp requires timezone")
            return result.astimezone(timezone.utc)
        if not (timestamp(attempt["run_started_at"]) <= timestamp(job["started_at"])
                <= timestamp(artifact["created_at"]) <= timestamp(job["completed_at"])):
            raise ValueError("artifact outside producer job attempt")
        return dict(artifact)
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed REST metadata") from error


def select_custody_artifact(identity: JsonObject, attempt: JsonObject, jobs: JsonObject,
                            listing: JsonObject, *, now: datetime) -> JsonObject:
    """Check completed custody metadata; this is not uploader authentication.

    A separately verified producer signature and protected graph must supply
    the expected identity, and stable independent reads must surround use.
    """
    return _select_custody_artifact(identity, attempt, jobs, listing, now=now, active=False)


def select_active_custody_artifact(identity: JsonObject, attempt: JsonObject, jobs: JsonObject,
                                   listing: JsonObject, *, now: datetime) -> JsonObject:
    """Check active producer upload metadata; this is not completed authority."""
    return _select_custody_artifact(identity, attempt, jobs, listing, now=now, active=True)


def _select_custody_artifact(identity: JsonObject, attempt: JsonObject, jobs: JsonObject,
                             listing: JsonObject, *, now: datetime, active: bool) -> JsonObject:
    try:
        required = {'run_id', 'attempt', 'workflow_id', 'repository_id', 'owner_id',
                    'head_sha', 'job_name', 'job_id', 'artifact_id', 'name'}
        if (type(identity) is not dict or set(identity) != required
                or any(type(identity[k]) is not int or identity[k] <= 0 for k in
                       ('run_id', 'attempt', 'workflow_id', 'repository_id', 'owner_id', 'job_id', 'artifact_id'))
                or identity['attempt'] != 1 or type(identity['head_sha']) is not str
                or not REV.fullmatch(identity['head_sha'])
                or type(identity['job_name']) is not str or not identity['job_name']
                or type(identity['name']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', identity['name'])
                or now.tzinfo is None):
            raise ValueError('invalid completed custody identity')
        if (type(attempt['id']) is not int or attempt['id'] != identity['run_id']
                or type(attempt['run_attempt']) is not int or attempt['run_attempt'] != identity['attempt']
                or type(attempt['workflow_id']) is not int or attempt['workflow_id'] != identity['workflow_id']
                or attempt['head_sha'] != identity['head_sha']
                or type(attempt['repository']['id']) is not int or attempt['repository']['id'] != identity['repository_id']
                or type(attempt['repository']['owner']['id']) is not int or attempt['repository']['owner']['id'] != identity['owner_id']
                or attempt['status'] != ('in_progress' if active else 'completed')
                or attempt['conclusion'] != (None if active else 'success')):
            raise ValueError('completed custody workflow mismatch')
        rows = jobs['jobs']
        if type(rows) is not list or type(jobs['total_count']) is not int or jobs['total_count'] != len(rows) or len(rows) > 100:
            raise ValueError('incomplete custody job listing')
        if (any(type(row) is not dict or type(row.get('id')) is not int or row['id'] <= 0 for row in rows)
                or len({row['id'] for row in rows}) != len(rows)):
            raise ValueError('invalid or duplicate custody job ID')
        selected = [row for row in rows if row.get('name') == identity['job_name']]
        if len(selected) != 1:
            raise ValueError('missing or ambiguous custody job')
        job = selected[0]
        if (type(job['id']) is not int or job['id'] != identity['job_id']
                or type(job['run_id']) is not int or job['run_id'] != identity['run_id']
                or job['head_sha'] != identity['head_sha'] or job['status'] != ('in_progress' if active else 'completed')
                or job['conclusion'] != (None if active else 'success')
                or (active and job['completed_at'] is not None)):
            raise ValueError('completed custody job mismatch')
        rows = listing['artifacts']
        if type(rows) is not list or type(listing['total_count']) is not int or listing['total_count'] != len(rows) or len(rows) > 100:
            raise ValueError('incomplete custody artifact listing')
        selected = [row for row in rows if row.get('name') == identity['name']]
        if len(selected) != 1:
            raise ValueError('missing or ambiguous custody artifact')
        artifact = selected[0]
        workflow_run = artifact['workflow_run']
        if (type(artifact['id']) is not int or artifact['id'] != identity['artifact_id']
                or type(artifact['size_in_bytes']) is not int or not 0 < artifact['size_in_bytes'] <= CUSTODY_ZIP_LIMIT
                or type(artifact['digest']) is not str or not DIGEST.fullmatch(artifact['digest'])
                or artifact['expired'] is not False
                or type(workflow_run['id']) is not int or workflow_run['id'] != identity['run_id']
                or type(workflow_run['repository_id']) is not int or workflow_run['repository_id'] != identity['repository_id']
                or workflow_run['head_sha'] != identity['head_sha']):
            raise ValueError('custody artifact identity mismatch')
        def stamp(value: str) -> datetime:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                raise ValueError('timestamp requires timezone')
            return parsed.astimezone(timezone.utc)
        created = stamp(artifact['created_at'])
        expires = stamp(artifact['expires_at'])
        retention = expires - created
        skew = timedelta(minutes=5)
        started = stamp(job['started_at'])
        completed = now + skew if active else stamp(job['completed_at'])
        if (not stamp(attempt['run_started_at']) <= started <= created <= completed
                or completed > now + skew
                or created > now + skew or not now < expires or now > created + timedelta(days=14)
                or not timedelta(days=14) - skew <= retention <= timedelta(days=14) + skew):
            raise ValueError('custody artifact timing or retention mismatch')
        return dict(artifact)
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError('malformed custody REST metadata') from error


def stable_metadata(fetch: Callable[[], JsonObject], *,
                    clock: Callable[[], float] = time.monotonic,
                    sleep: Callable[[float], None] = time.sleep) -> JsonObject:
    """Require three consecutive matching reads at least two seconds apart."""
    deadline = clock() + 60
    previous: bytes | None = None
    count = 0
    while clock() <= deadline:
        value = fetch()
        if clock() > deadline:
            break
        encoded = canonical(value)
        count = count + 1 if encoded == previous else 1
        if count == 3:
            return load_json(encoded)
        previous = encoded
        if clock() + 2 > deadline:
            break
        sleep(2)
    raise ValueError("artifact metadata did not stabilize within 60 seconds")


def validate_candidate_manifest(manifest: JsonObject, identity: JsonObject) -> JsonObject:
    """Bind the opaque dist roster to a separately frozen invocation identity."""
    fields = {"schema_version", "identity", "roles", "dependency_lock_sha256",
              "source_receipt_sha256", "build_receipt_sha256"}
    identity_fields = {"repository_id", "run_id", "attempt", "candidate_sha",
                       "target_sha", "merge_base_sha"}
    roles = {"primary_wheel", "sdist", "sdist_probe_wheel", "replay_base_wheel"}
    if (type(manifest) is not dict or set(manifest) != fields
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or type(identity) is not dict or set(identity) != identity_fields
            or canonical(manifest["identity"]) != canonical(identity)):
        raise ValueError("candidate manifest identity mismatch")
    for field in ("repository_id", "run_id", "attempt"):
        if type(identity[field]) is not int or identity[field] <= 0:
            raise ValueError("invalid invocation identity")
    for field in ("candidate_sha", "target_sha", "merge_base_sha"):
        if type(identity[field]) is not str or not REV.fullmatch(identity[field]):
            raise ValueError("invalid invocation revision")
    for field in ("dependency_lock_sha256", "source_receipt_sha256", "build_receipt_sha256"):
        if type(manifest[field]) is not str or not SHA.fullmatch(manifest[field]):
            raise ValueError("invalid candidate receipt identity")
    records = manifest["roles"]
    if type(records) is not dict or set(records) != roles:
        raise ValueError("candidate role roster mismatch")
    names: dict[str, str] = {}
    for role, record in records.items():
        if (type(record) is not dict or set(record) != {"path", "size", "sha256"}
                or type(record["size"]) is not int or not 0 < record["size"] <= SOURCE_ARCHIVE_LIMIT
                or type(record["sha256"]) is not str or not SHA.fullmatch(record["sha256"])):
            raise ValueError("invalid candidate role")
        path = safe_path(record["path"])
        if not path.endswith(".tar.gz" if role == "sdist" else ".whl"):
            raise ValueError("candidate role type mismatch")
        if path in names and not (set((names[path], role)) == {"primary_wheel", "replay_base_wheel"}
                                  and identity["candidate_sha"] == identity["merge_base_sha"]
                                  and records[names[path]] == record):
            raise ValueError("candidate role path collision")
        names[path] = role
    return load_json(canonical(manifest))


def verify_dist_bytes(raw: bytes, identity: JsonObject, expected_lock_sha256: str,
                      archive_path: Path, *, materialize: bool = False) -> JsonObject:
    """Bind dist bytes to an independently selected lock and frozen identity.

    Byte consistency does not establish the trust of the producer or lock.
    """
    if len(raw) > SOURCE_ARCHIVE_LIMIT:
        raise ValueError("dist archive byte bound")
    fd = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if len(infos) > 10000:
                raise ValueError("dist member count bound")
            def control(name: str) -> bytes:
                matches = [item for item in infos if item.filename == name]
                if len(matches) != 1:
                    raise ValueError("missing or ambiguous dist control")
                item = matches[0]
                if item.file_size > 2 * 1024 * 1024 or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG):
                    raise ValueError("invalid dist control")
                return archive.read(item)
            manifest_raw = control("candidate-manifest.json")
            manifest = validate_candidate_manifest(load_json(manifest_raw), identity)
            lock_raw = control("dependency-lock.json")
            if (not SHA.fullmatch(expected_lock_sha256)
                    or hashlib.sha256(lock_raw).hexdigest() != expected_lock_sha256
                    or manifest["dependency_lock_sha256"] != expected_lock_sha256):
                raise ValueError("dependency lock mismatch")
            lock = load_json(lock_raw)
            if (set(lock) != {"schema_version", "build_roots", "runtime_extras", "build_wheels", "runtime_wheels"}
                    or type(lock["schema_version"]) is not int or lock["schema_version"] != 1
                    or type(lock["build_roots"]) is not list or not lock["build_roots"]
                    or any(type(v) is not str or not v or len(v) > 8192 for v in lock["build_roots"])
                    or type(lock["runtime_extras"]) is not list
                    or any(type(v) is not str or not v or len(v) > 128 for v in lock["runtime_extras"])
                    or any(type(lock[group]) is not list or not lock[group] or len(lock[group]) > 10000
                           for group in ("build_wheels", "runtime_wheels"))):
                raise ValueError("invalid dependency lock")
            source_raw = control("source-receipt.json")
            build_raw = control("build-receipt.json")
            if (hashlib.sha256(source_raw).hexdigest() != manifest["source_receipt_sha256"]
                    or hashlib.sha256(build_raw).hexdigest() != manifest["build_receipt_sha256"]):
                raise ValueError("receipt digest mismatch")
            source = load_json(source_raw)
            build = load_json(build_raw)
            if (source.get("revision") != identity["candidate_sha"]
                    or canonical(build.get("identity")) != canonical(identity)
                    or build.get("roles_sha256") != digest(manifest["roles"])):
                raise ValueError("source/build receipt mismatch")
            roster: dict[str, Any] = {}
            for name, data in (("candidate-manifest.json", manifest_raw),
                               ("dependency-lock.json", lock_raw),
                               ("source-receipt.json", source_raw), ("build-receipt.json", build_raw)):
                roster[name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for entry in manifest["roles"].values():
                if type(entry) is not dict or set(entry) != {"path", "size", "sha256"}:
                    raise ValueError("invalid dist roster entry")
                path = safe_path(entry["path"])
                if path in roster and roster[path] != {"size": entry["size"], "sha256": entry["sha256"]}:
                    raise ValueError("dist roster collision")
                roster[path] = {"size": entry["size"], "sha256": entry["sha256"]}
            for group in ("build_wheels", "runtime_wheels"):
                seen: set[str] = set()
                for entry in lock[group]:
                    if type(entry) is not dict or set(entry) not in ({"path", "size", "sha256"},
                                                                    {"path", "size", "sha256", "url"}):
                        raise ValueError("invalid dependency wheel")
                    path = safe_path(entry["path"])
                    if path in seen or not path.startswith("deps/") or not path.endswith(".whl"):
                        raise ValueError("duplicate or invalid dependency wheel")
                    seen.add(path)
                    row = {"size": entry["size"], "sha256": entry["sha256"]}
                    if path in roster and roster[path] != row:
                        raise ValueError("dependency roster collision")
                    roster[path] = row
        verified = verify_candidate_archive(archive_path, roster)
        from .worker import _source_content
        _source_content(verified[manifest["roles"]["sdist"]["path"]])
        wheel_paths = {row["path"] for role, row in manifest["roles"].items() if role != "sdist"}
        wheel_paths.update(row["path"] for group in ("build_wheels", "runtime_wheels") for row in lock[group])
        for wheel_path in wheel_paths:
            inspect_opaque_wheel(verified[wheel_path])
        if materialize:
            target = archive_path.parent / "dist"
            target.mkdir()
            for name, content in verified.items():
                destination = target.joinpath(*PurePosixPath(name).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as stream:
                    stream.write(content)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError("invalid dist archive") from error
    return {"identity": identity, "roles": manifest["roles"],
            "dependency_lock_sha256": expected_lock_sha256,
            "build_wheels_sha256": digest({"roots": lock["build_roots"], "wheels": lock["build_wheels"]}),
            "runtime_wheels_sha256": digest({"extras": lock["runtime_extras"], "wheels": lock["runtime_wheels"]}),
            "dependency_lock": lock,
            "source_receipt_sha256": manifest["source_receipt_sha256"],
            "build_receipt_sha256": manifest["build_receipt_sha256"],
            "file_roster": [{"path": name, **entry} for name, entry in sorted(roster.items())],
            "archive_sha256": hashlib.sha256(raw).hexdigest()}


def validate_offline_closures(root: Path, lock: JsonObject, roles: JsonObject,
                              target: JsonObject, evaluator_python: Path) -> JsonObject:
    """Inspect selected wheel metadata with the separately sealed W01 interpreter."""
    script = Path(__file__).with_name("closure_probe.py")
    def probe(candidate: str | None, wheels: list[JsonObject], *, roots: list[str] | None = None,
              allow_orphans: bool = False) -> JsonObject:
        request: JsonObject = {
            "candidate": str(root / safe_path(candidate)) if candidate is not None else None,
            "dependencies": [str(root / safe_path(row["path"])) for row in wheels],
            "target": target, "allow_orphans": allow_orphans,
        }
        if roots is not None:
            request["roots"] = roots
        if candidate is not None:
            request["candidate_extras"] = lock["runtime_extras"]
        try:
            proc = subprocess.run([str(evaluator_python), "-I", "-B", str(script)],
                                  input=canonical(request), capture_output=True, timeout=60,
                                  cwd=root, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"})
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError("sealed offline closure probe unavailable") from None
        if proc.returncode != 0 or len(proc.stdout) > 2 * 1024 * 1024:
            raise ValueError("offline dependency closure failed")
        return load_json(proc.stdout)
    build = probe(None, lock["build_wheels"], roots=lock["build_roots"])
    sides = {role: probe(roles[role]["path"], lock["runtime_wheels"], allow_orphans=True)
             for role in ("primary_wheel", "sdist_probe_wheel", "replay_base_wheel")}
    available = set(sides["primary_wheel"]["available"])
    if any(set(row["available"]) != available for row in sides.values()):
        raise ValueError("offline dependency closure inconsistent")
    reached = {name for side in sides.values() for name in side["dependencies"]}
    if reached != available:
        raise ValueError("offline dependency closure contains orphan wheels")
    return {"status": "static-closure-verified", "build": build, "runtime": sides}


def verify_dependency_origins(root: Path, lock: JsonObject, output: Path) -> JsonObject:
    """Independently acquire exact PyPI wheel bytes from protected lock records."""
    from ..tool_downloads import download_locked_file
    from urllib.parse import urlsplit

    output.mkdir(parents=True, exist_ok=False)
    records: dict[str, JsonObject] = {}
    for group in ("build_wheels", "runtime_wheels"):
        for entry in lock[group]:
            if type(entry) is not dict or set(entry) != {"path", "size", "sha256", "url"}:
                raise ValueError("dependency origin record missing")
            name = safe_path(entry["path"])
            if type(entry["url"]) is not str or Path(urlsplit(entry["url"]).path).name != Path(name).name:
                raise ValueError("dependency origin filename mismatch")
            if name in records and records[name] != entry:
                raise ValueError("dependency origin conflict")
            records[name] = entry
    if len(records) > 256:
        raise ValueError("dependency origin count bound")
    observations: list[JsonObject] = []
    deadline = time.monotonic() + 300
    for index, name in enumerate(sorted(records)):
        entry = records[name]
        destination = output / f"{index:05d}.whl"
        record = {**entry, "kind": "python-wheel"}
        observation = download_locked_file(record, destination, deadline=deadline)
        actual = read_source_archive(destination)
        selected = read_source_archive(root / name)
        if (len(actual) != entry["size"] or hashlib.sha256(actual).hexdigest() != entry["sha256"]
                or actual != selected):
            raise ValueError("dependency origin readback mismatch")
        observations.append({"path": name, "size": len(actual), "sha256": entry["sha256"],
                             "url": entry["url"], "final_url": observation["final_url"]})
    return {"status": "anonymous-origin-byte-readback-verified", "wheels": observations}


def _snapshot_data(root: Path, expected: list[JsonObject]) -> tuple[list[JsonObject], dict[str, bytes]]:
    from ..tool_downloads import safe_directory

    safe_directory(root)
    if not root.is_dir() or len(expected) > 10000:
        raise ValueError("invalid data directory/roster")
    files: dict[str, bytes] = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            if not stat.S_ISDIR((Path(directory) / name).lstat().st_mode):
                raise ValueError("non-directory data entry")
        for name in names:
            path = Path(directory) / name
            relative = safe_path(path.relative_to(root).as_posix())
            files[relative] = read_source_archive(path)
            if len(files) > 10000 or sum(map(len, files.values())) > SOURCE_ARCHIVE_LIMIT:
                raise ValueError("data inventory bound")
    actual = [{"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
              for name, raw in sorted(files.items())]
    if canonical(actual) != canonical(expected) or not actual:
        raise ValueError("data inventory mismatch")
    return actual, files


def _verify_round_owner_proof(transport, profile: JsonObject | None, context: JsonObject,
                              metadata_identity: JsonObject, identity: JsonObject,
                              dist_raw: bytes) -> JsonObject | None:
    """Run job-binding owner proof for enrolled profiles; None when unenrolled.

    Unenrolled profiles (proof fields absent, or the zeros trust-root
    sentinel) skip proof and keep today's behavior; enrollment replaces
    the sentinel before live use. Enrolled profiles resolve the
    producer-uploaded attestation bundle, decode its single envelope,
    verify it against the pinned verifier, and re-read the metadata.
    """
    from .artifacts import decode_round_attestation, verify_artifact_digest
    from .owner_proof import (check_round_roster, check_round_signature, check_round_subject,
                              check_token_exclusivity_premise, round_verifier_overlay,
                              run_round_verifier)

    assert profile is not None
    if 'root_sha256' not in profile or profile.get('root_sha256') == '0' * 64:
        return None
    attestation_name = profile['attestation_artifact_name'].replace('{run_id}', str(identity['run_id'])).replace('{attempt}', str(identity['attempt']))
    proof = transport.resolve_round_attestation(metadata_identity, attestation_name=attestation_name)
    att_raw = transport.download(proof['artifact']['id'])
    verify_artifact_digest(att_raw, proof['artifact'])
    subject_raw, bundle_raw = decode_round_attestation(att_raw)
    check_round_roster(proof['jobs'], profile)
    overlay = round_verifier_overlay(profile, context, proof['attempt'])
    premise = check_token_exclusivity_premise(profile)
    check_round_subject(subject_raw, 'sha256:' + hashlib.sha256(dist_raw).hexdigest(), identity)
    executable = context.get('owner_proof_executable')
    trusted_root = context.get('owner_proof_trusted_root')
    if type(executable) is not str or not executable or type(trusted_root) is not str or not trusted_root:
        raise ValueError('round owner proof verifier inputs unavailable')
    producer_rows = [row for row in proof['jobs']['jobs'] if row.get('name') == profile['producer_job']]
    if len(producer_rows) != 1:
        raise ValueError('round job roster mismatch')
    proof_identity = {'run_id': identity['run_id'], 'attempt': identity['attempt'],
                      'producer_job': profile['producer_job'], 'run_head_sha': context['run_head_sha'],
                      'source_ref': overlay['source_ref']}
    with tempfile.TemporaryDirectory(prefix='p11lab-round-owner-proof-') as work:
        work_path = Path(work)
        subject_path = work_path / 'round-artifact.json'
        bundle_path = work_path / 'bundle.json'
        subject_path.write_bytes(subject_raw)
        bundle_path.write_bytes(bundle_raw)
        result, verified_raw = run_round_verifier(
            executable, subject_path, bundle_path, trusted_root,
            profile['root_sha256'], overlay, work_path / 'attestation')
    check_round_signature(result, overlay, proof_identity, verified_raw, producer_rows[0],
                          datetime.now(timezone.utc))
    second = transport.resolve_round_attestation(metadata_identity, attestation_name=attestation_name)
    if canonical(second) != canonical(proof):
        raise ValueError('round producer metadata changed during verification')
    artifact = proof['artifact']
    return {'attestation_artifact': {'id': artifact['id'], 'name': artifact['name'], 'digest': artifact['digest']},
            'source_ref': overlay['source_ref'], 'premise': premise}


def prepare(context: JsonObject, policy_root: Path | None, output: Path) -> JsonObject:
    """Acquire opaque inputs and record their byte identities without executing them.

    Caller/producer authority is an independent outstanding gate. Fixture
    transport is diagnostic only and forbidden in CI.
    """
    from .policy import load_policy
    from ..tool_downloads import safe_directory

    mode = context.get("transport")
    if mode == "fixture" and (os.getenv("CI") or os.getenv("GITHUB_ACTIONS")):
        raise ValueError("fixture transport is forbidden in CI")
    if mode not in ("fixture", "github"):
        raise ValueError("unknown transport")
    fields = {"transport", "tier", "identity", "repository", "run_head_sha", "workflow_id",
              "producer_job", "dependency_lock_sha256", "data_root", "data_files", "disabled_path", "target"}
    fields |= {"artifact_path", "fixture_metadata_path"} if mode == "fixture" else {"control_sha"}
    optional = {"cache_file", "owner_id", "owner_proof_executable", "owner_proof_trusted_root"}
    if type(context) is not dict or not fields <= set(context) or set(context) - fields - optional:
        raise ValueError("invalid preparation context")
    string_fields = {"tier", "repository", "run_head_sha", "producer_job", "dependency_lock_sha256",
                     "data_root", "disabled_path"}
    string_fields |= {"artifact_path", "fixture_metadata_path"} if mode == "fixture" else {"control_sha"}
    if "cache_file" in context:
        string_fields.add("cache_file")
    if "owner_proof_executable" in context:
        string_fields.add("owner_proof_executable")
    if "owner_proof_trusted_root" in context:
        string_fields.add("owner_proof_trusted_root")
    if (any(type(context[k]) is not str or not context[k] or len(context[k]) > 8192 for k in string_fields)
            or type(context["target"]) is not dict
            or ("owner_id" in context and (type(context["owner_id"]) is not int or context["owner_id"] <= 0))):
        raise ValueError("invalid preparation context fields")
    policy = load_policy(policy_root, context["tier"])
    identity = context["identity"]
    required = {"repository_id", "run_id", "attempt", "candidate_sha", "target_sha", "merge_base_sha"}
    if type(identity) is not dict or set(identity) != required:
        raise ValueError("invalid frozen invocation identity")
    identity = load_json(canonical(identity))
    if (any(type(identity[k]) is not int or identity[k] <= 0 for k in ("repository_id", "run_id", "attempt"))
            or any(type(identity[k]) is not str or not REV.fullmatch(identity[k])
                   for k in ("candidate_sha", "target_sha", "merge_base_sha"))
            or type(context["workflow_id"]) is not int or context["workflow_id"] <= 0
            or type(context["run_head_sha"]) is not str or not REV.fullmatch(context["run_head_sha"])
            or type(context["dependency_lock_sha256"]) is not str or not SHA.fullmatch(context["dependency_lock_sha256"])
            or type(context["data_files"]) is not list):
        raise ValueError("invalid preparation context identity or data roster")
    if (not context["data_files"] or len(context["data_files"]) > 256
            or any(type(row) is not dict or set(row) != {"path", "size", "sha256"}
                   or type(row["path"]) is not str or type(row["size"]) is not int
                   or not 0 <= row["size"] <= SOURCE_ARCHIVE_LIMIT
                   or type(row["sha256"]) is not str or not SHA.fullmatch(row["sha256"])
                   for row in context["data_files"])):
        raise ValueError("invalid data file roster")
    data_names = [safe_path(row["path"]) for row in context["data_files"]]
    if data_names != sorted(set(data_names)):
        raise ValueError("duplicate or unsorted data file roster")
    safe_path(context["disabled_path"])
    lock_sha = context["dependency_lock_sha256"]
    sources: list[JsonObject] = []
    profile: JsonObject | None = None
    profile_sha: str | None = None
    owner_proof_record: JsonObject | None = None
    retries_used = 0
    metadata: JsonObject
    raw: bytes
    if mode == "github":
        pins = policy.controls["sources"]["pins"]
        if not pins["checker-runtime-lock"]["sha256"] or not pins["checker-build-lock"]["sha256"]:
            raise ValueError("protected dependency lock pins unresolved")
        if pins["corpus"]["sha256"] != digest(context["data_files"]):
            raise ValueError("protected corpus pin unresolved or mismatched")
        from importlib.resources import files
        from .artifacts import GitHubTransport, TransientTransportError, decode_control_artifact, verify_producer_profile
        transport = GitHubTransport(context["repository"], os.environ.get("GITHUB_TOKEN", ""))
        metadata_identity = dict(identity, run_head_sha=context["run_head_sha"],
                                 workflow_id=context["workflow_id"], producer_job=context["producer_job"])
        cache_file = Path(context["cache_file"]) if "cache_file" in context else None
        profiles = load_json(files("p11lab").joinpath("data/rounds/producer-profiles.json").read_bytes())
        if (set(profiles) != {"schema_version", "profiles"} or type(profiles["schema_version"]) is not int
                or profiles["schema_version"] != 1 or type(profiles["profiles"]) is not list
                or any(type(p) is not dict for p in profiles["profiles"])):
            raise ValueError("invalid protected producer profiles")
        selected_profiles = [p for p in profiles["profiles"] if p.get("repository") == context["repository"]
                             and p.get("workflow_id") == context["workflow_id"]]
        if len(selected_profiles) != 1:
            raise ValueError("protected producer profile unavailable or ambiguous")
        profile = selected_profiles[0]
        if (type(profile.get("policy_sha256")) is not str
                or not SHA.fullmatch(profile["policy_sha256"])
                or profile["policy_sha256"] != policy.policy_digest):
            raise ValueError("policy bundle does not match protected producer profile")
        if (type(profile.get("data_sources")) is not list or type(profile.get("context_job")) is not str
                or type(profile.get("context_artifact_name")) is not str):
            raise ValueError("malformed protected producer profile")
        sources = profile["data_sources"]
        caller = dict(context, repository_id=identity["repository_id"], target_sha256=digest(context["target"]),
                      data_sources_sha256=digest(sources), policy_sha256=policy.policy_digest)
        def verify_profile(_metadata: JsonObject) -> None:
            assert profile is not None
            verify_producer_profile(profile, caller, lambda path: transport.source_file(context["run_head_sha"], path))
        control_identity = dict(metadata_identity, producer_job=profile["context_job"])
        control_name = profile["context_artifact_name"].replace("{run_id}", str(identity["run_id"])).replace("{attempt}", str(identity["attempt"]))
        protected_fields = ("identity", "repository", "run_head_sha", "workflow_id", "producer_job",
                            "control_sha", "target", "dependency_lock_sha256", "data_files", "disabled_path")
        expected_context = {key: context[key] for key in protected_fields}
        expected_context["policy_sha256"] = policy.policy_digest
        for retry in range(2):
            try:
                control_metadata, control_raw = transport.acquire(control_identity, artifact_name=control_name,
                    retries=0, before_download=verify_profile)
                actual_context = decode_control_artifact(control_raw)
                if canonical(actual_context) != canonical(expected_context):
                    raise ValueError("protected caller context mismatch")
                metadata, raw = transport.acquire(metadata_identity, cache_file=cache_file, retries=0)
                owner_proof_record = _verify_round_owner_proof(
                    transport, profile, context, metadata_identity, identity, raw)
                break
            except TransientTransportError:
                if retry:
                    raise
                retries_used += 1
                time.sleep(10)
        metadata = {key: metadata[key] for key in ("id", "name", "size_in_bytes", "created_at", "expired", "workflow_run", "digest")}
        control_metadata = {key: control_metadata[key] for key in ("id", "name", "size_in_bytes", "created_at", "expired", "workflow_run", "digest")}
        profile_sha = digest(profile)
    output = Path(output).absolute()
    safe_directory(output)
    output.mkdir(parents=True, exist_ok=False)
    data_root = Path(context["data_root"])
    if mode == "github" and not data_root.exists():
        if type(sources) is not list or len(sources) != len(context["data_files"]):
            raise ValueError("missing public data sources")
        expected = {row["path"]: row for row in context["data_files"]}
        if len(expected) != len(context["data_files"]):
            raise ValueError("ambiguous data roster")
        data_root = output / "acquired-data"
        data_root.mkdir()
        seen: set[str] = set()
        data_deadline = time.monotonic() + 300
        for source in sources:
            if type(source) is not dict or set(source) != {"path", "url", "size", "sha256", "redirect_origin"}:
                raise ValueError("invalid public data source")
            name = safe_path(source["path"])
            if name in seen or name not in expected or any(source[k] != expected[name][k] for k in ("size", "sha256")):
                raise ValueError("public data source roster mismatch")
            seen.add(name)
            from ..tool_downloads import RoundDataSource, TransientRoundDataError, download_round_data
            item = RoundDataSource(source["url"], source["size"], source["sha256"], source["redirect_origin"])
            try:
                payload = download_round_data(item, deadline=data_deadline)
            except TransientRoundDataError:
                if retries_used:
                    raise
                retries_used += 1
                time.sleep(10)
                payload = download_round_data(item, deadline=data_deadline)
            destination = data_root.joinpath(*PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(payload)
    before, data = _snapshot_data(data_root, context["data_files"])
    if context["disabled_path"] not in data:
        raise ValueError("missing disabled inventory")
    corpus_sha = digest(before)
    disabled_sha = hashlib.sha256(data[context["disabled_path"]]).hexdigest()
    if mode == "github":
        pins = policy.controls["sources"]["pins"]
        if pins["corpus"]["sha256"] != corpus_sha or policy.profile["disabled_inventory"]["sha256"] != disabled_sha:
            raise ValueError("protected corpus/disabled pin unresolved or mismatched")
    else:
        control_metadata = {"classification": "local-fixture"}
        fixture = load_json(read_source_archive(Path(context["fixture_metadata_path"])))
        metadata_identity = dict(identity, run_head_sha=context["run_head_sha"],
                                 workflow_id=context["workflow_id"], producer_job=context["producer_job"])
        selected = select_run_artifact(metadata_identity, fixture["attempt"], fixture["jobs"], fixture["listing"])
        metadata = {"classification": "local-fixture", "artifact": selected}
        selected_path = context["cache_file"] if "cache_file" in context else context["artifact_path"]
        raw = read_source_archive(Path(selected_path))
        from .artifacts import verify_artifact_digest
        verify_artifact_digest(raw, selected)
    dist = verify_dist_bytes(raw, identity, lock_sha, output / "dist.zip", materialize=True)
    if mode == "github" and (dist["build_wheels_sha256"] != pins["checker-build-lock"]["sha256"]
                              or dist["runtime_wheels_sha256"] != pins["checker-runtime-lock"]["sha256"]):
        raise ValueError("protected dependency wheel closure mismatch")
    dependency_origin: JsonObject = {"status": "not-executed", "observation": "local fixture wheels"}
    if mode == "github":
        dependency_origin = verify_dependency_origins(output / "dist", dist["dependency_lock"], output / "dependency-readback")
    materialized = output / "data"
    materialized.mkdir()
    for name, raw_data in data.items():
        path = materialized.joinpath(*PurePosixPath(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw_data)
    after, _ = _snapshot_data(data_root, context["data_files"])
    mounted, _ = _snapshot_data(materialized, context["data_files"])
    if before != after or before != mounted:
        raise ValueError("data changed during preparation")
    evaluator: JsonObject = {"status": "not-acquired"}
    closure: JsonObject = {"status": "not-executed"}
    installed: JsonObject = {"status": "not-executed"}
    authority = "local-fixture-non-authoritative" if mode == "fixture" else "producer-authority-unverified"
    if mode == "github":
        from .bootstrap import acquire_evaluator, sha256
        authority = "protected-profile-source-verified"
        lock_root = Path(__file__).resolve().parents[1] / "data/rounds/evaluator"
        source_pin = load_json((lock_root / "source.json").read_bytes())
        evaluator_receipt = acquire_evaluator(source_pin, lock_root, output / "evaluator")
        evaluator = {"status": "verified-bootstrap-receipt",
                     "receipt_path": "evaluator/evaluator-build-receipt.json",
                     "receipt_sha256": sha256(output / "evaluator/evaluator-build-receipt.json"),
                     "host_observations": {"platform": evaluator_receipt["python"]["platform"],
                                           "libc": evaluator_receipt["python"]["libc"],
                                           "native_dependencies": evaluator_receipt["native_dependencies"]}}
        _snapshot_data(output / "dist", dist["file_roster"])
        closure = validate_offline_closures(output / "dist", dist["dependency_lock"], dist["roles"],
                                           context["target"], output / "evaluator/evaluator-install/bin/python3")
        _snapshot_data(output / "dist", dist["file_roster"])
        from .prebuilt import ProtectedRuntimeSelection, WheelSnapshot, install_prebuilt_candidate
        assert profile is not None
        runtime = profile["runtime"]
        tools = SealedToolInputs.from_evaluator(output / "evaluator")
        verified_tools = verified_evaluator_identity(output / "evaluator")
        if (digest(verified_tools["identity"]) != verified_tools["identity_sha256"]
                or verified_tools["receipt_sha256"] != tools.receipt_sha256
                or verified_tools["identity_sha256"] != runtime["tool_identity_sha256"]
                or runtime["python_version"] != context["target"]["marker_environment"]["python_full_version"]):
            raise ValueError("protected runtime selection mismatch")
        (output / "runtime-tool-identity.json").write_bytes(canonical(verified_tools["identity"]))
        evaluator["tool_identity_sha256"] = verified_tools["identity_sha256"]
        deps = tuple(WheelSnapshot(output / "dist" / row["path"], row["sha256"])
                     for row in dist["dependency_lock"]["runtime_wheels"])
        roles: JsonObject = {}
        for role in ("primary_wheel", "sdist_probe_wheel", "replay_base_wheel"):
            row = dist["roles"][role]
            selection = ProtectedRuntimeSelection(
                image=runtime["image"], layers=tuple(runtime["layers"]), config_sha256=runtime["config_sha256"],
                control_revision=context["control_sha"], python_version=runtime["python_version"], tools=tools,
                candidate=WheelSnapshot(output / "dist" / row["path"], row["sha256"]), dependencies=deps,
                max_output_bytes=runtime["max_output_bytes"],
            )
            observed = install_prebuilt_candidate(selection, output / ("install-" + role))
            roles[role] = {"status": observed["status"], "wheel_sha256": row["sha256"],
                           "installed_manifest_sha256": observed.get("installed_manifest_sha256")}
            if observed["status"] != "installed":
                raise ValueError("guarded candidate installation failed: " + role)
            _snapshot_data(output / "dist", dist["file_roster"])
        installed = {"status": "local-isolated-installation-observed", "roles": roles}
    gates = ["Independent protected caller and producer contract requires owner proof.",
             "Dependency licensing, provider delivery and later execution remain unqualified."]
    if owner_proof_record is not None:
        authority = "round-owner-proof-verified"
        gates[0] = "Round owner proof verified for the producing job."
    result: JsonObject = {
        "schema_version": 1, "kind": "round-input-diagnostic", "transport": mode,
        "authority": authority, "protected_profile_sha256": profile_sha,
        "round_positive": False, "identity": identity, "policy_sha256": policy.policy_digest,
        "target": context["target"], "target_sha256": digest(context["target"]),
        "caller": {"repository": context["repository"], "run_head_sha": context["run_head_sha"],
                   "workflow_id": context["workflow_id"], "producer_job": context["producer_job"],
                   "control_sha": context.get("control_sha")},
        "artifact_metadata": metadata, "dist": dist, "corpus_sha256": corpus_sha,
        "context_artifact_metadata": control_metadata,
        "pre_provider_transport_retries": retries_used,
        "artifact_input": "verified-cache" if "cache_file" in context else "fresh-acquisition",
        "disabled_sha256": disabled_sha, "data_inventory": before,
        "data_sources_sha256": digest(sources),
        "evaluator": evaluator, "candidate_install": installed,
        "dependency_closure": closure,
        "dependency_origin": dependency_origin,
        "provider_delivery": {"status": "unresolved"},
        "gates": gates,
    }
    if owner_proof_record is not None:
        result["owner_proof"] = owner_proof_record
    (output / "round-inputs.json").write_bytes(canonical(result) + b"\n")
    return result


# A single closed definition, shared with the endpoint validator owned by M03.
_CONTROLS = dict.fromkeys(
    ("dataset", "profile", "config_policy", "consumer_policy", "obligation_policy"),
    "hash",
)
_ARTIFACTS: dict[str, Any] = {
    "checker": dict.fromkeys(
        ("source_sha", "wheel_sha256", "installed_manifest_sha256"), "hash"
    ),
    "provider": {
        "family": "text",
        "platform": "text",
        "source_sha": "rev",
        "recipe_sha256": "hash",
        "build_key": "hash",
        "manifest_digest": "digest",
        "config_digest": "digest",
        "layer_digests": ["digest"],
    },
    "proxy": {
        "source_sha": "rev",
        "build_key": "hash",
        "daemon_sha256": "hash",
        "cli_sha256": "hash",
        "shim_sha256": "hash",
    },
    "consumer": {"installed_manifest_sha256": "hash"},
    "derivative": {
        "manifest_digest": "digest",
        "config_digest": "digest",
        "layer_digests": ["digest"],
        "parent_manifest_digest": "digest",
    },
}
_ARTIFACTS["checker"]["source_sha"] = "rev"
_COUNTERS = dict.fromkeys(
    (
        "child_crash",
        "child_timeout",
        "crash_limited",
        "crashed",
        "error",
        "failed",
        "incomplete",
        "missing",
        "passed",
        "skipped",
        "timeout",
        "xfailed",
        "xpassed",
    ),
    "int",
)
_HEADER = {
    "record": "text",
    "schema_v": "int",
    "lane": "text",
    "lane_os": "text",
    "lane_arch": "text",
    "framework_sha": "rev",
    "image_digest": "digest",
    "p11lab_sha": "rev",
    "corpus_hash": "hash",
    "disabled_hash": "hash",
    "planned_collection_hash": "hash",
    "planned_count": "int",
    "created_by": "text",
    "counters": _COUNTERS,
    "malformed_lines": "int",
    "raw_stream_bytes": "int",
    "raw_stream_sha256": "optional-hash",
}
_ENDPOINT = {
    "role": "text",
    "artifacts": _ARTIFACTS,
    "header": _HEADER,
    "sidecar": dict.fromkeys(
        ("build_manifest_sha256", "installed_manifest_sha256", "source_archive_sha256"),
        "hash",
    ),
    "evidence": dict.fromkeys(
        (
            "ledger_sha256",
            "coverage_sha256",
            "raw_manifest_sha256",
            "obligations_sha256",
            "catalog_sha256",
            "selected_sha256",
        ),
        "hash",
    ),
    "catalog": ["text"],
    "selected": ["text"],
    "observed_selected": ["text"],
    "unselected": "reasons",
    "frozen_controls": _CONTROLS,
}
COMPARISON_ENVELOPE_V1 = {
    "schema_version": "int",
    "operation": "text",
    "allowed_axis": "text",
    "lane": "text",
    "protected": {
        "policy_sha256": "hash",
        "control_sha": "rev",
        "evaluator_sha": "rev",
        "prepare_sha256": "hash",
        "producer_authority_sha256": "hash",
        "selected_lane": "text",
        "selected_candidate_source_sha": "rev",
    },
    "frozen_controls": _CONTROLS,
    "endpoints": {"baseline": _ENDPOINT, "candidate": _ENDPOINT},
    "catalog_union": ["text"],
    "selected_union": ["text"],
    "reviewed_delta_refs": ["digest"],
}


def validate_shape(value: Any, schema: Any, path: str = "$") -> None:
    """Validate only the canonical schema; M03 owns actual endpoint bindings."""
    if value is None and path.endswith(".artifacts.proxy"):
        return
    if type(schema) is dict:
        if type(value) is not dict or set(value) != set(schema):
            raise ValueError(path + ": missing/extra fields")
        for key, child in schema.items():
            validate_shape(value[key], child, path + "." + key)
    elif type(schema) is list:
        if type(value) is not list or len(value) > 100000:
            raise ValueError(path + ": invalid roster")
        for child in value:
            validate_shape(child, schema[0], path + "[]")
    elif schema == "int":
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise ValueError(path + ": invalid integer")
    elif schema == "reasons":
        if type(value) is not dict or len(value) > 100000:
            raise ValueError(path + ": invalid reasons")
        for key, reason in value.items():
            validate_shape(key, "text", path)
            validate_shape(reason, "text", path)
    else:
        if type(value) is not str or not value or len(value) > 8192 or "\x00" in value:
            if schema == "optional-hash" and value == "":
                return
            raise ValueError(path + ": invalid string")
        pattern = {"hash": SHA, "rev": REV, "digest": DIGEST, "optional-hash": SHA}.get(
            schema
        )
        if pattern and not pattern.fullmatch(value):
            raise ValueError(path + ": malformed identity")


@dataclass(frozen=True)
class FrozenComparisonExpectation:
    serialized: bytes

    def as_dict(self) -> JsonObject:
        return load_json(self.serialized)


def freeze_comparison_expectation(value: JsonObject) -> FrozenComparisonExpectation:
    """Freeze a protected selection, checking its own internal consistency only.

    Caller must supply controller-owned values. No envelope/endpoint is accepted
    as authentic here; do not use this constructor as an endpoint validator.
    """
    validate_shape(value, COMPARISON_ENVELOPE_V1)
    axis = value["operation"]
    if (
        value["schema_version"] != 1
        or axis not in AXES
        or value["allowed_axis"] != axis
    ):
        raise ValueError("unknown version/axis")
    if value["lane"] != value["protected"]["selected_lane"]:
        raise ValueError("lane not selected")
    baseline, candidate = (value["endpoints"][r] for r in ("baseline", "candidate"))
    changed = {"provider" if axis == "image" else axis, "derivative"}
    for key in _ARTIFACTS:
        if (
            key not in changed
            and baseline["artifacts"][key] != candidate["artifacts"][key]
        ):
            raise ValueError("unselected artifact change: " + key)
    p, q = (e["artifacts"]["provider"] for e in (baseline, candidate))
    if (
        any(p[k] != q[k] for k in ("family", "platform"))
        or p["platform"] != "linux/amd64"
    ):
        raise ValueError("family/platform mismatch")
    selected = candidate["artifacts"]["provider" if axis == "image" else axis]
    if (
        selected is None
        or selected["source_sha"] != value["protected"]["selected_candidate_source_sha"]
    ):
        raise ValueError("selected source mismatch/absent proxy")
    for role, endpoint in value["endpoints"].items():
        if (
            endpoint["role"] != role
            or endpoint["frozen_controls"] != value["frozen_controls"]
        ):
            raise ValueError("role/control mismatch")
        if (
            endpoint["artifacts"]["derivative"]["parent_manifest_digest"]
            != endpoint["artifacts"]["provider"]["manifest_digest"]
        ):
            raise ValueError("wrong provider parent")
        for key in ("catalog", "selected", "observed_selected"):
            if endpoint[key] != sorted(set(endpoint[key])):
                raise ValueError("duplicate/noncanonical membership")
        if (
            not set(endpoint["selected"]) <= set(endpoint["catalog"])
            or endpoint["selected"] != endpoint["observed_selected"]
        ):
            raise ValueError("selected membership omission")
        if set(endpoint["unselected"]) != set(endpoint["catalog"]) - set(
            endpoint["selected"]
        ):
            raise ValueError("unselected reasons mismatch")
        for key in ("catalog", "selected"):
            if digest(endpoint[key]) != endpoint["evidence"][key + "_sha256"]:
                raise ValueError("membership hash mismatch")
    for key in ("catalog", "selected"):
        if value[key + "_union"] != sorted(set(baseline[key]) | set(candidate[key])):
            raise ValueError("union mismatch")
    return FrozenComparisonExpectation(canonical(value))


@dataclass(frozen=True)
class LocalProducerEvent:
    """Explicitly local controller provenance, with no CI/run/job claims."""

    repository: str
    source_sha: str
    attempt: str


@dataclass(frozen=True)
class VerifiedSource:
    archive: Path
    archive_sha256: str
    revision: str
    tree: str
    members: tuple[bytes, ...]  # canonical {path,sha256,size,mode} rows


@dataclass(frozen=True)
class SealedToolInputs:
    root: Path
    receipt_sha256: str
    python_members: tuple[bytes, ...]
    wheels: tuple[bytes, ...]
    lock: bytes
    requirements: tuple[str, ...]

    @classmethod
    def from_evaluator(cls, root: Path) -> SealedToolInputs:
        from .bootstrap import verify_receipt

        receipt_path = root / "evaluator-build-receipt.json"
        receipt_raw = read_source_archive(receipt_path)
        receipt_sha = hashlib.sha256(receipt_raw).hexdigest()
        receipt = load_json(receipt_raw, max_bytes=16 * 1024 * 1024)
        locks = Path(__file__).resolve().parents[1] / "data/rounds/evaluator"
        verify_receipt(receipt, root, locks)
        if hashlib.sha256(read_source_archive(receipt_path)).hexdigest() != receipt_sha:
            raise ValueError("evaluator receipt changed during tool selection")
        source = receipt["source"]
        return cls(
            root.resolve(),
            receipt_sha,
            tuple(canonical(row) for row in receipt["python_files"]),
            tuple(canonical(row) for row in source["build_wheels"]),
            (locks / "build-linux-amd64.lock").read_bytes(),
            tuple(
                sorted(f"{w['name']}=={w['version']}" for w in source["build_wheels"])
            ),
        )


def verified_evaluator_identity(root: Path) -> JsonObject:
    from .tool_identity import verified_evaluator_identity as verify_identity
    return verify_identity(root)


@dataclass(frozen=True)
class ProtectedSelection:
    expectation: FrozenComparisonExpectation
    builder_image: str
    builder_layers: tuple[str, ...]
    source_date_epoch: int
    builder_config_sha256: str


@dataclass(frozen=True)
class FrozenCandidateContext:
    serialized: bytes
    source: VerifiedSource
    tools: SealedToolInputs

    def as_dict(self) -> JsonObject:
        return load_json(self.serialized, max_bytes=16 * 1024 * 1024)


def freeze_candidate_context(
    protected_selection: ProtectedSelection,
    authenticated_event: LocalProducerEvent,
    verified_source: VerifiedSource,
    sealed_tool_inputs: SealedToolInputs,
) -> FrozenCandidateContext:
    """Freeze protected local inputs before any candidate-controlled execution."""
    if (
        type(protected_selection) is not ProtectedSelection
        or type(authenticated_event) is not LocalProducerEvent
        or type(verified_source) is not VerifiedSource
        or type(sealed_tool_inputs) is not SealedToolInputs
    ):
        raise TypeError(
            "typed protected controller inputs required; JSON is not authority"
        )
    selection, event, source, tools = (
        protected_selection,
        authenticated_event,
        verified_source,
        sealed_tool_inputs,
    )
    expectation = freeze_comparison_expectation(
        selection.expectation.as_dict()
    ).as_dict()
    for value in (source.revision, source.tree, event.source_sha):
        if not REV.fullmatch(value):
            raise ValueError("invalid source revision/tree")
    if (
        not SHA.fullmatch(source.archive_sha256)
        or hashlib.sha256(read_source_archive(source.archive)).hexdigest()
        != source.archive_sha256
        or event.source_sha != source.revision
        or source.revision != expectation["protected"]["selected_candidate_source_sha"]
    ):
        raise ValueError("source selection/archive mismatch")
    if (
        not event.repository.startswith("https://github.com/")
        or "?" in event.repository
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", event.attempt)
    ):
        raise ValueError("invalid local provenance")
    if not SHA.fullmatch(selection.builder_config_sha256):
        raise ValueError("unsealed builder config")
    if (
        not DIGEST.fullmatch(selection.builder_image)
        or not selection.builder_layers
        or any(not DIGEST.fullmatch(v) for v in selection.builder_layers)
    ):
        raise ValueError("unsealed builder identity")
    if type(selection.source_date_epoch) is not int or selection.source_date_epoch < 0:
        raise ValueError("invalid source epoch")
    members = [load_json(row) for row in source.members]
    names = []
    for row in members:
        validate_shape(
            row, {"path": "text", "sha256": "hash", "size": "int", "mode": "int"}
        )
        names.append(safe_path(row["path"]))
        if row["mode"] not in (0o400, 0o444, 0o644, 0o755):
            raise ValueError("unsupported source mode")
    if names != sorted(set(names)) or not names or len(names) > 10000:
        raise ValueError("invalid source membership")
    if (
        not SHA.fullmatch(tools.receipt_sha256)
        or not tools.python_members
        or not tools.wheels
        or not tools.lock
    ):
        raise ValueError("unsealed tools")
    context = {
        "schema_version": 1,
        "authority": {
            "scope": "local-controller",
            "repository": event.repository,
            "source_sha": event.source_sha,
            "attempt": event.attempt,
        },
        "expectation": expectation,
        "source": {
            "revision": source.revision,
            "tree": source.tree,
            "archive_sha256": source.archive_sha256,
            "members": members,
            "membership_sha256": digest(members),
        },
        "tools": {
            "receipt_sha256": tools.receipt_sha256,
            "python_members": [load_json(r) for r in tools.python_members],
            "wheels": [load_json(r) for r in tools.wheels],
            "lock_sha256": hashlib.sha256(tools.lock).hexdigest(),
            "requirements": list(tools.requirements),
        },
        "builder": {
            "image": selection.builder_image,
            "config_sha256": selection.builder_config_sha256,
            "layers": list(selection.builder_layers),
            "platform": "linux/amd64",
        },
        "source_date_epoch": selection.source_date_epoch,
    }
    return FrozenCandidateContext(canonical(context), source, tools)

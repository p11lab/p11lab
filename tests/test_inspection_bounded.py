"""Physical stream limits and failure journals for inert image inspection."""
import json
import sys
import time

import pytest


@pytest.mark.parametrize('identity', ['getuid', 'geteuid'])
def test_root_inspector_is_refused_before_journal_or_engine(tmp_path, monkeypatch, identity):
    from p11lab.inspection_bounded import BoundedInspection, InspectionPolicy
    from p11lab.models import ArtifactRef
    monkeypatch.setattr('os.' + identity, lambda: 0)
    class Engine:
        def image(self, artifact):
            pytest.fail('engine must not be reached')
    artifact = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    journal = tmp_path / 'journal.json'
    with pytest.raises(ValueError, match='nonroot'):
        BoundedInspection(artifact, InspectionPolicy(), journal, engine=Engine())
    assert not journal.exists()


def test_export_stream_stops_before_exceeding_limit(tmp_path):
    from p11lab.inspection_bounded import InspectionError, bounded_stream
    path = tmp_path / 'export.tar'
    record = {}
    with pytest.raises(InspectionError, match='limit'):
        bounded_stream([sys.executable, '-c', 'import os; os.write(1, b"x" * 1000000)'],
                       path, 65536, 10, {}, record)
    assert path.stat().st_size <= 65536
    assert record['overflow'] is True


def test_export_stream_timeout_reaps_process(tmp_path):
    from p11lab.inspection_bounded import InspectionError, bounded_stream
    record = {}
    start = time.monotonic()
    with pytest.raises(InspectionError, match='deadline'):
        bounded_stream([sys.executable, '-c', 'import time; time.sleep(10)'],
                       tmp_path / 'save.tar', 65536, .15, {}, record)
    assert time.monotonic() - start < 5
    assert record['timed_out'] is True


def test_inspection_creation_uncertainty_is_retained(tmp_path):
    from p11lab.inspection_bounded import BoundedInspection, InspectionError, InspectionPolicy
    from p11lab.docker import DockerError
    from p11lab.models import ArtifactRef
    class Engine:
        def image(self, artifact):
            return {'Id': artifact.reference, 'Config': {}, 'RootFS': {'Layers': []}}
        def create(self, image, argv, options, labels, name):
            raise DockerError('ambiguous creation', uncertain_resource=('container', name))
    artifact = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    journal = tmp_path / 'journal.json'
    inspection = BoundedInspection(artifact, InspectionPolicy(), journal, engine=Engine())
    with pytest.raises(InspectionError, match='creation'):
        inspection.export(tmp_path / 'out.tar')
    data = json.loads(journal.read_text())
    assert data['cleanup']['status'] == 'creation-uncertain'
    assert data['cleanup']['uncertain_name'].startswith('p11lab-inspect-')


def test_save_cannot_bypass_export_or_cleanup(tmp_path, monkeypatch):
    from p11lab.inspection_bounded import BoundedInspection, InspectionError, InspectionPolicy
    from p11lab.models import ArtifactRef
    class Engine:
        def image(self, artifact):
            return {'Id': artifact.reference, 'Config': {}, 'RootFS': {'Layers': []}}
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    inspector = BoundedInspection(image, InspectionPolicy(), tmp_path / 'journal.json', engine=Engine())
    monkeypatch.setattr('p11lab.inspection_bounded.bounded_stream', lambda *args: pytest.fail('must not save'))
    with pytest.raises(InspectionError, match='export'):
        inspector.save(tmp_path / 'save.tar')


def test_inspection_cleanup_failure_is_retained(tmp_path, monkeypatch):
    from p11lab.inspection_bounded import BoundedInspection, InspectionError, InspectionPolicy
    from p11lab.docker import DockerError
    from p11lab.models import ArtifactRef
    class Engine:
        env = {}
        def image(self, artifact):
            return {'Id': artifact.reference, 'Config': {}, 'RootFS': {'Layers': []}}
        def create(self, image, argv, options, labels, name):
            self.labels = labels
            return 'a' * 64
        def command(self, args):
            from p11lab.docker import CommandResult
            observed = {'Id': 'a' * 64, 'Image': 'sha256:' + 'b' * 64,
                        'Config': {'Labels': self.labels}, 'State': {'Running': False, 'Pid': 0}}
            return CommandResult(0, json.dumps([observed]), '')
        def remove(self, kind, identity, labels):
            raise DockerError('removal refused')
    artifact = ArtifactRef('docker-local', 'sha256:' + 'b' * 64, 'b' * 64, 'linux/amd64')
    journal = tmp_path / 'journal.json'
    inspection = BoundedInspection(artifact, InspectionPolicy(), journal, engine=Engine())
    monkeypatch.setattr('p11lab.inspection_bounded.bounded_stream', lambda *args: None)
    with pytest.raises(InspectionError, match='cleanup'):
        inspection.export(tmp_path / 'out.tar')
    assert json.loads(journal.read_text())['cleanup']['status'] == 'failed'


def test_wrong_inspection_container_image_fails_before_export_and_cleans(tmp_path, monkeypatch):
    from p11lab.inspection_bounded import BoundedInspection, InspectionError, InspectionPolicy
    from p11lab.docker import CommandResult
    from p11lab.models import ArtifactRef
    class Engine:
        env = {}
        removed = False
        def image(self, artifact):
            return {'Id': artifact.reference, 'Config': {}, 'RootFS': {'Layers': []}}
        def create(self, image, argv, options, labels, name):
            self.labels = labels
            return 'a' * 64
        def command(self, args):
            observed = {'Id': 'a' * 64, 'Image': 'sha256:' + 'c' * 64,
                        'Config': {'Labels': self.labels}, 'State': {'Running': False, 'Pid': 0}}
            return CommandResult(0, json.dumps([observed]), '')
        def remove(self, kind, identity, labels):
            self.removed = True
    engine = Engine()
    artifact = ArtifactRef('docker-local', 'sha256:' + 'b' * 64, 'b' * 64, 'linux/amd64')
    inspection = BoundedInspection(artifact, InspectionPolicy(), tmp_path / 'journal.json', engine=engine)
    monkeypatch.setattr('p11lab.inspection_bounded.bounded_stream', lambda *args: pytest.fail('must not export'))
    with pytest.raises(InspectionError, match='identity'):
        inspection.export(tmp_path / 'out.tar')
    assert engine.removed


def test_bounded_inspector_parser_failure_is_journaled(tmp_path, monkeypatch):
    from p11lab.licenses import inspect_artifact
    from p11lab.sources import SourceError
    from p11lab.models import ArtifactRef
    class FakeInspection:
        def __init__(self, artifact, policy, journal):
            self.journal = journal
            self.image = {'Id': artifact.reference, 'Os': 'linux', 'Architecture': 'amd64'}
        def export(self, destination):
            destination.write_bytes(b'not an archive')
        def fail(self, error):
            self.journal.write_text(json.dumps({'status': 'failed', 'error_type': type(error).__name__}))
    monkeypatch.setattr('p11lab.inspection_bounded.BoundedInspection', FakeInspection)
    image = ArtifactRef('docker-local', 'sha256:' + 'b' * 64, 'b' * 64, 'linux/amd64')
    journal = tmp_path / 'journal.json'
    with pytest.raises(SourceError, match='inspection'):
        inspect_artifact(image, inspection_policy=object(), journal_path=journal)
    assert json.loads(journal.read_text())['status'] == 'failed'

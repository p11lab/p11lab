# SPDX-License-Identifier: Apache-2.0
"""Trusted checker public-API bridge for one frozen local-image N1 stream."""
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
import sys

from pkcs11_check.core.evidence import (PredeclaredRoster, ShardExpectation, admit_lane,
                                       compile_obligations, export_ledger, load_ledger, shard_digest)
from pkcs11_check.core.report_log import SessionCompletionTracker, iter_report_log_records


def main():
    raw, plan_path, output = map(Path, sys.argv[1:])
    plan = json.loads(plan_path.read_bytes())
    raw_bytes = raw.read_bytes()
    identity = dict(plan['identity'])
    identity.update(raw_stream_sha256=hashlib.sha256(raw_bytes).hexdigest(), raw_stream_bytes=str(len(raw_bytes)))
    identity['planned_count'] = str(identity['planned_count'])
    invalid = 0
    tracker = SessionCompletionTracker()
    observed_nodes = set()

    def bad():
        nonlocal invalid
        invalid += 1
        tracker.invalidate()

    def records():
        for record in iter_report_log_records(raw, on_invalid=bad):
            tracker.observe(record)
            if record.get('$report_type') == 'TestReport':
                observed_nodes.add(record.get('nodeid'))
            yield record

    with output.open('x', encoding='utf-8') as sink:
        export_ledger(records(), identity, sink, reader_invalid_lines=lambda: invalid)
    header, rows = load_ledger(output)
    selected, catalog = plan['selected'], plan['catalog']
    if (not tracker.complete or invalid or tracker.starts != tracker.finishes
            or observed_nodes != set(selected) or len(catalog) != len(set(catalog))
            or len(selected) != len(set(selected)) or not set(selected) <= set(catalog)):
        raise ValueError('incomplete framing or changed frozen test roster')
    if (header.lane != identity['lane'] or header.planned_count != len(selected)
            or header.planned_collection_hash != identity['planned_collection_hash']):
        raise ValueError('exported identity or plan mismatch')
    obligations = compile_obligations({node: {} for node in catalog}, {'cases': selected})
    roster = PredeclaredRoster(lane=identity['lane'], shards={identity['shard_id']:
        ShardExpectation(records=len(rows), sha256=shard_digest(rows))})
    verdict = admit_lane(header, rows, roster, obligations)
    result = {'admission': asdict(verdict), 'starts': tracker.starts, 'finishes': tracker.finishes,
              'single_exitstatus': tracker.single_exitstatus, 'invalid_lines': invalid,
              'rows': len(rows), 'shard_sha256': shard_digest(rows),
              'ledger_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}
    print(json.dumps(result, sort_keys=True))
    if not verdict.admitted:
        raise ValueError('public evaluator rejected lane')


if __name__ == '__main__':
    main()

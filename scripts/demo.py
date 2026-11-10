"""Replay synthetic events through the same Python worker used by Lambda."""

import json

from sentinela.model import BASELINE
from sentinela.processor import Processor
from tests.support import DRIFTED, MemoryBucket, MemoryJournal, MemoryNotifier, fixture, settings


def replay():
    event = fixture("cloudtrail")
    results = {}
    for mode in ("observe", "enforce"):
        journal = MemoryJournal()
        bucket = MemoryBucket(DRIFTED)
        notifier = MemoryNotifier()
        worker = Processor(settings(mode), journal, bucket, notifier, lambda: 1794250800)
        result = {
            "result": worker.process(event),
            "bucket_writes": bucket.writes,
            "current_bucket_flags": bucket.read(),
            "evidence": next(iter(journal.items.values()))["evidence"],
        }
        if mode == "enforce":
            result["redelivery"] = worker.process(event)
            result["guardduty"] = worker.process(fixture("guardduty"))
            result["notification_count"] = len(notifier.alerts)
            assert bucket.snapshot == BASELINE
        results[mode] = result
    return {"environment": "offline_synthetic", **results}


if __name__ == "__main__":
    print(json.dumps(replay(), indent=2, sort_keys=True))

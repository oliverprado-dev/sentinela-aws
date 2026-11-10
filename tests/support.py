"""Deterministic test adapters used by the offline demonstration."""

import json
from copy import deepcopy
from pathlib import Path

from sentinela.model import BASELINE, Settings
from sentinela.processor import IncidentBusy, Lease

ACCOUNT = "111122223333"
REGION = "us-east-1"
BUCKET = "sentinela-aws-lab-exemplo"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/sentinela-aws-worker"
SCHEDULE = f"arn:aws:events:{REGION}:{ACCOUNT}:rule/sentinela-aws-reconcile"
DRIFTED = {**BASELINE, "BlockPublicPolicy": False}


def settings(mode="enforce"):
    return Settings(ACCOUNT, REGION, BUCKET, ROLE, SCHEDULE, mode)


def fixture(name):
    path = Path(__file__).with_name("fixtures") / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def sqs_record(identifier, payload):
    return {"messageId": identifier, "body": json.dumps(payload)}


class MemoryJournal:
    def __init__(self):
        self.items = {}

    def exists(self, signal):
        return signal.incident_id in self.items

    def acquire(self, signal, token, now):
        item = self.items.setdefault(
            signal.incident_id, {"signal": signal.record(), "phase": "check", "evidence": {}}
        )
        if item["phase"] == "done":
            return None
        if item.get("lease_until", 0) > now:
            raise IncidentBusy()
        item.update(lease_until=now + 60, lock_token=token)
        return Lease(item["phase"], deepcopy(item["evidence"]))

    def advance(self, signal, token, phase, evidence, now):
        item = self.items[signal.incident_id]
        if item["lock_token"] != token or item["lease_until"] <= now:
            raise IncidentBusy()
        item.update(phase=phase, evidence=deepcopy(evidence))
        return Lease(phase, evidence)


class MemoryBucket:
    def __init__(self, snapshot):
        self.snapshot = deepcopy(snapshot)
        self.reads = 0
        self.writes = 0
        self.before_write = lambda: None
        self.fail_on_read = None

    def read(self):
        self.reads += 1
        if self.reads == self.fail_on_read:
            raise TimeoutError("Test read failure")
        return deepcopy(self.snapshot)

    def apply_baseline(self):
        self.before_write()
        self.writes += 1
        self.snapshot = BASELINE.copy()


class MemoryNotifier:
    def __init__(self):
        self.alerts = []
        self.fail = False

    def publish(self, signal, evidence):
        if self.fail:
            raise TimeoutError("Test notification failure")
        self.alerts.append({"signal": signal.record(), "evidence": deepcopy(evidence)})

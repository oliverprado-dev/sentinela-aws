"""Execute the incident state machine with recoverable transitions."""

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from time import time
from typing import Protocol
from uuid import uuid4

from .model import BASELINE, Settings, Signal, Snapshot, normalize

logger = logging.getLogger(__name__)


class IncidentBusy(RuntimeError):
    """Another invocation holds the incident lease."""


class BaselineUnverified(RuntimeError):
    """A post-write read did not confirm all four flags."""


@dataclass(frozen=True)
class Lease:
    phase: str
    evidence: dict


class Journal(Protocol):
    def exists(self, signal: Signal) -> bool: ...

    def acquire(self, signal: Signal, token: str, now: int) -> Lease | None: ...

    def advance(
        self, signal: Signal, token: str, phase: str, evidence: dict, now: int
    ) -> Lease: ...


class Bucket(Protocol):
    def read(self) -> Snapshot: ...

    def apply_baseline(self) -> None: ...


class Notifier(Protocol):
    def publish(self, signal: Signal, evidence: dict) -> None: ...


class Processor:
    def __init__(
        self,
        scope: Settings,
        journal: Journal,
        bucket: Bucket,
        notifier: Notifier,
        clock: Callable[[], float] = time,
    ):
        self.scope = scope
        self.journal = journal
        self.bucket = bucket
        self.notifier = notifier
        self.clock = clock

    def process(self, payload: object) -> str:
        signal = normalize(payload, self.scope)
        if signal is None:
            return "ignored"

        snapshot = None
        if signal.source == "reconciliation":
            snapshot = self.bucket.read()
            # A healthy scheduled check creates no incident. A check recovering
            # after a write must still finish any incident already journaled.
            if snapshot == BASELINE and not self.journal.exists(signal):
                return "healthy"

        token = uuid4().hex
        lease = self.journal.acquire(signal, token, int(self.clock()))
        if lease is None:
            return "duplicate"

        if lease.phase == "check":
            if signal.source == "guardduty":
                lease = self._advance(signal, token, "notify", {"outcome": "triage_required"})
            else:
                before = snapshot if signal.source == "reconciliation" else self.bucket.read()
                evidence = {"before": before, "desired": BASELINE, "mode": self.scope.mode}
                if before == BASELINE:
                    evidence.update(outcome="already_compliant", after=before)
                    lease = self._advance(signal, token, "done", evidence)
                elif self.scope.mode == "observe":
                    evidence.update(outcome="would_remediate", after=None)
                    lease = self._advance(signal, token, "notify", evidence)
                else:
                    evidence.update(outcome="remediation_planned", after=None)
                    lease = self._advance(signal, token, "apply", evidence)

        if lease.phase == "apply":
            evidence = {**lease.evidence, "mode": self.scope.mode}
            current = self.bucket.read()
            if current == BASELINE:
                evidence.update(outcome="baseline_verified", after=current)
            elif self.scope.mode == "observe":
                evidence.update(outcome="would_remediate", after=None)
            else:
                self.bucket.apply_baseline()
                after = self.bucket.read()
                if after != BASELINE:
                    raise BaselineUnverified("Bucket-level baseline was not verified")
                evidence.update(outcome="remediated", after=after)
            lease = self._advance(signal, token, "notify", evidence)

        if lease.phase == "notify":
            self.notifier.publish(signal, lease.evidence)
            lease = self._advance(signal, token, "done", lease.evidence)

        outcome = lease.evidence["outcome"]
        logger.info(
            "Incident completed",
            extra={
                "event": "incident_completed",
                "incident_id": signal.incident_id,
                "outcome": outcome,
            },
        )
        return outcome

    def _advance(self, signal: Signal, token: str, phase: str, evidence: dict) -> Lease:
        return self.journal.advance(signal, token, phase, evidence, int(self.clock()))


def handle_batch(event: dict, processor: Processor) -> dict:
    """Acknowledge successful SQS records and retry only the records that failed."""
    failures = []
    for record in event["Records"]:
        message_id = record["messageId"]
        try:
            processor.process(json.loads(record["body"]))
        except Exception as exc:
            # Event bodies and AWS exception strings can contain sensitive fields.
            logger.warning(
                "SQS record failed",
                extra={
                    "event": "processing_failed",
                    "sqs_message_id": message_id,
                    "error_type": type(exc).__name__,
                    "aws_error": getattr(exc, "response", {}).get("Error", {}).get("Code"),
                },
            )
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}

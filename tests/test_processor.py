import json
import unittest

from sentinela.model import BASELINE, InvalidEvent, normalize
from sentinela.processor import IncidentBusy, Processor, handle_batch
from tests.support import (
    DRIFTED,
    ROLE,
    MemoryBucket,
    MemoryJournal,
    MemoryNotifier,
    fixture,
    settings,
    sqs_record,
)


class ProcessorTest(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.journal = MemoryJournal()
        self.bucket = MemoryBucket(DRIFTED)
        self.notifier = MemoryNotifier()
        self.event = fixture("cloudtrail")
        self.incident_id = normalize(self.event, settings()).incident_id
        self.processor = self.make_processor()

    def make_processor(self, mode="enforce"):
        return Processor(settings(mode), self.journal, self.bucket, self.notifier, lambda: self.now)

    def test_observe_records_drift_without_writing(self):
        self.assertEqual(self.make_processor("observe").process(self.event), "would_remediate")
        evidence = self.journal.items[self.incident_id]["evidence"]
        self.assertEqual(evidence["before"], DRIFTED)
        self.assertIsNone(evidence["after"])
        self.assertEqual(evidence["desired"], BASELINE)
        self.assertEqual(self.bucket.writes, 0)
        self.assertEqual(self.bucket.snapshot, DRIFTED)
        self.assertEqual(len(self.notifier.alerts), 1)

    def test_enforce_persists_before_state_before_the_write(self):
        def check_evidence():
            item = self.journal.items[self.incident_id]
            self.assertEqual(item["phase"], "apply")
            self.assertEqual(item["evidence"]["before"], DRIFTED)

        self.bucket.before_write = check_evidence
        self.assertEqual(self.processor.process(self.event), "remediated")
        self.assertEqual(self.bucket.writes, 1)
        self.assertEqual(self.journal.items[self.incident_id]["evidence"]["after"], BASELINE)
        self.assertEqual(self.journal.items[self.incident_id]["phase"], "done")

    def test_s3_configuration_deleted(self):
        self.bucket.snapshot = None
        self.event["detail"]["eventName"] = "DeleteBucketPublicAccessBlock"
        self.assertEqual(self.processor.process(self.event), "remediated")
        self.assertIsNone(self.journal.items[self.incident_id]["evidence"]["before"])

    def test_duplicate_cloudtrail_with_new_eventbridge_id(self):
        self.assertEqual(self.processor.process(self.event), "remediated")
        self.event["id"] = "a-new-eventbridge-id"
        self.assertEqual(self.processor.process(self.event), "duplicate")
        self.assertEqual(self.bucket.writes, 1)
        self.assertEqual(len(self.notifier.alerts), 1)

    def test_duplicate_guardduty_revision_and_new_revision(self):
        event = fixture("guardduty")
        self.assertEqual(self.processor.process(event), "triage_required")
        event["id"] = "a-new-eventbridge-id"
        self.assertEqual(self.processor.process(event), "duplicate")
        event["detail"]["updatedAt"] = "2026-11-09T19:10:00Z"
        self.assertEqual(self.processor.process(event), "triage_required")
        self.assertEqual(len(self.notifier.alerts), 2)
        self.assertEqual(self.bucket.reads, 0)

    def test_guardduty_scope_and_filters(self):
        for field, value in (
            ("accountId", "999988887777"),
            ("region", "us-west-2"),
            ("type", "Policy:S3/BucketPublicAccessGranted"),
            ("severity", 3.9),
            ("service", {"archived": True}),
        ):
            with self.subTest(field=field):
                event = fixture("guardduty")
                event["detail"][field] = value
                self.assertEqual(self.processor.process(event), "ignored")
        self.assertEqual(self.notifier.alerts, [])

    def test_guardduty_rejects_nonfinite_or_nonnumeric_severity(self):
        for severity in (True, "8.0", float("nan"), float("inf"), 11):
            with self.subTest(severity=severity):
                event = fixture("guardduty")
                event["detail"]["severity"] = severity
                with self.assertRaises(InvalidEvent):
                    self.processor.process(event)

    def test_cloudtrail_scope_and_self_event(self):
        events = [fixture("cloudtrail") for _ in range(6)]
        events[0]["account"] = "999988887777"
        events[1]["detail"]["recipientAccountId"] = "999988887777"
        events[2]["region"] = "us-west-2"
        events[3]["detail"]["requestParameters"]["bucketName"] = "out-of-scope-bucket"
        events[4]["detail"]["errorCode"] = "AccessDenied"
        events[5]["detail"]["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = ROLE
        for event in events:
            with self.subTest(event_id=event["id"], detail=event["detail"]):
                self.assertEqual(self.processor.process(event), "ignored")
        self.assertEqual(self.bucket.reads, 0)
        self.assertEqual(self.journal.items, {})

    def test_stale_cloudtrail_does_not_write_a_compliant_bucket(self):
        self.bucket.snapshot = BASELINE.copy()
        self.assertEqual(self.processor.process(self.event), "already_compliant")
        self.assertEqual(self.bucket.writes, 0)
        self.assertEqual(self.notifier.alerts, [])

    def test_post_write_failure_resumes_from_original_evidence(self):
        self.bucket.fail_on_read = 3
        with self.assertRaises(TimeoutError):
            self.processor.process(self.event)
        self.assertEqual(self.journal.items[self.incident_id]["phase"], "apply")
        with self.assertRaises(IncidentBusy):
            self.processor.process(self.event)
        self.now += 61
        self.assertEqual(self.processor.process(self.event), "baseline_verified")
        self.assertEqual(self.bucket.writes, 1)
        self.assertEqual(self.notifier.alerts[0]["evidence"]["before"], DRIFTED)

    def test_sns_failure_retries_without_another_s3_write(self):
        self.notifier.fail = True
        with self.assertRaises(TimeoutError):
            self.processor.process(self.event)
        self.assertEqual(self.journal.items[self.incident_id]["phase"], "notify")
        self.notifier.fail = False
        self.now += 61
        self.assertEqual(self.processor.process(self.event), "remediated")
        self.assertEqual(self.bucket.writes, 1)
        self.assertEqual(len(self.notifier.alerts), 1)

    def test_switch_to_observe_disarms_a_pending_write(self):
        self.bucket.fail_on_read = 2
        with self.assertRaises(TimeoutError):
            self.processor.process(self.event)
        self.now += 61
        self.assertEqual(self.make_processor("observe").process(self.event), "would_remediate")
        self.assertEqual(self.bucket.writes, 0)

    def test_reconciliation_catches_missed_cloudtrail_and_stays_quiet_when_healthy(self):
        event = fixture("scheduled")
        self.bucket.snapshot = BASELINE.copy()
        self.assertEqual(self.processor.process(event), "healthy")
        self.assertEqual(self.journal.items, {})
        self.bucket.snapshot = DRIFTED.copy()
        self.assertEqual(self.processor.process(event), "remediated")
        self.assertEqual(self.processor.process(event), "duplicate")

    def test_reconciliation_retries_notification_after_state_is_restored(self):
        event = fixture("scheduled")
        self.notifier.fail = True
        with self.assertRaises(TimeoutError):
            self.processor.process(event)
        self.notifier.fail = False
        self.now += 61
        self.assertEqual(self.processor.process(event), "remediated")
        self.assertEqual(self.bucket.writes, 1)

    def test_reconciliation_requires_the_exact_rule_arn(self):
        event = fixture("scheduled")
        event["resources"] = ["arn:aws:events:us-east-1:111122223333:rule/other"]
        self.assertEqual(self.processor.process(event), "ignored")
        self.assertEqual(self.bucket.reads, 0)

    def test_sqs_returns_only_failed_ids(self):
        malformed = fixture("cloudtrail")
        del malformed["detail"]["eventTime"]
        result = handle_batch(
            {
                "Records": [
                    {"messageId": "bad-json", "body": "{bad"},
                    sqs_record("valid", self.event),
                    sqs_record("bad-event", malformed),
                    {"messageId": "unrelated", "body": json.dumps({"source": "other"})},
                ]
            },
            self.processor,
        )
        self.assertEqual(
            result,
            {
                "batchItemFailures": [
                    {"itemIdentifier": "bad-json"},
                    {"itemIdentifier": "bad-event"},
                ]
            },
        )
        self.assertEqual(self.bucket.writes, 1)

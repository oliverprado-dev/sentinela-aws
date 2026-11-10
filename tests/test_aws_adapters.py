import json
import os
import unittest
from unittest.mock import patch

try:
    import boto3
    from botocore.exceptions import ClientError
    from botocore.stub import Stubber
    from moto import mock_aws
    from moto.core import DEFAULT_ACCOUNT_ID
except ImportError:
    mock_aws = None

from sentinela.model import BASELINE, Settings, normalize
from sentinela.processor import IncidentBusy
from tests.support import BUCKET, DRIFTED, REGION, ROLE, SCHEDULE, fixture, sqs_record


@unittest.skipUnless(mock_aws is not None, "Install the development lock for AWS adapter tests")
class AwsAdapterTest(unittest.TestCase):
    def setUp(self):
        from sentinela.aws import DynamoJournal, S3Bucket

        self.mock = mock_aws()
        self.mock.start()
        self.addCleanup(self.mock.stop)
        self.scope = Settings(DEFAULT_ACCOUNT_ID, REGION, BUCKET, ROLE, SCHEDULE, "enforce")
        self.s3 = boto3.client("s3", region_name=REGION)
        self.s3.create_bucket(Bucket=BUCKET)
        self.bucket = S3Bucket(self.s3, self.scope)
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        self.table = dynamodb.create_table(
            TableName="incidents",
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "incident_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "incident_id", "AttributeType": "S"}],
        )
        self.journal = DynamoJournal(self.table, 30)
        self.event = fixture("cloudtrail")
        self.event["account"] = DEFAULT_ACCOUNT_ID
        self.event["detail"]["recipientAccountId"] = DEFAULT_ACCOUNT_ID
        self.signal = normalize(self.event, self.scope)

    def test_conditional_lease_and_completion(self):
        self.assertFalse(self.journal.exists(self.signal))
        self.assertEqual(self.journal.acquire(self.signal, "first", 1000).phase, "check")
        self.assertTrue(self.journal.exists(self.signal))
        with self.assertRaises(IncidentBusy):
            self.journal.acquire(self.signal, "racing", 1001)

        lease = self.journal.advance(self.signal, "first", "apply", {"before": None}, 1002)
        self.assertEqual(lease.phase, "apply")
        self.assertEqual(self.journal.acquire(self.signal, "second", 1060), lease)
        with self.assertRaises(ClientError):
            self.journal.advance(self.signal, "first", "done", {}, 1061)

        self.journal.advance(self.signal, "second", "done", {"outcome": "baseline_verified"}, 1061)
        self.assertIsNone(self.journal.acquire(self.signal, "third", 2000))
        item = self.table.get_item(Key={"incident_id": self.signal.incident_id})["Item"]
        self.assertNotIn("lock_token", item)
        self.assertEqual(item["expires_at"], 1060 + 30 * 86400)

    def test_s3_stubber_distinguishes_absent_config_and_permission_errors(self):
        target = {"Bucket": BUCKET, "ExpectedBucketOwner": DEFAULT_ACCOUNT_ID}
        with Stubber(self.s3) as stub:
            stub.add_client_error(
                "get_public_access_block",
                service_error_code="NoSuchPublicAccessBlockConfiguration",
                http_status_code=404,
                expected_params=target,
            )
            stub.add_client_error(
                "get_public_access_block",
                service_error_code="AccessDenied",
                http_status_code=403,
                expected_params=target,
            )
            stub.add_response(
                "put_public_access_block",
                {},
                {**target, "PublicAccessBlockConfiguration": BASELINE},
            )
            self.assertIsNone(self.bucket.read())
            with self.assertRaises(ClientError):
                self.bucket.read()
            self.bucket.apply_baseline()
            stub.assert_no_pending_responses()

    def test_full_event_with_real_sdk_adapters_and_emulated_services(self):
        from sentinela.entrypoint import _processor, handler

        self.s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=DRIFTED)
        sns = boto3.client("sns", region_name=REGION)
        topic = sns.create_topic(Name="alerts")["TopicArn"]
        sqs = boto3.client("sqs", region_name=REGION)
        queue = sqs.create_queue(QueueName="test-alerts")["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)

        environment = {
            "AWS_REGION": REGION,
            "AWS_DEFAULT_REGION": REGION,
            "TARGET_ACCOUNT": DEFAULT_ACCOUNT_ID,
            "LAB_BUCKET": BUCKET,
            "WORKER_ROLE_ARN": ROLE,
            "RECONCILIATION_RULE_ARN": SCHEDULE,
            "RESPONSE_MODE": "enforce",
            "RETENTION_DAYS": "30",
            "INCIDENT_TABLE": self.table.name,
            "ALERTS_TOPIC_ARN": topic,
        }
        self.addCleanup(_processor.cache_clear)
        with patch.dict(os.environ, environment):
            response = handler(
                {
                    "Records": [
                        sqs_record("delivery-one", self.event),
                        sqs_record("redelivery", self.event),
                    ]
                },
                None,
            )
        self.assertEqual(response, {"batchItemFailures": []})
        self.assertEqual(self.bucket.read(), BASELINE)
        item = self.table.get_item(Key={"incident_id": self.signal.incident_id})["Item"]
        self.assertEqual(item["phase"], "done")
        self.assertEqual(item["evidence"]["before"], DRIFTED)
        messages = sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=10)["Messages"]
        self.assertEqual(len(messages), 1)
        notification = json.loads(json.loads(messages[0]["Body"])["Message"])
        self.assertEqual(notification["evidence"]["outcome"], "remediated")

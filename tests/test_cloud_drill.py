import unittest
from unittest.mock import Mock

from scripts.cloud_drill import check_preconditions
from sentinela.model import BASELINE
from tests.support import ACCOUNT, BUCKET, DRIFTED


class CloudDrillTest(unittest.TestCase):
    def setUp(self):
        self.outputs = {
            "account_id": {"value": ACCOUNT},
            "lab_bucket": {"value": BUCKET},
            "response_mode": {"value": "enforce"},
        }
        self.aws = Mock()
        self.responses = [
            {"Account": ACCOUNT},
            {"PublicAccessBlockConfiguration": BASELINE},
            {},
            {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}},
            {"PolicyStatus": {"IsPublic": False}},
            {"PublicAccessBlockConfiguration": BASELINE},
        ]

    def test_accepts_private_empty_lab_with_full_account_protection(self):
        self.aws.side_effect = self.responses
        target = check_preconditions(self.aws, self.outputs)
        self.assertEqual(target, ("--bucket", BUCKET, "--expected-bucket-owner", ACCOUNT))
        self.assertEqual(self.aws.call_count, 6)

    def test_refuses_mismatched_account_or_partial_account_protection(self):
        for responses in (
            [{"Account": "999988887777"}],
            [{"Account": ACCOUNT}, {"PublicAccessBlockConfiguration": DRIFTED}],
        ):
            with self.subTest(responses=responses):
                self.aws.side_effect = responses
                with self.assertRaises(RuntimeError):
                    check_preconditions(self.aws, self.outputs)

    def test_refuses_a_bucket_with_a_delete_marker(self):
        self.responses[2] = {"DeleteMarkers": [{"Key": "example"}]}
        self.aws.side_effect = self.responses
        with self.assertRaisesRegex(RuntimeError, "vazio"):
            check_preconditions(self.aws, self.outputs)
        self.assertEqual(self.aws.call_count, 3)

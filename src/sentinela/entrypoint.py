"""Lambda entry point for SQS."""

import os
from functools import cache

from .model import Settings
from .processor import Processor, handle_batch


@cache
def _processor() -> Processor:
    import boto3
    from botocore.config import Config

    from .aws import DynamoJournal, S3Bucket, SnsNotifier

    scope = Settings(
        account=os.environ["TARGET_ACCOUNT"],
        region=os.environ["AWS_REGION"],
        bucket=os.environ["LAB_BUCKET"],
        role_arn=os.environ["WORKER_ROLE_ARN"],
        schedule_arn=os.environ["RECONCILIATION_RULE_ARN"],
        mode=os.environ["RESPONSE_MODE"],
        retention_days=int(os.environ["RETENTION_DAYS"]),
    )
    sdk = Config(
        connect_timeout=2,
        read_timeout=3,
        retries={"mode": "standard", "total_max_attempts": 2},
    )
    table = boto3.resource("dynamodb", config=sdk).Table(os.environ["INCIDENT_TABLE"])
    return Processor(
        scope,
        DynamoJournal(table, scope.retention_days),
        S3Bucket(boto3.client("s3", config=sdk), scope),
        SnsNotifier(boto3.client("sns", config=sdk), os.environ["ALERTS_TOPIC_ARN"]),
    )


def handler(event, context):
    return handle_batch(event, _processor())

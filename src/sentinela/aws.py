"""AWS SDK adapters for scoped S3 writes, a DynamoDB journal, and SNS."""

import json

from botocore.exceptions import ClientError

from .model import BASELINE, Settings, Signal, Snapshot
from .processor import IncidentBusy, Lease

LEASE_SECONDS = 60


class DynamoJournal:
    def __init__(self, table, retention_days: int):
        self.table = table
        self.retention_seconds = retention_days * 86400

    def _get(self, signal: Signal) -> dict:
        return self.table.get_item(
            Key={"incident_id": signal.incident_id}, ConsistentRead=True
        ).get("Item", {})

    def exists(self, signal: Signal) -> bool:
        return bool(self._get(signal))

    def acquire(self, signal: Signal, token: str, now: int) -> Lease | None:
        try:
            response = self.table.update_item(
                Key={"incident_id": signal.incident_id},
                ConditionExpression=(
                    "attribute_not_exists(incident_id) OR (#phase <> :done AND lease_until <= :now)"
                ),
                UpdateExpression=(
                    "SET #phase = if_not_exists(#phase, :check), "
                    "#signal = if_not_exists(#signal, :signal), "
                    "created_at = if_not_exists(created_at, :now), "
                    "updated_at = :now, lease_until = :lease, lock_token = :token, "
                    "expires_at = :ttl"
                ),
                ExpressionAttributeNames={"#phase": "phase", "#signal": "signal"},
                ExpressionAttributeValues={
                    ":done": "done",
                    ":check": "check",
                    ":signal": signal.record(),
                    ":now": now,
                    ":lease": now + LEASE_SECONDS,
                    ":token": token,
                    ":ttl": now + self.retention_seconds,
                },
                ReturnValues="ALL_NEW",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            if self._get(signal).get("phase") == "done":
                return None
            raise IncidentBusy("Incident lease is held") from exc

        item = response["Attributes"]
        return Lease(item["phase"], item.get("evidence", {}))

    def advance(self, signal: Signal, token: str, phase: str, evidence: dict, now: int) -> Lease:
        update = "SET #phase = :phase, #evidence = :evidence, updated_at = :now"
        if phase == "done":
            update += " REMOVE lock_token, lease_until"
        self.table.update_item(
            Key={"incident_id": signal.incident_id},
            ConditionExpression="lock_token = :token AND lease_until > :now",
            UpdateExpression=update,
            ExpressionAttributeNames={"#phase": "phase", "#evidence": "evidence"},
            ExpressionAttributeValues={
                ":token": token,
                ":phase": phase,
                ":evidence": evidence,
                ":now": now,
            },
        )
        return Lease(phase, evidence)


class S3Bucket:
    def __init__(self, client, scope: Settings):
        self.client = client
        self.target = {"Bucket": scope.bucket, "ExpectedBucketOwner": scope.account}

    def read(self) -> Snapshot:
        try:
            result = self.client.get_public_access_block(**self.target)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise
        config = result["PublicAccessBlockConfiguration"]
        return {flag: config.get(flag) is True for flag in BASELINE}

    def apply_baseline(self) -> None:
        self.client.put_public_access_block(**self.target, PublicAccessBlockConfiguration=BASELINE)


class SnsNotifier:
    def __init__(self, client, topic_arn: str):
        self.client = client
        self.topic_arn = topic_arn

    def publish(self, signal: Signal, evidence: dict) -> None:
        self.client.publish(
            TopicArn=self.topic_arn,
            Subject=f"Sentinela AWS - {evidence['outcome']}",
            Message=json.dumps({"signal": signal.record(), "evidence": evidence}, sort_keys=True),
        )

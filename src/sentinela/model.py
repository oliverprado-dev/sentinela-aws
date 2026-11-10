"""Validate event envelopes and keep only fields needed for incident response."""

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from math import isfinite
from pathlib import Path
from typing import Literal

RULES = json.loads(Path(__file__).with_name("rules.json").read_text(encoding="utf-8"))
BASELINE = dict.fromkeys(
    ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"),
    True,
)
BUCKET_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
IDENTIFIER = re.compile(r"[a-zA-Z0-9_-]{1,128}")

Mode = Literal["observe", "enforce"]
Snapshot = dict[str, bool] | None


class InvalidEvent(ValueError):
    """A supported event is malformed and should be reviewed in the DLQ."""


@dataclass(frozen=True)
class Settings:
    account: str
    region: str
    bucket: str
    role_arn: str
    schedule_arn: str
    mode: Mode
    retention_days: int = 30

    def __post_init__(self):
        if self.mode not in ("observe", "enforce"):
            raise ValueError("Invalid response mode")
        if not re.fullmatch(r"[0-9]{12}", self.account) or not BUCKET_NAME.fullmatch(self.bucket):
            raise ValueError("Invalid account or bucket scope")
        if not all((self.region, self.role_arn, self.schedule_arn)):
            raise ValueError("Incomplete event scope")
        if not 14 <= self.retention_days <= 365:
            raise ValueError("Invalid incident retention")


@dataclass(frozen=True)
class Signal:
    incident_id: str
    source: Literal["cloudtrail", "guardduty", "reconciliation"]
    operation: str
    account: str
    region: str
    event_time: str
    buckets: tuple[str, ...]
    event_id: str
    severity: str | None = None
    finding_id: str | None = None

    def record(self) -> dict:
        record = asdict(self)
        record["buckets"] = list(self.buckets)
        return record


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise InvalidEvent("Expected JSON object")
    return value


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise InvalidEvent("Invalid event identifier")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise InvalidEvent("Invalid timestamp")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise InvalidEvent("Invalid timestamp") from exc
    if timestamp.tzinfo is None:
        raise InvalidEvent("Missing timezone")
    return timestamp.isoformat()


def _cloudtrail(event: dict, scope: Settings) -> Signal | None:
    detail = _object(event.get("detail"))
    operation = detail.get("eventName")
    if (
        detail.get("eventSource") != "s3.amazonaws.com"
        or operation not in RULES["cloudtrail_operations"]
        or "errorCode" in detail
    ):
        return None

    if (
        detail.get("recipientAccountId") != scope.account
        or detail.get("awsRegion") != scope.region
        or _object(detail.get("requestParameters")).get("bucketName") != scope.bucket
    ):
        return None

    identity = _object(detail.get("userIdentity"))
    session = _object(identity.get("sessionContext", {}))
    issuer = _object(session.get("sessionIssuer", {}))
    if issuer.get("arn") == scope.role_arn:
        return None

    event_id = _identifier(detail.get("eventID"))
    return Signal(
        f"cloudtrail#{event_id}",
        "cloudtrail",
        operation,
        scope.account,
        scope.region,
        _timestamp(detail.get("eventTime")),
        (scope.bucket,),
        event_id,
    )


def _guardduty(event: dict, scope: Settings) -> Signal | None:
    detail = _object(event.get("detail"))
    operation = detail.get("type")
    if (
        operation not in RULES["guardduty_types"]
        or detail.get("accountId") != scope.account
        or detail.get("region") != scope.region
    ):
        return None

    service = _object(detail.get("service", {}))
    if service.get("archived") is True:
        return None

    severity = detail.get("severity")
    if type(severity) not in (int, float) or not 0 <= severity <= 10 or not isfinite(severity):
        raise InvalidEvent("Invalid GuardDuty severity")
    if severity < RULES["guardduty_min_severity"]:
        return None

    finding_id = _identifier(detail.get("id"))
    updated_at = _timestamp(detail.get("updatedAt"))
    resource = _object(detail.get("resource", {}))
    buckets = resource.get("s3BucketDetails", [])
    if not isinstance(buckets, list):
        raise InvalidEvent("Invalid GuardDuty resource")
    names = [_object(bucket).get("name") for bucket in buckets[:10]]
    names = tuple(name for name in names if isinstance(name, str) and BUCKET_NAME.fullmatch(name))
    return Signal(
        f"guardduty#{finding_id}#{updated_at}",
        "guardduty",
        operation,
        scope.account,
        scope.region,
        updated_at,
        names,
        _identifier(event.get("id")),
        str(severity),
        finding_id,
    )


def normalize(payload: object, scope: Settings) -> Signal | None:
    event = _object(payload)
    if event.get("account") != scope.account or event.get("region") != scope.region:
        return None

    match event.get("source"), event.get("detail-type"):
        case "aws.s3", "AWS API Call via CloudTrail":
            return _cloudtrail(event, scope)
        case "aws.guardduty", "GuardDuty Finding":
            return _guardduty(event, scope)
        case "aws.events", "Scheduled Event":
            resources = event.get("resources")
            if isinstance(resources, list) and scope.schedule_arn in resources:
                event_id = _identifier(event.get("id"))
                return Signal(
                    f"schedule#{event_id}",
                    "reconciliation",
                    "CheckBucketPublicAccessBlock",
                    scope.account,
                    scope.region,
                    _timestamp(event.get("time")),
                    (scope.bucket,),
                    event_id,
                )
    return None

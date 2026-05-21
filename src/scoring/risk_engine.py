"""
Risk Scoring Engine — aggregates findings by severity to produce a normalized
0-100 posture score, tracks score history in DynamoDB, and generates trend data.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "informational": 0,
}

# Maximum theoretical penalty per check category (used for normalization)
MAX_SCORE_CAP = 1000


@dataclass
class SeverityBreakdown:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    def total_penalty(self) -> int:
        return (
            self.critical * SEVERITY_WEIGHTS["critical"]
            + self.high * SEVERITY_WEIGHTS["high"]
            + self.medium * SEVERITY_WEIGHTS["medium"]
            + self.low * SEVERITY_WEIGHTS["low"]
        )


@dataclass
class PostureScore:
    score: float  # 0 (worst) to 100 (best)
    total_findings: int
    breakdown: SeverityBreakdown
    per_service: dict[str, float] = field(default_factory=dict)
    calculated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    account_id: str = ""


@dataclass
class ScoreTrendPoint:
    date: str
    score: float
    total_findings: int
    critical: int
    high: int


def compute_posture_score(
    findings: list[Any],  # list of Finding or CheckResult
    account_id: str = "",
) -> PostureScore:
    """
    Aggregates findings by severity, computes a normalized 0-100 posture score,
    and breaks down scores per service.

    Score formula: max(0, 100 - (penalty / MAX_SCORE_CAP * 100))
    """
    breakdown = SeverityBreakdown()
    service_penalties: dict[str, int] = {}

    for finding in findings:
        # Support both Finding (prowler) and CheckResult (s3_checks) objects
        severity = getattr(finding, "severity", "informational").lower()
        service = (
            getattr(finding, "service_name", None)
            or getattr(finding, "bucket", None)
            or "unknown"
        )
        status = getattr(finding, "status", "FAIL").upper()

        if status not in ("FAIL", "FAILED"):
            continue

        weight = SEVERITY_WEIGHTS.get(severity, 0)
        if severity == "critical":
            breakdown.critical += 1
        elif severity == "high":
            breakdown.high += 1
        elif severity == "medium":
            breakdown.medium += 1
        elif severity == "low":
            breakdown.low += 1
        elif severity == "informational":
            breakdown.informational += 1

        service_penalties[service] = service_penalties.get(service, 0) + weight

    total_penalty = breakdown.total_penalty()
    score = max(0.0, 100.0 - (total_penalty / MAX_SCORE_CAP * 100.0))
    score = round(score, 1)

    # Per-service scores
    per_service: dict[str, float] = {}
    for svc, penalty in service_penalties.items():
        per_service[svc] = round(max(0.0, 100.0 - (penalty / MAX_SCORE_CAP * 100.0)), 1)

    total_findings = breakdown.critical + breakdown.high + breakdown.medium + breakdown.low + breakdown.informational

    logger.info(
        "Posture score: %.1f (critical=%d, high=%d, medium=%d, low=%d)",
        score, breakdown.critical, breakdown.high, breakdown.medium, breakdown.low,
    )

    return PostureScore(
        score=score,
        total_findings=total_findings,
        breakdown=breakdown,
        per_service=per_service,
        account_id=account_id,
    )


def store_score_history(
    dynamodb_resource: Any,
    table_name: str,
    posture: PostureScore,
) -> None:
    """
    Stores a PostureScore snapshot in DynamoDB for trend analysis.
    Table schema: PK=account_id, SK=calculated_at (ISO8601), TTL=90 days.
    """
    table = dynamodb_resource.Table(table_name)
    import time as _time
    ttl = int(_time.time()) + 90 * 86400  # 90-day TTL

    item = {
        "account_id": posture.account_id or "default",
        "calculated_at": posture.calculated_at,
        "score": str(round(posture.score, 2)),
        "total_findings": posture.total_findings,
        "critical": posture.breakdown.critical,
        "high": posture.breakdown.high,
        "medium": posture.breakdown.medium,
        "low": posture.breakdown.low,
        "per_service": {k: str(v) for k, v in posture.per_service.items()},
        "ttl": ttl,
    }

    try:
        table.put_item(Item=item)
        logger.info("Stored posture score %.1f for account %s at %s",
                    posture.score, posture.account_id, posture.calculated_at)
    except ClientError as exc:
        logger.error("Failed to store posture score: %s", exc)
        raise


def fetch_score_trend(
    dynamodb_resource: Any,
    table_name: str,
    account_id: str,
    days: int = 30,
) -> list[ScoreTrendPoint]:
    """
    Retrieves the score history for an account over the past N days.
    Returns list of ScoreTrendPoint sorted by date ascending.
    """
    from datetime import timedelta
    table = dynamodb_resource.Table(table_name)

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    try:
        response = table.query(
            KeyConditionExpression=Key("account_id").eq(account_id) & Key("calculated_at").gte(cutoff),
            ScanIndexForward=True,
        )
    except ClientError as exc:
        logger.error("Failed to query score trend: %s", exc)
        raise

    trend: list[ScoreTrendPoint] = []
    for item in response.get("Items", []):
        trend.append(
            ScoreTrendPoint(
                date=item["calculated_at"],
                score=float(item.get("score", 0)),
                total_findings=int(item.get("total_findings", 0)),
                critical=int(item.get("critical", 0)),
                high=int(item.get("high", 0)),
            )
        )

    logger.info("Fetched %d score trend points for account %s", len(trend), account_id)
    return trend


def ensure_score_table(dynamodb_resource: Any, table_name: str, region: str = "us-east-1") -> None:
    """Creates the DynamoDB score history table if it does not exist."""
    client = dynamodb_resource.meta.client
    try:
        client.describe_table(TableName=table_name)
        logger.debug("DynamoDB table %s already exists", table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        logger.info("Creating DynamoDB table %s", table_name)
        dynamodb_resource.create_table(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "account_id", "KeyType": "HASH"},
                {"AttributeName": "calculated_at", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "account_id", "AttributeType": "S"},
                {"AttributeName": "calculated_at", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
        )
        waiter = client.get_waiter("table_exists")
        waiter.wait(TableName=table_name)
        logger.info("DynamoDB table %s created", table_name)

# _r 20260521113611-ae9113be

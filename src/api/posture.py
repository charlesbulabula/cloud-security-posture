"""
FastAPI router for cloud security posture APIs:
  GET  /posture/score       — overall + per-service posture score
  GET  /posture/findings    — filtered findings list
  GET  /posture/trend       — score history over N days
  POST /posture/scan        — trigger an async security scan
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

import boto3
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel

from src.checks.s3_checks import run_checks_for_all_buckets
from src.scanners.prowler_runner import ProwlerRunConfig, run_prowler
from src.scoring.risk_engine import (
    PostureScore,
    ScoreTrendPoint,
    compute_posture_score,
    ensure_score_table,
    fetch_score_trend,
    store_score_history,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/posture", tags=["security-posture"])

DYNAMODB_TABLE = os.environ.get("POSTURE_SCORE_TABLE", "security-posture-scores")
ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "default")

SeverityFilter = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def get_session() -> boto3.Session:
    return boto3.Session()


def get_dynamodb(session: boto3.Session = Depends(get_session)):
    return session.resource("dynamodb")


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ServiceScoreItem(BaseModel):
    service: str
    score: float


class PostureScoreResponse(BaseModel):
    overall_score: float
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    per_service: list[ServiceScoreItem]
    calculated_at: str


class FindingItem(BaseModel):
    id: str
    check_id: str
    check_title: str
    severity: str
    status: str
    service: str
    resource_arn: str
    region: str
    description: str
    remediation: str


class TrendPoint(BaseModel):
    date: str
    score: float
    total_findings: int
    critical: int
    high: int


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    initiated_at: str


# ---------------------------------------------------------------------------
# Background scan task
# ---------------------------------------------------------------------------


def _run_scan_background(
    scan_id: str,
    account_id: str,
    session: boto3.Session,
) -> None:
    """Background task: runs Prowler + S3 checks, scores results, stores in DynamoDB."""
    logger.info("Background scan %s started", scan_id)
    try:
        prowler_cfg = ProwlerRunConfig(
            compliance_frameworks=["cis_level2_aws_2.0"],
            aws_region=session.region_name,
        )
        findings = run_prowler(prowler_cfg, min_severity="low")
    except Exception as exc:
        logger.warning("Prowler scan failed, falling back to S3 checks only: %s", exc)
        findings = []

    try:
        s3_results = run_checks_for_all_buckets(session)
        findings.extend(s3_results)  # type: ignore[arg-type]
    except Exception as exc:
        logger.error("S3 checks failed: %s", exc)

    posture = compute_posture_score(findings, account_id=account_id)
    dynamodb = session.resource("dynamodb")
    try:
        ensure_score_table(dynamodb, DYNAMODB_TABLE)
        store_score_history(dynamodb, DYNAMODB_TABLE, posture)
    except Exception as exc:
        logger.error("Failed to store scan results: %s", exc)

    logger.info("Background scan %s complete — score=%.1f", scan_id, posture.score)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/score", response_model=PostureScoreResponse)
async def get_posture_score(
    session: boto3.Session = Depends(get_session),
    dynamodb=Depends(get_dynamodb),
) -> PostureScoreResponse:
    """
    Returns the most recent posture score from DynamoDB history.
    Falls back to a live S3 check if no history is available.
    """
    account_id = ACCOUNT_ID
    try:
        trend = fetch_score_trend(dynamodb, DYNAMODB_TABLE, account_id, days=1)
    except Exception:
        trend = []

    if trend:
        latest = trend[-1]
        posture = PostureScore(
            score=latest.score,
            total_findings=latest.total_findings,
            breakdown=__import__("src.scoring.risk_engine", fromlist=["SeverityBreakdown"]).SeverityBreakdown(
                critical=latest.critical, high=latest.high
            ),
        )
        return PostureScoreResponse(
            overall_score=latest.score,
            total_findings=latest.total_findings,
            critical=latest.critical,
            high=latest.high,
            medium=0,
            low=0,
            per_service=[],
            calculated_at=latest.date,
        )

    # Live fallback
    try:
        results = run_checks_for_all_buckets(session)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Live check failed: {exc}")

    posture = compute_posture_score(results, account_id=account_id)
    return PostureScoreResponse(
        overall_score=posture.score,
        total_findings=posture.total_findings,
        critical=posture.breakdown.critical,
        high=posture.breakdown.high,
        medium=posture.breakdown.medium,
        low=posture.breakdown.low,
        per_service=[ServiceScoreItem(service=k, score=v) for k, v in posture.per_service.items()],
        calculated_at=posture.calculated_at,
    )


@router.get("/findings", response_model=list[FindingItem])
async def get_findings(
    severity: SeverityFilter | None = Query(None, description="Filter by minimum severity"),
    service: str | None = Query(None, description="Filter by service name (e.g. 's3')"),
    session: boto3.Session = Depends(get_session),
) -> list[FindingItem]:
    """Returns current security findings, optionally filtered by severity and service."""
    try:
        results = run_checks_for_all_buckets(session)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    from src.scoring.risk_engine import SEVERITY_WEIGHTS
    min_level = SEVERITY_WEIGHTS.get(severity.lower(), 0) if severity else 0

    items: list[FindingItem] = []
    for r in results:
        if r.status not in ("FAIL", "ERROR"):
            continue
        finding_severity = getattr(r, "severity", "informational").lower()
        if SEVERITY_WEIGHTS.get(finding_severity, 0) < min_level:
            continue
        resource_name = getattr(r, "bucket", None) or getattr(r, "resource_id", "")
        svc = getattr(r, "service_name", None) or "s3"
        if service and service.lower() not in svc.lower():
            continue
        items.append(FindingItem(
            id=f"{r.check_id}-{resource_name}",
            check_id=r.check_id,
            check_title=r.check_title,
            severity=finding_severity,
            status=r.status,
            service=svc,
            resource_arn=r.resource_arn,
            region=session.region_name or "",
            description=getattr(r, "detail", ""),
            remediation=r.remediation,
        ))
    return items


@router.get("/trend", response_model=list[TrendPoint])
async def get_score_trend(
    days: int = Query(30, ge=1, le=365, description="Number of days of history"),
    dynamodb=Depends(get_dynamodb),
) -> list[TrendPoint]:
    """Returns posture score trend over the requested period."""
    try:
        trend = fetch_score_trend(dynamodb, DYNAMODB_TABLE, ACCOUNT_ID, days=days)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    return [
        TrendPoint(date=p.date, score=p.score, total_findings=p.total_findings,
                   critical=p.critical, high=p.high)
        for p in trend
    ]


@router.post("/scan", response_model=ScanResponse, status_code=202)
async def trigger_scan(
    background_tasks: BackgroundTasks,
    session: boto3.Session = Depends(get_session),
) -> ScanResponse:
    """Triggers an asynchronous security scan (Prowler + S3 checks)."""
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(_run_scan_background, scan_id, ACCOUNT_ID, session)
    return ScanResponse(
        scan_id=scan_id,
        status="INITIATED",
        message="Scan started in background. Poll /posture/score for updated results.",
        initiated_at=datetime.now(timezone.utc).isoformat(),
    )

# _r 20260525135015-903dc17e

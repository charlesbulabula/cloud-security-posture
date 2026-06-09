"""
Custom S3 Security Checks — checks public access block, bucket ACL,
server-side encryption, versioning, MFA delete, and access logging.
Returns a list of CheckResult objects.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Literal

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

CheckStatus = Literal["PASS", "FAIL", "ERROR", "NOT_APPLICABLE"]


@dataclass
class CheckResult:
    bucket: str
    check_id: str
    check_title: str
    status: CheckStatus
    severity: str  # critical | high | medium | low
    detail: str
    remediation: str = ""
    resource_arn: str = ""


def _bucket_arn(bucket_name: str) -> str:
    return f"arn:aws:s3:::{bucket_name}"


def check_public_access_block(s3_client: Any, bucket: str) -> CheckResult:
    """Checks that all four S3 Public Access Block settings are enabled."""
    check_id = "s3_public_access_block"
    title = "S3 bucket public access block enabled"
    arn = _bucket_arn(bucket)
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket)
        cfg = resp.get("PublicAccessBlockConfiguration", {})
        required_keys = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        disabled = [k for k in required_keys if not cfg.get(k, False)]
        if disabled:
            return CheckResult(
                bucket=bucket, check_id=check_id, check_title=title,
                status="FAIL", severity="critical",
                detail=f"Public access block settings not enabled: {disabled}",
                remediation="Enable all public access block settings via S3 console or aws s3api put-public-access-block",
                resource_arn=arn,
            )
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="PASS", severity="critical", detail="All public access block settings enabled",
                           resource_arn=arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                               status="FAIL", severity="critical",
                               detail="No public access block configuration found",
                               remediation="Configure public access block settings",
                               resource_arn=arn)
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="ERROR", severity="critical", detail=str(exc), resource_arn=arn)


def check_bucket_acl(s3_client: Any, bucket: str) -> CheckResult:
    """Checks that the bucket ACL does not grant public access."""
    check_id = "s3_no_public_acl"
    title = "S3 bucket ACL does not allow public access"
    arn = _bucket_arn(bucket)
    PUBLIC_URIS = [
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    ]
    try:
        resp = s3_client.get_bucket_acl(Bucket=bucket)
        grants = resp.get("Grants", [])
        public_grants = [
            g for g in grants
            if g.get("Grantee", {}).get("URI") in PUBLIC_URIS
        ]
        if public_grants:
            permissions = [g.get("Permission") for g in public_grants]
            return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                               status="FAIL", severity="critical",
                               detail=f"Bucket grants public access: {permissions}",
                               remediation="Remove public grants from bucket ACL",
                               resource_arn=arn)
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="PASS", severity="critical", detail="No public ACL grants found",
                           resource_arn=arn)
    except ClientError as exc:
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="ERROR", severity="critical", detail=str(exc), resource_arn=arn)


def check_server_side_encryption(s3_client: Any, bucket: str) -> CheckResult:
    """Checks that default server-side encryption is configured."""
    check_id = "s3_default_encryption"
    title = "S3 bucket server-side encryption enabled"
    arn = _bucket_arn(bucket)
    try:
        resp = s3_client.get_bucket_encryption(Bucket=bucket)
        rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not rules:
            raise ClientError({"Error": {"Code": "NoEncryption"}}, "get_bucket_encryption")
        sse_algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="PASS", severity="high",
                           detail=f"Encryption algorithm: {sse_algo}", resource_arn=arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("ServerSideEncryptionConfigurationNotFoundError", "NoEncryption"):
            return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                               status="FAIL", severity="high",
                               detail="No default encryption configured",
                               remediation="Enable AES-256 or aws:kms encryption via S3 default encryption settings",
                               resource_arn=arn)
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="ERROR", severity="high", detail=str(exc), resource_arn=arn)


def check_versioning(s3_client: Any, bucket: str) -> CheckResult:
    """Checks that versioning is enabled on the bucket."""
    check_id = "s3_versioning_enabled"
    title = "S3 bucket versioning enabled"
    arn = _bucket_arn(bucket)
    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket)
        status = resp.get("Status", "")
        if status == "Enabled":
            return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                               status="PASS", severity="medium", detail="Versioning is Enabled",
                               resource_arn=arn)
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="FAIL", severity="medium",
                           detail=f"Versioning status: {status or 'Disabled'}",
                           remediation="Enable versioning via aws s3api put-bucket-versioning",
                           resource_arn=arn)
    except ClientError as exc:
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="ERROR", severity="medium", detail=str(exc), resource_arn=arn)


def check_mfa_delete(s3_client: Any, bucket: str) -> CheckResult:
    """Checks that MFA Delete is enabled for versioned buckets."""
    check_id = "s3_mfa_delete"
    title = "S3 bucket MFA Delete enabled"
    arn = _bucket_arn(bucket)
    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket)
        versioning = resp.get("Status", "")
        mfa_delete = resp.get("MFADelete", "")
        if versioning != "Enabled":
            return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                               status="NOT_APPLICABLE", severity="low",
                               detail="Versioning not enabled, MFA Delete N/A", resource_arn=arn)
        if mfa_delete == "Enabled":
            return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                               status="PASS", severity="low", detail="MFA Delete enabled",
                               resource_arn=arn)
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="FAIL", severity="low",
                           detail=f"MFA Delete is {mfa_delete or 'Disabled'}",
                           remediation="Enable MFA Delete via aws s3api put-bucket-versioning with MFADelete=Enabled",
                           resource_arn=arn)
    except ClientError as exc:
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="ERROR", severity="low", detail=str(exc), resource_arn=arn)


def check_access_logging(s3_client: Any, bucket: str) -> CheckResult:
    """Checks that S3 server access logging is enabled."""
    check_id = "s3_access_logging"
    title = "S3 bucket access logging enabled"
    arn = _bucket_arn(bucket)
    try:
        resp = s3_client.get_bucket_logging(Bucket=bucket)
        logging_cfg = resp.get("LoggingEnabled")
        if logging_cfg:
            target = logging_cfg.get("TargetBucket", "unknown")
            return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                               status="PASS", severity="medium",
                               detail=f"Logging to bucket: {target}", resource_arn=arn)
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="FAIL", severity="medium",
                           detail="Server access logging is not enabled",
                           remediation="Enable S3 access logging via aws s3api put-bucket-logging",
                           resource_arn=arn)
    except ClientError as exc:
        return CheckResult(bucket=bucket, check_id=check_id, check_title=title,
                           status="ERROR", severity="medium", detail=str(exc), resource_arn=arn)


def run_all_checks(
    bucket: str,
    session: boto3.Session | None = None,
) -> list[CheckResult]:
    """Runs all S3 security checks against a bucket and returns the results."""
    if session is None:
        session = boto3.Session()
    s3 = session.client("s3")

    results: list[CheckResult] = [
        check_public_access_block(s3, bucket),
        check_bucket_acl(s3, bucket),
        check_server_side_encryption(s3, bucket),
        check_versioning(s3, bucket),
        check_mfa_delete(s3, bucket),
        check_access_logging(s3, bucket),
    ]

    failed = [r for r in results if r.status == "FAIL"]
    logger.info("S3 checks for %s: %d/%d failed", bucket, len(failed), len(results))
    return results


def run_checks_for_all_buckets(
    session: boto3.Session | None = None,
) -> list[CheckResult]:
    """Discovers all S3 buckets in the account and runs checks on each."""
    if session is None:
        session = boto3.Session()
    s3 = session.client("s3")
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    logger.info("Running S3 checks on %d buckets", len(buckets))

    all_results: list[CheckResult] = []
    for bucket in buckets:
        all_results.extend(run_all_checks(bucket, session))
    return all_results

# _r 20260609124911-95217697

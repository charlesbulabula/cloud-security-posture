"""
Prowler Runner — executes `prowler aws` as a subprocess with specified checks
or frameworks, parses the JSON output, converts findings to internal Finding
model, and filters by severity threshold.
"""

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

SeverityLabel = Literal["critical", "high", "medium", "low", "informational"]

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


@dataclass
class Finding:
    id: str
    check_id: str
    check_title: str
    severity: str
    status: str  # FAIL | PASS | MUTED | ERROR
    service_name: str
    resource_arn: str
    resource_id: str
    account_id: str
    region: str
    description: str
    risk: str = ""
    remediation: str = ""
    compliance: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict, repr=False)


@dataclass
class ProwlerRunConfig:
    checks: list[str] = field(default_factory=list)
    compliance_frameworks: list[str] = field(default_factory=list)
    aws_profile: str | None = None
    aws_region: str | None = None
    role_arn: str | None = None
    output_directory: str | None = None
    extra_args: list[str] = field(default_factory=list)


class ProwlerExecutionError(Exception):
    pass


def _build_prowler_command(config: ProwlerRunConfig, output_dir: str) -> list[str]:
    cmd = ["prowler", "aws", "--output-formats", "json", "--output-directory", output_dir]

    if config.aws_profile:
        cmd += ["--profile", config.aws_profile]
    if config.aws_region:
        cmd += ["--region", config.aws_region]
    if config.role_arn:
        cmd += ["--role", config.role_arn]

    if config.checks:
        for check in config.checks:
            cmd += ["--checks", check]
    elif config.compliance_frameworks:
        for framework in config.compliance_frameworks:
            cmd += ["--compliance", framework]

    cmd.extend(config.extra_args)
    return cmd


def _parse_prowler_json(json_path: Path) -> list[dict]:
    """Reads and parses the Prowler JSON output file."""
    if not json_path.exists():
        raise FileNotFoundError(f"Prowler output not found at {json_path}")
    with json_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return []


def _raw_to_finding(raw: dict) -> Finding:
    """Converts a raw Prowler JSON finding dict to a Finding dataclass."""
    # Prowler v3+ JSON schema
    check_metadata = raw.get("metadata", {}).get("event", raw)
    severity = (raw.get("severity") or check_metadata.get("Severity", "informational")).lower()
    status = (raw.get("status") or check_metadata.get("Status", "")).upper()

    resource_details = raw.get("resources", [{}])
    resource = resource_details[0] if resource_details else {}
    resource_arn = resource.get("arn") or raw.get("resource_arn", "")
    resource_id = resource.get("uid") or raw.get("resource_id", "")

    remediation_obj = raw.get("remediation", {})
    if isinstance(remediation_obj, dict):
        remediation = remediation_obj.get("recommendation", {}).get("text", "")
    else:
        remediation = str(remediation_obj)

    return Finding(
        id=raw.get("uid", raw.get("finding_uid", "")),
        check_id=raw.get("check_id", raw.get("CheckID", "")),
        check_title=raw.get("check_title", raw.get("CheckTitle", "")),
        severity=severity,
        status=status,
        service_name=raw.get("service_name", raw.get("ServiceName", "")),
        resource_arn=resource_arn,
        resource_id=resource_id,
        account_id=raw.get("account_uid", raw.get("AwsAccountId", "")),
        region=raw.get("region", raw.get("Region", "")),
        description=raw.get("description", raw.get("Description", "")),
        risk=raw.get("risk", ""),
        remediation=remediation,
        compliance=raw.get("compliance", {}),
        raw=raw,
    )


def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    """Filters findings to only include those at or above the given severity level."""
    min_level = SEVERITY_ORDER.get(min_severity.lower(), 0)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_level]


def run_prowler(
    config: ProwlerRunConfig,
    min_severity: str = "medium",
    timeout: int = 3600,
) -> list[Finding]:
    """
    Executes Prowler as a subprocess, parses the JSON output, and returns
    filtered findings above the minimum severity threshold.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = config.output_directory or tmpdir
        cmd = _build_prowler_command(config, output_dir)
        logger.info("Running prowler: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProwlerExecutionError(f"Prowler timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise ProwlerExecutionError("prowler binary not found in PATH") from exc

        if result.returncode not in (0, 3):  # Prowler returns 3 when findings exist
            logger.error("Prowler stderr: %s", result.stderr[-2000:])
            raise ProwlerExecutionError(
                f"Prowler exited with code {result.returncode}: {result.stderr[-500:]}"
            )

        # Locate the JSON output file
        output_path = Path(output_dir)
        json_files = list(output_path.glob("*.json"))
        if not json_files:
            logger.warning("No JSON output files found in %s", output_dir)
            return []

        json_file = sorted(json_files, key=lambda p: p.stat().st_mtime, reverse=True)[0]
        logger.info("Parsing Prowler output: %s", json_file)

        raw_findings = _parse_prowler_json(json_file)
        findings = [_raw_to_finding(r) for r in raw_findings]
        fail_findings = [f for f in findings if f.status == "FAIL"]
        filtered = filter_by_severity(fail_findings, min_severity)

        logger.info(
            "Prowler: %d total, %d FAILs, %d above severity=%s",
            len(findings),
            len(fail_findings),
            len(filtered),
            min_severity,
        )
        return filtered

# _r 20260525131611-247c7a15

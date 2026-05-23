"""
Finding Suppression Engine — loads suppression rules from YAML (resource ARN
patterns, control IDs, expiry dates), applies them to a findings list, and
logs suppression decisions with justification.
"""

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class SuppressionRule:
    id: str
    justification: str
    control_ids: list[str] = field(default_factory=list)
    resource_arn_patterns: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    severity: list[str] = field(default_factory=list)
    expires: str | None = None  # ISO date string YYYY-MM-DD
    created_by: str = ""
    ticket: str = ""


@dataclass
class SuppressionDecision:
    finding_id: str
    suppressed: bool
    rule_id: str | None = None
    justification: str | None = None
    reason: str | None = None  # "EXPIRED" | "CONTROL_MATCH" | "ARN_MATCH" | "SERVICE_MATCH"


class SuppressionRuleError(Exception):
    pass


def _parse_rule(raw: dict, source: str) -> SuppressionRule:
    """Parses a single rule dict from YAML into a SuppressionRule."""
    rule_id = raw.get("id")
    if not rule_id:
        raise SuppressionRuleError(f"Rule missing 'id' in {source}")
    justification = raw.get("justification")
    if not justification:
        raise SuppressionRuleError(f"Rule '{rule_id}' missing 'justification' in {source}")

    expires = raw.get("expires")
    if expires and not isinstance(expires, str):
        expires = str(expires)

    return SuppressionRule(
        id=rule_id,
        justification=justification,
        control_ids=[str(c) for c in raw.get("control_ids", [])],
        resource_arn_patterns=raw.get("resource_arn_patterns", []),
        services=raw.get("services", []),
        severity=raw.get("severity", []),
        expires=expires,
        created_by=raw.get("created_by", ""),
        ticket=raw.get("ticket", ""),
    )


def load_rules_from_yaml(yaml_path: str | Path) -> list[SuppressionRule]:
    """
    Loads suppression rules from a YAML file.
    Expected format:
      suppressions:
        - id: RULE-001
          justification: "Accepted risk per security review SR-42"
          control_ids: ["CIS.2.1"]
          resource_arn_patterns: ["arn:aws:s3:::my-logs-bucket"]
          expires: "2026-12-31"
    """
    path = Path(yaml_path)
    if not path.exists():
        raise FileNotFoundError(f"Suppression rules file not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise SuppressionRuleError(f"Expected YAML mapping at top level in {path}")

    raw_rules = data.get("suppressions", [])
    if not isinstance(raw_rules, list):
        raise SuppressionRuleError(f"'suppressions' must be a list in {path}")

    rules: list[SuppressionRule] = []
    for raw in raw_rules:
        rule = _parse_rule(raw, str(path))
        rules.append(rule)

    logger.info("Loaded %d suppression rules from %s", len(rules), path)
    return rules


def _is_rule_expired(rule: SuppressionRule) -> bool:
    """Returns True if the rule has an expiry date that is in the past."""
    if not rule.expires:
        return False
    try:
        expiry = date.fromisoformat(rule.expires)
        return date.today() > expiry
    except ValueError:
        logger.warning("Invalid expiry date format in rule %s: %s", rule.id, rule.expires)
        return False


def _arn_matches_pattern(resource_arn: str, patterns: list[str]) -> bool:
    """Returns True if resource_arn matches any of the given glob-style patterns."""
    for pattern in patterns:
        if fnmatch.fnmatch(resource_arn, pattern):
            return True
        # Also try regex patterns prefixed with re:
        if pattern.startswith("re:"):
            try:
                if re.fullmatch(pattern[3:], resource_arn):
                    return True
            except re.error:
                logger.warning("Invalid regex in suppression pattern: %s", pattern)
    return False


def _match_rule(finding: Any, rule: SuppressionRule) -> str | None:
    """
    Returns the match reason string if a rule applies to a finding, else None.
    """
    # Control ID match
    check_id = getattr(finding, "check_id", getattr(finding, "check_id", ""))
    if rule.control_ids and check_id:
        for ctrl in rule.control_ids:
            if check_id == ctrl or check_id.startswith(ctrl):
                return "CONTROL_MATCH"

    # Resource ARN match
    resource_arn = getattr(finding, "resource_arn", "")
    if rule.resource_arn_patterns and resource_arn:
        if _arn_matches_pattern(resource_arn, rule.resource_arn_patterns):
            return "ARN_MATCH"

    # Service match
    service = getattr(finding, "service_name", getattr(finding, "bucket", ""))
    if rule.services and service:
        for svc in rule.services:
            if svc.lower() in service.lower():
                return "SERVICE_MATCH"

    # Severity-only match (broad suppression)
    severity = getattr(finding, "severity", "").lower()
    if rule.severity and not rule.control_ids and not rule.resource_arn_patterns and not rule.services:
        if severity in [s.lower() for s in rule.severity]:
            return "SEVERITY_MATCH"

    return None


def apply_suppressions(
    findings: list[Any],
    rules: list[SuppressionRule],
) -> tuple[list[Any], list[SuppressionDecision]]:
    """
    Applies suppression rules to the findings list.

    Returns:
        (active_findings, decisions) — active_findings excludes suppressed ones.
        decisions includes all suppression decisions (suppressed + unsuppressed).
    """
    active: list[Any] = []
    decisions: list[SuppressionDecision] = []

    active_rules = []
    for rule in rules:
        if _is_rule_expired(rule):
            logger.info("Suppression rule %s is expired (expiry=%s), skipping", rule.id, rule.expires)
        else:
            active_rules.append(rule)

    for finding in findings:
        finding_id = getattr(finding, "id", getattr(finding, "check_id", str(id(finding))))
        suppressed = False
        decision = SuppressionDecision(finding_id=finding_id, suppressed=False)

        for rule in active_rules:
            match_reason = _match_rule(finding, rule)
            if match_reason:
                suppressed = True
                decision = SuppressionDecision(
                    finding_id=finding_id,
                    suppressed=True,
                    rule_id=rule.id,
                    justification=rule.justification,
                    reason=match_reason,
                )
                logger.info(
                    "Suppressed finding %s via rule %s (%s): %s",
                    finding_id,
                    rule.id,
                    match_reason,
                    rule.justification,
                )
                if rule.ticket:
                    logger.debug("Suppression ticket: %s", rule.ticket)
                break

        decisions.append(decision)
        if not suppressed:
            active.append(finding)

    suppressed_count = sum(1 for d in decisions if d.suppressed)
    logger.info(
        "Suppression applied: %d/%d findings suppressed (%d active)",
        suppressed_count, len(findings), len(active),
    )
    return active, decisions


def load_and_apply(
    findings: list[Any],
    rules_path: str | Path,
) -> tuple[list[Any], list[SuppressionDecision]]:
    """Convenience wrapper: load rules from YAML and apply to findings."""
    rules = load_rules_from_yaml(rules_path)
    return apply_suppressions(findings, rules)

# _r 20260523114708-363ae13e

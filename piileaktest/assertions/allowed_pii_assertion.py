"""Assertion: Only allowed PII types should be present."""

import pandas as pd
from typing import List, Set
from piileaktest.models import (
    AssertionResult,
    Finding,
    PIIType,
    Severity,
    DatasetPolicy,
    MaskingType,
)
from piileaktest.detectors import detect_pii_in_value, is_credit_card
from piileaktest.detectors.luhn import detect_credit_card_masking
from piileaktest.detectors.entropy import is_high_entropy_token
from piileaktest.utils.redaction import redact_value


def assert_only_allowed_pii(
    df: pd.DataFrame,
    policy: DatasetPolicy,
    max_violations: int = 10,
) -> AssertionResult:
    """
    Assert that only explicitly allowed PII types appear in the dataset.

    This is a strict check: any PII not in allowed_pii_types is flagged.

    Args:
        df: DataFrame to check
        policy: Dataset policy with allowed_pii_types
        max_violations: Maximum number of violation examples to collect

    Returns:
        AssertionResult with findings
    """
    findings: List[Finding] = []
    allowed_types = set(policy.allowed_pii_types)

    # Scan each column
    for col in df.columns:
        col_findings = {}  # Track findings by PII type

        for idx, value in df[col].items():
            if pd.isna(value):
                continue

            value_str = str(value).strip()
            if not value_str:
                continue

            # Collect all detected PII types
            detected_types: Set[PIIType] = set()

            # Check standard patterns
            detected = detect_pii_in_value(value_str)
            for pii_type, masking_type in detected:
                if pii_type not in allowed_types:
                    detected_types.add(pii_type)
                    if pii_type not in col_findings:
                        col_findings[pii_type] = []
                    if len(col_findings[pii_type]) < max_violations:
                        col_findings[pii_type].append((idx, value_str, masking_type))

            # Check credit card separately (Luhn)
            if is_credit_card(value_str):
                if PIIType.CREDIT_CARD not in allowed_types:
                    masking_type = detect_credit_card_masking(value_str)
                    if PIIType.CREDIT_CARD not in col_findings:
                        col_findings[PIIType.CREDIT_CARD] = []
                    if len(col_findings[PIIType.CREDIT_CARD]) < max_violations:
                        col_findings[PIIType.CREDIT_CARD].append((idx, value_str, masking_type))

            # Check high entropy tokens
            if is_high_entropy_token(value_str):
                if PIIType.HIGH_ENTROPY_TOKEN not in allowed_types:
                    if PIIType.HIGH_ENTROPY_TOKEN not in col_findings:
                        col_findings[PIIType.HIGH_ENTROPY_TOKEN] = []
                    if len(col_findings[PIIType.HIGH_ENTROPY_TOKEN]) < max_violations:
                        col_findings[PIIType.HIGH_ENTROPY_TOKEN].append(
                            (idx, value_str, MaskingType.PLAINTEXT)
                        )

        # Convert to Finding objects
        for pii_type, violations in col_findings.items():
            if violations:
                first_violation = violations[0]
                finding = Finding(
                    dataset=policy.name,
                    column=col,
                    pii_type=pii_type,
                    masking_type=first_violation[2],
                    row_index=int(first_violation[0]),
                    redacted_sample=redact_value(first_violation[1], pii_type.value),
                    count=len(violations),
                    severity=Severity.HIGH,
                    message=f"Disallowed PII type '{pii_type.value}' found in column '{col}' "
                    f"({len(violations)} occurrence(s))",
                )
                findings.append(finding)

    passed = len(findings) == 0
    severity = Severity.HIGH if not passed else Severity.INFO

    if passed:
        message = f"PASS: Only allowed PII types present in {policy.name}"
    else:
        total_violations = sum(f.count for f in findings)
        unique_types = len(set(f.pii_type for f in findings))
        message = (
            f"FAIL: {policy.name} contains {unique_types} disallowed PII type(s) "
            f"with {total_violations} total occurrence(s)"
        )

    return AssertionResult(
        assertion_type="only_allowed_pii",
        dataset=policy.name,
        passed=passed,
        findings=findings,
        message=message,
        severity=severity,
    )

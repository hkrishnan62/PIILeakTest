"""Assertion: No forbidden PII should be present in the dataset."""

import pandas as pd
from typing import List
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


def assert_no_forbidden_pii(
    df: pd.DataFrame,
    policy: DatasetPolicy,
    max_violations: int = 10,
) -> AssertionResult:
    """
    Assert that no forbidden PII types appear in the dataset.
    
    Args:
        df: DataFrame to check
        policy: Dataset policy with forbidden_pii_types
        max_violations: Maximum number of violation examples to collect
        
    Returns:
        AssertionResult with findings
    """
    findings: List[Finding] = []
    forbidden_types = set(policy.forbidden_pii_types)
    
    if not forbidden_types:
        return AssertionResult(
            assertion_type="no_forbidden_pii",
            dataset=policy.name,
            passed=True,
            message="No forbidden PII types specified in policy",
            severity=Severity.INFO,
        )
    
    # Scan each column
    for col in df.columns:
        col_findings = {}  # Track findings by PII type
        
        for idx, value in df[col].items():
            if pd.isna(value):
                continue
            
            value_str = str(value).strip()
            if not value_str:
                continue
            
            # Check standard patterns
            detected = detect_pii_in_value(value_str)
            for pii_type, masking_type in detected:
                if pii_type in forbidden_types:
                    if pii_type not in col_findings:
                        col_findings[pii_type] = []
                    if len(col_findings[pii_type]) < max_violations:
                        col_findings[pii_type].append((idx, value_str, masking_type))
            
            # Check credit card separately (Luhn)
            if PIIType.CREDIT_CARD in forbidden_types and is_credit_card(value_str):
                masking_type = detect_credit_card_masking(value_str)
                if PIIType.CREDIT_CARD not in col_findings:
                    col_findings[PIIType.CREDIT_CARD] = []
                if len(col_findings[PIIType.CREDIT_CARD]) < max_violations:
                    col_findings[PIIType.CREDIT_CARD].append((idx, value_str, masking_type))
            
            # Check high entropy tokens
            if PIIType.HIGH_ENTROPY_TOKEN in forbidden_types and is_high_entropy_token(value_str):
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
                    severity=Severity.CRITICAL,
                    message=f"Forbidden PII type '{pii_type.value}' found in column '{col}' "
                            f"({len(violations)} occurrence(s))",
                )
                findings.append(finding)
    
    passed = len(findings) == 0
    severity = Severity.CRITICAL if not passed else Severity.INFO
    
    if passed:
        message = f"PASS: No forbidden PII detected in {policy.name}"
    else:
        total_violations = sum(f.count for f in findings)
        message = (
            f"FAIL: {policy.name} contains {len(findings)} forbidden PII type(s) "
            f"with {total_violations} total violation(s)"
        )
    
    return AssertionResult(
        assertion_type="no_forbidden_pii",
        dataset=policy.name,
        passed=passed,
        findings=findings,
        message=message,
        severity=severity,
    )

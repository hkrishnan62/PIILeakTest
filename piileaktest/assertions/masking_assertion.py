"""Assertion: Verify masking/hashing is properly applied to PII."""

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
from piileaktest.utils.redaction import redact_value


def assert_masking_applied(
    df: pd.DataFrame,
    policy: DatasetPolicy,
    max_violations: int = 10,
) -> AssertionResult:
    """
    Assert that required masking/hashing is properly applied to PII.
    
    Args:
        df: DataFrame to check
        policy: Dataset policy with masking_required_for and hash_allowed_for
        max_violations: Maximum number of violation examples to collect
        
    Returns:
        AssertionResult with findings
    """
    findings: List[Finding] = []
    masking_required = set(policy.masking_required_for)
    hash_allowed = set(policy.hash_allowed_for)
    
    if not masking_required:
        return AssertionResult(
            assertion_type="masking_applied",
            dataset=policy.name,
            passed=True,
            message="No masking requirements specified in policy",
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
                if pii_type in masking_required:
                    # Check if masking is acceptable
                    is_violation = False
                    
                    if masking_type == MaskingType.PLAINTEXT:
                        # Plaintext is never acceptable for masking_required
                        is_violation = True
                    elif masking_type == MaskingType.HASH:
                        # Hash is only acceptable if explicitly allowed
                        if pii_type not in hash_allowed:
                            is_violation = True
                    # PARTIAL_MASK, FULL_MASK, TOKENIZED are acceptable
                    
                    if is_violation:
                        if pii_type not in col_findings:
                            col_findings[pii_type] = []
                        if len(col_findings[pii_type]) < max_violations:
                            col_findings[pii_type].append((idx, value_str, masking_type))
            
            # Check credit card separately (Luhn)
            if PIIType.CREDIT_CARD in masking_required and is_credit_card(value_str):
                masking_type = detect_credit_card_masking(value_str)
                
                is_violation = False
                if masking_type == MaskingType.PLAINTEXT:
                    is_violation = True
                elif masking_type == MaskingType.HASH:
                    if PIIType.CREDIT_CARD not in hash_allowed:
                        is_violation = True
                
                if is_violation:
                    if PIIType.CREDIT_CARD not in col_findings:
                        col_findings[PIIType.CREDIT_CARD] = []
                    if len(col_findings[PIIType.CREDIT_CARD]) < max_violations:
                        col_findings[PIIType.CREDIT_CARD].append((idx, value_str, masking_type))
        
        # Convert to Finding objects
        for pii_type, violations in col_findings.items():
            if violations:
                first_violation = violations[0]
                
                # Determine severity based on masking type
                if first_violation[2] == MaskingType.PLAINTEXT:
                    severity = Severity.CRITICAL
                    msg_detail = "not masked (plaintext detected)"
                elif first_violation[2] == MaskingType.HASH:
                    severity = Severity.HIGH
                    msg_detail = "hashed but hashing not allowed by policy"
                else:
                    severity = Severity.MEDIUM
                    msg_detail = "masking insufficient"
                
                finding = Finding(
                    dataset=policy.name,
                    column=col,
                    pii_type=pii_type,
                    masking_type=first_violation[2],
                    row_index=int(first_violation[0]),
                    redacted_sample=redact_value(first_violation[1], pii_type.value),
                    count=len(violations),
                    severity=severity,
                    message=f"Required masking not applied to '{pii_type.value}' in column '{col}' "
                            f"({len(violations)} occurrence(s)): {msg_detail}",
                )
                findings.append(finding)
    
    passed = len(findings) == 0
    max_severity = max([f.severity for f in findings], default=Severity.INFO)
    
    if passed:
        message = f"PASS: All required masking properly applied in {policy.name}"
    else:
        total_violations = sum(f.count for f in findings)
        message = (
            f"FAIL: {policy.name} has {len(findings)} masking violation(s) "
            f"with {total_violations} total occurrence(s)"
        )
    
    return AssertionResult(
        assertion_type="masking_applied",
        dataset=policy.name,
        passed=passed,
        findings=findings,
        message=message,
        severity=max_severity if not passed else Severity.INFO,
    )

"""Assertion: Detect PII leakage across data lineage paths."""

import pandas as pd
from typing import List, Dict, Set, Tuple
from piileaktest.models import (
    AssertionResult,
    Finding,
    PIIType,
    Severity,
    DatasetPolicy,
    LineageEdge,
    MaskingType,
)
from piileaktest.detectors import detect_pii_in_value, is_credit_card
from piileaktest.detectors.luhn import detect_credit_card_masking
from piileaktest.detectors.entropy import is_high_entropy_token
from piileaktest.utils.redaction import redact_value


def assert_no_pii_leakage(
    source_df: pd.DataFrame,
    target_df: pd.DataFrame,
    source_policy: DatasetPolicy,
    target_policy: DatasetPolicy,
    lineage_edge: LineageEdge,
    max_violations: int = 10,
) -> AssertionResult:
    """
    Assert that forbidden PII in target does not leak from source.
    
    This checks if PII types that are:
    - Present in source
    - Forbidden in target
    
    Actually appear in the target dataset (contamination/leakage).
    
    Args:
        source_df: Source DataFrame
        target_df: Target DataFrame
        source_policy: Source dataset policy
        target_policy: Target dataset policy
        lineage_edge: Lineage edge describing the flow
        max_violations: Maximum number of violation examples
        
    Returns:
        AssertionResult with findings
    """
    findings: List[Finding] = []
    
    # Identify PII types that could leak
    target_forbidden = set(target_policy.forbidden_pii_types)
    
    if not target_forbidden:
        return AssertionResult(
            assertion_type="no_pii_leakage",
            dataset=f"{source_policy.name} -> {target_policy.name}",
            passed=True,
            message="No forbidden PII types in target policy",
            severity=Severity.INFO,
        )
    
    # First, detect what PII types exist in source
    source_pii_types = _detect_pii_types_in_dataframe(source_df)
    
    # Check which forbidden types in target actually appear in target
    risky_types = target_forbidden.intersection(source_pii_types)
    
    if not risky_types:
        return AssertionResult(
            assertion_type="no_pii_leakage",
            dataset=f"{source_policy.name} -> {target_policy.name}",
            passed=True,
            message=f"No risky PII types flow from {source_policy.name} to {target_policy.name}",
            severity=Severity.INFO,
        )
    
    # Now scan target for these risky types
    for col in target_df.columns:
        col_findings = {}  # Track findings by PII type
        
        for idx, value in target_df[col].items():
            if pd.isna(value):
                continue
            
            value_str = str(value).strip()
            if not value_str:
                continue
            
            # Check standard patterns
            detected = detect_pii_in_value(value_str)
            for pii_type, masking_type in detected:
                if pii_type in risky_types:
                    if pii_type not in col_findings:
                        col_findings[pii_type] = []
                    if len(col_findings[pii_type]) < max_violations:
                        col_findings[pii_type].append((idx, value_str, masking_type))
            
            # Check credit card
            if PIIType.CREDIT_CARD in risky_types and is_credit_card(value_str):
                masking_type = detect_credit_card_masking(value_str)
                if PIIType.CREDIT_CARD not in col_findings:
                    col_findings[PIIType.CREDIT_CARD] = []
                if len(col_findings[PIIType.CREDIT_CARD]) < max_violations:
                    col_findings[PIIType.CREDIT_CARD].append((idx, value_str, masking_type))
            
            # Check high entropy tokens
            if PIIType.HIGH_ENTROPY_TOKEN in risky_types and is_high_entropy_token(value_str):
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
                    dataset=target_policy.name,
                    column=col,
                    pii_type=pii_type,
                    masking_type=first_violation[2],
                    row_index=int(first_violation[0]),
                    redacted_sample=redact_value(first_violation[1], pii_type.value),
                    count=len(violations),
                    severity=Severity.CRITICAL,
                    message=(
                        f"PII LEAKAGE: '{pii_type.value}' leaked from {source_policy.name} "
                        f"to {target_policy.name} in column '{col}' ({len(violations)} occurrence(s))"
                    ),
                )
                findings.append(finding)
    
    passed = len(findings) == 0
    severity = Severity.CRITICAL if not passed else Severity.INFO
    
    if passed:
        message = f"PASS: No PII leakage detected from {source_policy.name} to {target_policy.name}"
    else:
        total_violations = sum(f.count for f in findings)
        leaked_types = len(set(f.pii_type for f in findings))
        message = (
            f"FAIL: {leaked_types} PII type(s) leaked from {source_policy.name} "
            f"to {target_policy.name} ({total_violations} total occurrence(s))"
        )
    
    return AssertionResult(
        assertion_type="no_pii_leakage",
        dataset=f"{source_policy.name} -> {target_policy.name}",
        passed=passed,
        findings=findings,
        message=message,
        severity=severity,
    )


def _detect_pii_types_in_dataframe(df: pd.DataFrame) -> Set[PIIType]:
    """
    Detect all PII types present in a DataFrame.
    
    Args:
        df: DataFrame to scan
        
    Returns:
        Set of PIIType values found
    """
    found_types: Set[PIIType] = set()
    
    for col in df.columns:
        for value in df[col]:
            if pd.isna(value):
                continue
            
            value_str = str(value).strip()
            if not value_str:
                continue
            
            # Check standard patterns
            detected = detect_pii_in_value(value_str)
            for pii_type, _ in detected:
                found_types.add(pii_type)
            
            # Check credit card
            if is_credit_card(value_str):
                found_types.add(PIIType.CREDIT_CARD)
            
            # Check high entropy
            if is_high_entropy_token(value_str):
                found_types.add(PIIType.HIGH_ENTROPY_TOKEN)
    
    return found_types

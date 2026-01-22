"""Tests for PII leakage path assertion."""

import pytest
import pandas as pd
from piileaktest.models import DatasetPolicy, PIIType, LineageEdge, Severity
from piileaktest.assertions import assert_no_pii_leakage


class TestLeakagePathAssertion:
    def test_leakage_detected(self):
        # Source has email, target forbids email, and email leaks through
        source_df = pd.DataFrame({
            'id': [1, 2],
            'email': ['john@example.com', 'jane@example.com'],
        })
        
        target_df = pd.DataFrame({
            'id': [1, 2],
            'contact': ['john@example.com', 'jane@example.com'],  # Email leaked!
        })
        
        source_policy = DatasetPolicy(
            name="source",
            path="source.csv",
            allowed_pii_types=[PIIType.EMAIL],
        )
        
        target_policy = DatasetPolicy(
            name="target",
            path="target.csv",
            forbidden_pii_types=[PIIType.EMAIL],
        )
        
        edge = LineageEdge(source="source", target="target")
        
        result = assert_no_pii_leakage(
            source_df,
            target_df,
            source_policy,
            target_policy,
            edge,
        )
        
        assert not result.passed
        assert result.severity == Severity.CRITICAL
        assert len(result.findings) > 0
        assert "LEAKAGE" in result.message
    
    def test_no_leakage_when_masked(self):
        # Source has email, target has masked email - no leakage
        source_df = pd.DataFrame({
            'id': [1, 2],
            'email': ['john@example.com', 'jane@example.com'],
        })
        
        target_df = pd.DataFrame({
            'id': [1, 2],
            'contact_hash': ['5d41402abc4b2a76b9719d911017c592', '7f8b6dd14b4e4e7e9a5b3e7e4c2a1f0d'],
        })
        
        source_policy = DatasetPolicy(
            name="source",
            path="source.csv",
            allowed_pii_types=[PIIType.EMAIL],
        )
        
        target_policy = DatasetPolicy(
            name="target",
            path="target.csv",
            forbidden_pii_types=[PIIType.EMAIL],
        )
        
        edge = LineageEdge(source="source", target="target")
        
        result = assert_no_pii_leakage(
            source_df,
            target_df,
            source_policy,
            target_policy,
            edge,
        )
        
        # Hashes don't match email patterns, so no leakage detected
        assert result.passed
    
    def test_no_risky_pii_types(self):
        # Source has email, but target doesn't forbid email
        source_df = pd.DataFrame({
            'id': [1, 2],
            'email': ['john@example.com', 'jane@example.com'],
        })
        
        target_df = pd.DataFrame({
            'id': [1, 2],
            'name': ['John', 'Jane'],
        })
        
        source_policy = DatasetPolicy(
            name="source",
            path="source.csv",
            allowed_pii_types=[PIIType.EMAIL],
        )
        
        target_policy = DatasetPolicy(
            name="target",
            path="target.csv",
            forbidden_pii_types=[PIIType.SSN],  # Forbids SSN, not email
        )
        
        edge = LineageEdge(source="source", target="target")
        
        result = assert_no_pii_leakage(
            source_df,
            target_df,
            source_policy,
            target_policy,
            edge,
        )
        
        # No risky types (email not forbidden in target)
        assert result.passed
    
    def test_empty_target_forbidden_list(self):
        # Target has no forbidden PII
        source_df = pd.DataFrame({
            'id': [1, 2],
            'email': ['john@example.com', 'jane@example.com'],
        })
        
        target_df = pd.DataFrame({
            'id': [1, 2],
            'email': ['john@example.com', 'jane@example.com'],
        })
        
        source_policy = DatasetPolicy(
            name="source",
            path="source.csv",
            allowed_pii_types=[PIIType.EMAIL],
        )
        
        target_policy = DatasetPolicy(
            name="target",
            path="target.csv",
            forbidden_pii_types=[],  # Nothing forbidden
        )
        
        edge = LineageEdge(source="source", target="target")
        
        result = assert_no_pii_leakage(
            source_df,
            target_df,
            source_policy,
            target_policy,
            edge,
        )
        
        assert result.passed
        assert result.severity == Severity.INFO

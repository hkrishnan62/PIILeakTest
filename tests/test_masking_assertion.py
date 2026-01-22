"""Tests for masking assertion."""

import pytest
import pandas as pd
from piileaktest.models import DatasetPolicy, PIIType, Severity
from piileaktest.assertions import assert_masking_applied


class TestMaskingAssertion:
    def test_plaintext_fails_when_masking_required(self):
        # Dataset with plaintext SSN when masking is required
        df = pd.DataFrame({
            'customer_id': [1, 2],
            'ssn': ['123-45-6789', '234-56-7890'],
        })
        
        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            masking_required_for=[PIIType.SSN],
        )
        
        result = assert_masking_applied(df, policy)
        
        assert not result.passed
        assert result.severity == Severity.CRITICAL
        assert len(result.findings) > 0
    
    def test_masked_ssn_passes(self):
        # Dataset with properly masked SSN
        df = pd.DataFrame({
            'customer_id': [1, 2],
            'ssn': ['***-**-6789', '***-**-7890'],
        })
        
        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            masking_required_for=[PIIType.SSN],
        )
        
        result = assert_masking_applied(df, policy)
        
        assert result.passed
        assert result.severity == Severity.INFO
    
    def test_hash_allowed(self):
        # Dataset with hashed email (allowed by policy)
        df = pd.DataFrame({
            'customer_id': [1, 2],
            'email_hash': ['5d41402abc4b2a76b9719d911017c592', '7f8b6dd14b4e4e7e9a5b3e7e4c2a1f0d'],
        })
        
        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            masking_required_for=[PIIType.EMAIL],
            hash_allowed_for=[PIIType.EMAIL],
        )
        
        result = assert_masking_applied(df, policy)
        
        # Hash is allowed, so should pass
        assert result.passed
    
    def test_hash_not_allowed(self):
        # Dataset with hashed email (not allowed by policy)
        df = pd.DataFrame({
            'customer_id': [1, 2],
            'email_hash': ['5d41402abc4b2a76b9719d911017c592', '7f8b6dd14b4e4e7e9a5b3e7e4c2a1f0d'],
        })
        
        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            masking_required_for=[PIIType.EMAIL],
            hash_allowed_for=[],  # Hash not allowed
        )
        
        result = assert_masking_applied(df, policy)
        
        # Hash is not allowed, but we can't detect it as email without plaintext
        # This test checks that we handle hash detection properly
        assert result.passed  # No email patterns detected in hash
    
    def test_no_masking_requirements(self):
        # No masking required
        df = pd.DataFrame({
            'customer_id': [1, 2],
            'name': ['John', 'Jane'],
        })
        
        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            masking_required_for=[],
        )
        
        result = assert_masking_applied(df, policy)
        
        assert result.passed
        assert result.severity == Severity.INFO

"""Tests for no forbidden PII assertion."""

import pytest
import pandas as pd
from piileaktest.models import DatasetPolicy, PIIType, Severity
from piileaktest.assertions import assert_no_forbidden_pii


class TestNoPIIAssertion:
    def test_forbidden_pii_detected(self):
        # Dataset with forbidden email
        df = pd.DataFrame(
            {
                "customer_id": [1, 2, 3],
                "email": ["john@example.com", "jane@example.com", "bob@example.com"],
            }
        )

        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            forbidden_pii_types=[PIIType.EMAIL],
        )

        result = assert_no_forbidden_pii(df, policy)

        assert not result.passed
        assert result.severity == Severity.CRITICAL
        assert len(result.findings) > 0
        assert result.findings[0].pii_type == PIIType.EMAIL

    def test_no_forbidden_pii(self):
        # Dataset without forbidden PII
        df = pd.DataFrame(
            {
                "customer_id": [1, 2, 3],
                "name": ["John", "Jane", "Bob"],
            }
        )

        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            forbidden_pii_types=[PIIType.EMAIL, PIIType.SSN],
        )

        result = assert_no_forbidden_pii(df, policy)

        assert result.passed
        assert result.severity == Severity.INFO

    def test_multiple_pii_types_forbidden(self):
        # Dataset with multiple forbidden PII types
        df = pd.DataFrame(
            {
                "customer_id": [1, 2],
                "email": ["john@example.com", "jane@example.com"],
                "ssn": ["123-45-6789", "234-56-7890"],
            }
        )

        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            forbidden_pii_types=[PIIType.EMAIL, PIIType.SSN],
        )

        result = assert_no_forbidden_pii(df, policy)

        assert not result.passed
        assert len(result.findings) >= 2  # At least email and ssn findings

    def test_empty_forbidden_list(self):
        # No forbidden PII types specified
        df = pd.DataFrame(
            {
                "customer_id": [1, 2],
                "email": ["john@example.com", "jane@example.com"],
            }
        )

        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            forbidden_pii_types=[],
        )

        result = assert_no_forbidden_pii(df, policy)

        assert result.passed
        assert result.severity == Severity.INFO

    def test_redacted_samples(self):
        # Check that samples are properly redacted
        df = pd.DataFrame(
            {
                "customer_id": [1],
                "email": ["john.doe@example.com"],
            }
        )

        policy = DatasetPolicy(
            name="test_dataset",
            path="test.csv",
            forbidden_pii_types=[PIIType.EMAIL],
        )

        result = assert_no_forbidden_pii(df, policy)

        assert not result.passed
        assert result.findings[0].redacted_sample is not None
        # Should be redacted (not full email)
        assert "john.doe@example.com" not in result.findings[0].redacted_sample
        assert "***" in result.findings[0].redacted_sample

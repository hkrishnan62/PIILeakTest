"""Tests for value pattern detectors."""

import pytest
from piileaktest.detectors.value_patterns import (
    EmailMatcher,
    PhoneMatcher,
    SSNMatcher,
    IPAddressMatcher,
    detect_pii_in_value,
)
from piileaktest.models import MaskingType, PIIType


class TestEmailMatcher:
    def test_plaintext_email(self):
        matcher = EmailMatcher()
        assert matcher.matches("john.doe@example.com")
        assert matcher.detect_masking("john.doe@example.com") == MaskingType.PLAINTEXT
    
    def test_masked_email(self):
        matcher = EmailMatcher()
        assert matcher.matches("j***@e***.com")
        assert matcher.detect_masking("j***@e***.com") == MaskingType.PARTIAL_MASK
    
    def test_hash(self):
        matcher = EmailMatcher()
        hash_value = "5d41402abc4b2a76b9719d911017c592"
        assert matcher.detect_masking(hash_value) == MaskingType.HASH
    
    def test_invalid_email(self):
        matcher = EmailMatcher()
        assert not matcher.matches("not-an-email")
        assert not matcher.matches("@example.com")


class TestPhoneMatcher:
    def test_plaintext_phone_formats(self):
        matcher = PhoneMatcher()
        assert matcher.matches("555-123-4567")
        assert matcher.matches("(555) 123-4567")
        assert matcher.matches("5551234567")
        assert matcher.matches("+15551234567")
    
    def test_masked_phone(self):
        matcher = PhoneMatcher()
        assert matcher.matches("(***) ***-4567")
        assert matcher.detect_masking("(***) ***-4567") == MaskingType.PARTIAL_MASK
    
    def test_invalid_phone(self):
        matcher = PhoneMatcher()
        assert not matcher.matches("123")
        assert not matcher.matches("not-a-phone")


class TestSSNMatcher:
    def test_plaintext_ssn(self):
        matcher = SSNMatcher()
        assert matcher.matches("123-45-6789")
        assert matcher.matches("123456789")
        assert matcher.detect_masking("123-45-6789") == MaskingType.PLAINTEXT
    
    def test_masked_ssn(self):
        matcher = SSNMatcher()
        assert matcher.matches("***-**-6789")
        assert matcher.matches("XXX-XX-6789")
        assert matcher.detect_masking("***-**-6789") == MaskingType.PARTIAL_MASK
    
    def test_invalid_ssn(self):
        matcher = SSNMatcher()
        assert not matcher.matches("123-45")
        assert not matcher.matches("not-a-ssn")


class TestIPAddressMatcher:
    def test_valid_ipv4(self):
        matcher = IPAddressMatcher()
        assert matcher.matches("192.168.1.1")
        assert matcher.matches("10.0.0.1")
        assert matcher.matches("255.255.255.255")
    
    def test_invalid_ip(self):
        matcher = IPAddressMatcher()
        assert not matcher.matches("256.1.1.1")
        assert not matcher.matches("192.168.1")
        assert not matcher.matches("not-an-ip")


class TestDetectPIIInValue:
    def test_email_detection(self):
        results = detect_pii_in_value("john.doe@example.com")
        pii_types = [pii_type for pii_type, _ in results]
        assert PIIType.EMAIL in pii_types
    
    def test_phone_detection(self):
        results = detect_pii_in_value("555-123-4567")
        pii_types = [pii_type for pii_type, _ in results]
        assert PIIType.PHONE in pii_types
    
    def test_ssn_detection(self):
        results = detect_pii_in_value("123-45-6789")
        pii_types = [pii_type for pii_type, _ in results]
        assert PIIType.SSN in pii_types
    
    def test_no_pii(self):
        results = detect_pii_in_value("just a normal string")
        assert len(results) == 0
    
    def test_empty_string(self):
        results = detect_pii_in_value("")
        assert len(results) == 0

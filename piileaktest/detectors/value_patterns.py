"""Value pattern matchers for detecting PII in data."""

import re
from typing import Optional
from piileaktest.models import PIIType, MaskingType


class PatternMatcher:
    """Base class for PII pattern matching."""
    
    def __init__(self):
        self.pii_type: Optional[PIIType] = None
    
    def matches(self, value: str) -> bool:
        """Check if value matches the pattern."""
        raise NotImplementedError
    
    def detect_masking(self, value: str) -> MaskingType:
        """Detect the type of masking applied to the value."""
        raise NotImplementedError


class EmailMatcher(PatternMatcher):
    """Matcher for email addresses."""
    
    def __init__(self):
        super().__init__()
        self.pii_type = PIIType.EMAIL
        # Standard email pattern
        self.pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        # Masked email patterns
        self.masked_pattern = re.compile(r'\*+@.*\.\w+')
        self.hash_pattern = re.compile(r'^[a-fA-F0-9]{32,64}$')
    
    def matches(self, value: str) -> bool:
        """Check if value is an email or masked email."""
        if not isinstance(value, str):
            return False
        value = value.strip()
        return bool(self.pattern.match(value) or self.masked_pattern.match(value))
    
    def detect_masking(self, value: str) -> MaskingType:
        """Detect masking type for email."""
        if self.hash_pattern.match(value):
            return MaskingType.HASH
        elif '*' in value:
            return MaskingType.PARTIAL_MASK
        elif self.pattern.match(value):
            return MaskingType.PLAINTEXT
        return MaskingType.PLAINTEXT


class PhoneMatcher(PatternMatcher):
    """Matcher for US phone numbers."""
    
    def __init__(self):
        super().__init__()
        self.pii_type = PIIType.PHONE
        # Various US phone formats
        self.patterns = [
            re.compile(r'^\d{3}-\d{3}-\d{4}$'),
            re.compile(r'^\(\d{3}\)\s*\d{3}-\d{4}$'),
            re.compile(r'^\d{10}$'),
            re.compile(r'^\+1\d{10}$'),
        ]
        # Masked patterns
        self.masked_patterns = [
            re.compile(r'\*+.*\d{4}'),
            re.compile(r'\(\*+\).*\d{4}'),
        ]
        self.hash_pattern = re.compile(r'^[a-fA-F0-9]{32,64}$')
    
    def matches(self, value: str) -> bool:
        """Check if value is a phone number."""
        if not isinstance(value, str):
            return False
        value = value.strip()
        
        # Check plaintext patterns
        for pattern in self.patterns:
            if pattern.match(value):
                return True
        
        # Check masked patterns
        for pattern in self.masked_patterns:
            if pattern.match(value):
                return True
        
        return False
    
    def detect_masking(self, value: str) -> MaskingType:
        """Detect masking type for phone."""
        if self.hash_pattern.match(value):
            return MaskingType.HASH
        elif '*' in value:
            return MaskingType.PARTIAL_MASK
        else:
            for pattern in self.patterns:
                if pattern.match(value):
                    return MaskingType.PLAINTEXT
        return MaskingType.PLAINTEXT


class SSNMatcher(PatternMatcher):
    """Matcher for US Social Security Numbers."""
    
    def __init__(self):
        super().__init__()
        self.pii_type = PIIType.SSN
        # SSN patterns: 123-45-6789 or 123456789
        self.patterns = [
            re.compile(r'^\d{3}-\d{2}-\d{4}$'),
            re.compile(r'^\d{9}$'),
        ]
        # Masked patterns: ***-**-1234, XXX-XX-1234
        self.masked_patterns = [
            re.compile(r'^[\*X]{3}-[\*X]{2}-\d{4}$'),
            re.compile(r'^[\*X]{5}\d{4}$'),
        ]
        self.hash_pattern = re.compile(r'^[a-fA-F0-9]{32,64}$')
    
    def matches(self, value: str) -> bool:
        """Check if value is an SSN."""
        if not isinstance(value, str):
            return False
        value = value.strip()
        
        # Check plaintext
        for pattern in self.patterns:
            if pattern.match(value):
                return True
        
        # Check masked
        for pattern in self.masked_patterns:
            if pattern.match(value):
                return True
        
        return False
    
    def detect_masking(self, value: str) -> MaskingType:
        """Detect masking type for SSN."""
        if self.hash_pattern.match(value):
            return MaskingType.HASH
        elif '*' in value or 'X' in value:
            return MaskingType.PARTIAL_MASK
        else:
            for pattern in self.patterns:
                if pattern.match(value):
                    return MaskingType.PLAINTEXT
        return MaskingType.PLAINTEXT


class IPAddressMatcher(PatternMatcher):
    """Matcher for IP addresses."""
    
    def __init__(self):
        super().__init__()
        self.pii_type = PIIType.IP_ADDRESS
        # IPv4 pattern
        self.pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        self.hash_pattern = re.compile(r'^[a-fA-F0-9]{32,64}$')
    
    def matches(self, value: str) -> bool:
        """Check if value is an IP address."""
        if not isinstance(value, str):
            return False
        return bool(self.pattern.match(value.strip()))
    
    def detect_masking(self, value: str) -> MaskingType:
        """Detect masking type for IP."""
        if self.hash_pattern.match(value):
            return MaskingType.HASH
        elif '*' in value:
            return MaskingType.PARTIAL_MASK
        return MaskingType.PLAINTEXT


class ZipCodeMatcher(PatternMatcher):
    """Matcher for US ZIP codes."""
    
    def __init__(self):
        super().__init__()
        self.pii_type = PIIType.ZIP_CODE
        # US ZIP: 12345 or 12345-6789
        self.patterns = [
            re.compile(r'^\d{5}$'),
            re.compile(r'^\d{5}-\d{4}$'),
        ]
    
    def matches(self, value: str) -> bool:
        """Check if value is a ZIP code."""
        if not isinstance(value, str):
            return False
        value = value.strip()
        for pattern in self.patterns:
            if pattern.match(value):
                return True
        return False
    
    def detect_masking(self, value: str) -> MaskingType:
        """ZIP codes are quasi-identifiers, typically not masked."""
        return MaskingType.PLAINTEXT


class DOBMatcher(PatternMatcher):
    """Matcher for dates of birth."""
    
    def __init__(self):
        super().__init__()
        self.pii_type = PIIType.DOB
        # Common date formats
        self.patterns = [
            re.compile(r'^\d{4}-\d{2}-\d{2}$'),  # YYYY-MM-DD
            re.compile(r'^\d{2}/\d{2}/\d{4}$'),  # MM/DD/YYYY
            re.compile(r'^\d{2}-\d{2}-\d{4}$'),  # MM-DD-YYYY
        ]
    
    def matches(self, value: str) -> bool:
        """Check if value looks like a date of birth."""
        if not isinstance(value, str):
            return False
        value = value.strip()
        for pattern in self.patterns:
            if pattern.match(value):
                # Additional check: year should be reasonable for DOB
                if '19' in value or '20' in value:
                    return True
        return False
    
    def detect_masking(self, value: str) -> MaskingType:
        """DOB masking detection."""
        if '*' in value or 'X' in value:
            return MaskingType.PARTIAL_MASK
        return MaskingType.PLAINTEXT


class AccountNumberMatcher(PatternMatcher):
    """Matcher for account numbers."""
    
    def __init__(self):
        super().__init__()
        self.pii_type = PIIType.ACCOUNT_NUMBER
        # Generic account number: 8-16 digits
        self.pattern = re.compile(r'^\d{8,16}$')
        self.masked_pattern = re.compile(r'^\*+\d{4}$')
        self.hash_pattern = re.compile(r'^[a-fA-F0-9]{32,64}$')
    
    def matches(self, value: str) -> bool:
        """Check if value looks like an account number."""
        if not isinstance(value, str):
            return False
        value = value.strip()
        return bool(self.pattern.match(value) or self.masked_pattern.match(value))
    
    def detect_masking(self, value: str) -> MaskingType:
        """Detect masking for account numbers."""
        if self.hash_pattern.match(value):
            return MaskingType.HASH
        elif '*' in value:
            return MaskingType.PARTIAL_MASK
        return MaskingType.PLAINTEXT


# Registry of all matchers
MATCHERS = [
    EmailMatcher(),
    PhoneMatcher(),
    SSNMatcher(),
    IPAddressMatcher(),
    ZipCodeMatcher(),
    DOBMatcher(),
    AccountNumberMatcher(),
]


def detect_pii_in_value(value: str) -> list[tuple[PIIType, MaskingType]]:
    """
    Detect PII types and masking in a single value.
    
    Args:
        value: The value to check
        
    Returns:
        List of (PIIType, MaskingType) tuples for all matches
    """
    if not isinstance(value, str) or not value.strip():
        return []
    
    results = []
    value = str(value).strip()
    
    for matcher in MATCHERS:
        if matcher.matches(value):
            masking = matcher.detect_masking(value)
            results.append((matcher.pii_type, masking))
    
    return results

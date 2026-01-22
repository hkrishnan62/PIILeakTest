"""Data models for PIILeakTest framework."""

from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class PIIType(str, Enum):
    """Enumeration of PII types detected by the framework."""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    PASSPORT = "passport"
    DOB = "dob"
    ZIP_CODE = "zip_code"
    FULL_NAME = "full_name"
    ACCOUNT_NUMBER = "account_number"
    HIGH_ENTROPY_TOKEN = "high_entropy_token"


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class MaskingType(str, Enum):
    """Types of masking/obfuscation applied to PII."""

    PLAINTEXT = "plaintext"
    PARTIAL_MASK = "partial_mask"  # e.g., ***-**-1234
    FULL_MASK = "full_mask"  # e.g., ****
    HASH = "hash"  # hex string of length 32/40/64
    TOKENIZED = "tokenized"  # replaced with token


class Finding(BaseModel):
    """Represents a single PII detection finding."""

    dataset: str
    column: str
    pii_type: PIIType
    masking_type: MaskingType
    row_index: Optional[int] = None
    redacted_sample: Optional[str] = None
    count: int = 1
    severity: Severity = Severity.MEDIUM
    message: str = ""


class DatasetPolicy(BaseModel):
    """Policy definition for a dataset."""

    name: str
    path: str
    format: str = "csv"
    allowed_pii_types: List[PIIType] = Field(default_factory=list)
    forbidden_pii_types: List[PIIType] = Field(default_factory=list)
    masking_required_for: List[PIIType] = Field(default_factory=list)
    hash_allowed_for: List[PIIType] = Field(default_factory=list)


class LineageEdge(BaseModel):
    """Represents a data lineage edge between datasets."""

    source: str
    target: str


class SamplingConfig(BaseModel):
    """Configuration for data sampling."""

    mode: str = "head"  # head, random, full
    rows: int = 1000


class ThresholdConfig(BaseModel):
    """Thresholds for detection and reporting."""

    entropy_threshold: float = 4.5
    max_violations_to_show: int = 10
    fail_on_severity: List[Severity] = Field(
        default_factory=lambda: [Severity.CRITICAL, Severity.HIGH]
    )


class SuiteConfig(BaseModel):
    """Complete test suite configuration."""

    datasets: List[DatasetPolicy]
    lineage: List[LineageEdge] = Field(default_factory=list)
    sampling: SamplingConfig = Field(default_factory=SamplingConfig)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)


class AssertionResult(BaseModel):
    """Result of a single assertion."""

    assertion_type: str
    dataset: str
    passed: bool
    findings: List[Finding] = Field(default_factory=list)
    message: str = ""
    severity: Severity = Severity.INFO


class SuiteResult(BaseModel):
    """Overall result of running a test suite."""

    suite_name: str = "PIILeakTest Suite"
    timestamp: datetime = Field(default_factory=datetime.now)
    total_datasets: int = 0
    total_assertions: int = 0
    passed_assertions: int = 0
    failed_assertions: int = 0
    assertion_results: List[AssertionResult] = Field(default_factory=list)
    overall_passed: bool = False
    execution_time_seconds: float = 0.0
    summary: Dict[str, Any] = Field(default_factory=dict)

    def should_fail_ci(self) -> bool:
        """Determine if CI should fail based on severity thresholds."""
        critical_high_failures = [
            ar
            for ar in self.assertion_results
            if not ar.passed and ar.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        return len(critical_high_failures) > 0

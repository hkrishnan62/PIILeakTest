"""JSON reporter for PIILeakTest results."""

import json
from pathlib import Path
from datetime import datetime
from piileaktest.models import SuiteResult, Finding, AssertionResult


def export_to_json(result: SuiteResult, output_path: str) -> None:
    """
    Export suite results to JSON format.
    
    Args:
        result: SuiteResult object to export
        output_path: Path to output JSON file
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Convert to dict with proper serialization
    result_dict = _serialize_result(result)
    
    with open(output_file, 'w') as f:
        json.dump(result_dict, f, indent=2, default=str)


def _serialize_result(result: SuiteResult) -> dict:
    """Serialize SuiteResult to dictionary."""
    return {
        "suite_name": result.suite_name,
        "timestamp": result.timestamp.isoformat(),
        "total_datasets": result.total_datasets,
        "total_assertions": result.total_assertions,
        "passed_assertions": result.passed_assertions,
        "failed_assertions": result.failed_assertions,
        "overall_passed": result.overall_passed,
        "should_fail_ci": result.should_fail_ci(),
        "execution_time_seconds": result.execution_time_seconds,
        "summary": result.summary,
        "assertion_results": [
            _serialize_assertion_result(ar) for ar in result.assertion_results
        ],
    }


def _serialize_assertion_result(ar: AssertionResult) -> dict:
    """Serialize AssertionResult to dictionary."""
    return {
        "assertion_type": ar.assertion_type,
        "dataset": ar.dataset,
        "passed": ar.passed,
        "message": ar.message,
        "severity": ar.severity.value,
        "findings": [_serialize_finding(f) for f in ar.findings],
    }


def _serialize_finding(finding: Finding) -> dict:
    """Serialize Finding to dictionary."""
    return {
        "dataset": finding.dataset,
        "column": finding.column,
        "pii_type": finding.pii_type.value,
        "masking_type": finding.masking_type.value,
        "row_index": finding.row_index,
        "redacted_sample": finding.redacted_sample,
        "count": finding.count,
        "severity": finding.severity.value,
        "message": finding.message,
    }


def load_from_json(input_path: str) -> dict:
    """
    Load results from JSON file.
    
    Args:
        input_path: Path to JSON file
        
    Returns:
        Dictionary representation of results
    """
    with open(input_path, 'r') as f:
        return json.load(f)

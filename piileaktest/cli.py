"""Command-line interface for PIILeakTest."""

import sys
import time
from pathlib import Path
from typing import Optional
import typer
import pandas as pd
from piileaktest import __version__
from piileaktest.config import load_suite_config
from piileaktest.models import DatasetPolicy, SuiteResult, Severity
from piileaktest.assertions import (
    assert_no_forbidden_pii,
    assert_masking_applied,
    assert_only_allowed_pii,
    assert_no_pii_leakage,
)
from piileaktest.lineage import (
    get_all_lineage_edges,
    validate_lineage_references,
)
from piileaktest.reporting import export_to_json, export_to_html, load_from_json
from piileaktest.utils import setup_logger, sample_dataframe

app = typer.Typer(
    name="piileaktest",
    help="ETL testing framework for detecting PII leakage in data pipelines",
    add_completion=False,
)

logger = setup_logger("piileaktest.cli")


def load_dataframe(file_path: str, format_hint: Optional[str] = None) -> pd.DataFrame:
    """Load a DataFrame from file with format auto-detection."""
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Determine format
    if format_hint:
        fmt = format_hint.lower()
    else:
        fmt = path.suffix.lower().lstrip('.')
    
    if fmt in ['csv', 'txt']:
        return pd.read_csv(file_path)
    elif fmt == 'json':
        return pd.read_json(file_path)
    elif fmt in ['parquet', 'pq']:
        return pd.read_parquet(file_path)
    else:
        # Try CSV as fallback
        try:
            return pd.read_csv(file_path)
        except Exception:
            raise ValueError(f"Unsupported file format: {fmt}")


@app.command()
def scan(
    file: str = typer.Argument(..., help="Path to data file to scan"),
    forbidden_pii: str = typer.Option(
        "",
        "--forbidden",
        "-f",
        help="Comma-separated list of forbidden PII types (e.g., email,ssn,phone)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for results (JSON)",
    ),
    format: Optional[str] = typer.Option(
        None,
        help="File format hint (csv, json, parquet)",
    ),
):
    """
    Ad-hoc scan of a single file for PII violations.
    """
    logger.info(f"Scanning file: {file}")
    
    try:
        # Load data
        df = load_dataframe(file, format)
        logger.info(f"Loaded {len(df)} rows, {len(df.columns)} columns")
        
        # Parse forbidden PII types
        forbidden_types = []
        if forbidden_pii:
            from piileaktest.models import PIIType
            for pii_str in forbidden_pii.split(','):
                pii_str = pii_str.strip().upper()
                try:
                    forbidden_types.append(PIIType[pii_str])
                except KeyError:
                    typer.echo(f"Warning: Unknown PII type '{pii_str}', skipping", err=True)
        
        if not forbidden_types:
            typer.echo("No forbidden PII types specified. Specify with --forbidden", err=True)
            raise typer.Exit(1)
        
        # Create ad-hoc policy
        policy = DatasetPolicy(
            name=Path(file).name,
            path=file,
            format=format or 'csv',
            forbidden_pii_types=forbidden_types,
        )
        
        # Run assertion
        result = assert_no_forbidden_pii(df, policy)
        
        # Display results
        typer.echo(f"\n{result.message}")
        typer.echo(f"Severity: {result.severity.value}")
        
        if result.findings:
            typer.echo(f"\nFindings ({len(result.findings)}):")
            for finding in result.findings:
                typer.echo(f"  - {finding.message}")
                if finding.redacted_sample:
                    typer.echo(f"    Sample: {finding.redacted_sample}")
        
        # Save output if requested
        if output:
            suite_result = SuiteResult(
                suite_name="Ad-hoc Scan",
                total_datasets=1,
                total_assertions=1,
                passed_assertions=1 if result.passed else 0,
                failed_assertions=0 if result.passed else 1,
                assertion_results=[result],
                overall_passed=result.passed,
            )
            export_to_json(suite_result, output)
            typer.echo(f"\nResults saved to: {output}")
        
        # Exit with appropriate code
        if not result.passed:
            raise typer.Exit(1)
        
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def run_suite(
    config: str = typer.Argument(..., help="Path to suite configuration YAML"),
    output_dir: str = typer.Option(
        "reports",
        "--output",
        "-o",
        help="Output directory for reports",
    ),
):
    """
    Run a complete test suite across datasets and lineage.
    """
    logger.info(f"Loading suite configuration: {config}")
    
    start_time = time.time()
    
    try:
        # Load configuration
        suite_config = load_suite_config(config)
        logger.info(f"Loaded configuration with {len(suite_config.datasets)} datasets")
        
        # Validate lineage
        lineage_errors = validate_lineage_references(suite_config)
        if lineage_errors:
            for error in lineage_errors:
                typer.echo(f"Error: {error}", err=True)
            raise typer.Exit(1)
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Load all datasets
        datasets = {}
        for ds_policy in suite_config.datasets:
            logger.info(f"Loading dataset: {ds_policy.name}")
            df = load_dataframe(ds_policy.path, ds_policy.format)
            
            # Apply sampling
            df = sample_dataframe(
                df,
                mode=suite_config.sampling.mode,
                rows=suite_config.sampling.rows,
            )
            datasets[ds_policy.name] = df
            logger.info(f"  Loaded {len(df)} rows (after sampling)")
        
        # Run assertions
        suite_result = SuiteResult(
            suite_name="PIILeakTest Suite",
            total_datasets=len(suite_config.datasets),
        )
        
        # 1. Run per-dataset assertions
        for ds_policy in suite_config.datasets:
            df = datasets[ds_policy.name]
            
            # No forbidden PII assertion
            if ds_policy.forbidden_pii_types:
                logger.info(f"Checking forbidden PII in {ds_policy.name}")
                result = assert_no_forbidden_pii(
                    df,
                    ds_policy,
                    suite_config.thresholds.max_violations_to_show,
                )
                suite_result.assertion_results.append(result)
            
            # Masking assertion
            if ds_policy.masking_required_for:
                logger.info(f"Checking masking requirements in {ds_policy.name}")
                result = assert_masking_applied(
                    df,
                    ds_policy,
                    suite_config.thresholds.max_violations_to_show,
                )
                suite_result.assertion_results.append(result)
            
            # Only allowed PII assertion (if allowed list is specified)
            if ds_policy.allowed_pii_types:
                logger.info(f"Checking allowed PII constraints in {ds_policy.name}")
                result = assert_only_allowed_pii(
                    df,
                    ds_policy,
                    suite_config.thresholds.max_violations_to_show,
                )
                suite_result.assertion_results.append(result)
        
        # 2. Run lineage assertions
        if suite_config.lineage:
            logger.info("Checking lineage for PII leakage")
            for edge in suite_config.lineage:
                source_policy = next(ds for ds in suite_config.datasets if ds.name == edge.source)
                target_policy = next(ds for ds in suite_config.datasets if ds.name == edge.target)
                
                source_df = datasets[edge.source]
                target_df = datasets[edge.target]
                
                logger.info(f"  Checking flow: {edge.source} -> {edge.target}")
                result = assert_no_pii_leakage(
                    source_df,
                    target_df,
                    source_policy,
                    target_policy,
                    edge,
                    suite_config.thresholds.max_violations_to_show,
                )
                suite_result.assertion_results.append(result)
        
        # Calculate summary
        suite_result.total_assertions = len(suite_result.assertion_results)
        suite_result.passed_assertions = sum(
            1 for ar in suite_result.assertion_results if ar.passed
        )
        suite_result.failed_assertions = suite_result.total_assertions - suite_result.passed_assertions
        suite_result.overall_passed = suite_result.failed_assertions == 0
        suite_result.execution_time_seconds = time.time() - start_time
        
        # Generate summary stats
        total_findings = sum(len(ar.findings) for ar in suite_result.assertion_results)
        suite_result.summary = {
            "total_findings": total_findings,
            "critical_findings": sum(
                1 for ar in suite_result.assertion_results
                for f in ar.findings
                if f.severity == Severity.CRITICAL
            ),
            "high_findings": sum(
                1 for ar in suite_result.assertion_results
                for f in ar.findings
                if f.severity == Severity.HIGH
            ),
        }
        
        # Export reports
        json_path = output_path / "findings.json"
        html_path = output_path / "report.html"
        
        export_to_json(suite_result, str(json_path))
        export_to_html(suite_result, str(html_path))
        
        # Display summary
        typer.echo("\n" + "=" * 60)
        typer.echo("PIILeakTest Suite Results")
        typer.echo("=" * 60)
        typer.echo(f"Total Datasets: {suite_result.total_datasets}")
        typer.echo(f"Total Assertions: {suite_result.total_assertions}")
        typer.echo(f"Passed: {suite_result.passed_assertions}")
        typer.echo(f"Failed: {suite_result.failed_assertions}")
        typer.echo(f"Total Findings: {total_findings}")
        typer.echo(f"Execution Time: {suite_result.execution_time_seconds:.2f}s")
        typer.echo("")
        
        if suite_result.overall_passed:
            typer.echo("✓ ALL CHECKS PASSED", fg=typer.colors.GREEN, bold=True)
        else:
            typer.echo("✗ FAILURES DETECTED", fg=typer.colors.RED, bold=True)
            
            # Show failed assertions
            typer.echo("\nFailed Assertions:")
            for ar in suite_result.assertion_results:
                if not ar.passed:
                    typer.echo(f"  - [{ar.severity.value}] {ar.dataset}: {ar.message}")
        
        typer.echo(f"\nReports generated:")
        typer.echo(f"  JSON: {json_path}")
        typer.echo(f"  HTML: {html_path}")
        
        # Exit with appropriate code
        if suite_result.should_fail_ci():
            typer.echo("\n⚠ CI should fail (Critical/High severity failures detected)", err=True)
            raise typer.Exit(1)
        
    except Exception as e:
        logger.exception("Suite execution failed")
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def validate_flow(
    config: str = typer.Argument(..., help="Path to suite configuration YAML"),
):
    """
    Validate data lineage flows for PII contamination only.
    """
    logger.info(f"Validating lineage flows: {config}")
    
    try:
        # Load configuration
        suite_config = load_suite_config(config)
        
        if not suite_config.lineage:
            typer.echo("No lineage edges defined in configuration", err=True)
            raise typer.Exit(0)
        
        # Validate lineage
        lineage_errors = validate_lineage_references(suite_config)
        if lineage_errors:
            for error in lineage_errors:
                typer.echo(f"Error: {error}", err=True)
            raise typer.Exit(1)
        
        # Load datasets
        datasets = {}
        for ds_policy in suite_config.datasets:
            df = load_dataframe(ds_policy.path, ds_policy.format)
            df = sample_dataframe(
                df,
                mode=suite_config.sampling.mode,
                rows=suite_config.sampling.rows,
            )
            datasets[ds_policy.name] = df
        
        # Run lineage checks only
        suite_result = SuiteResult(suite_name="Lineage Validation")
        
        for edge in suite_config.lineage:
            source_policy = next(ds for ds in suite_config.datasets if ds.name == edge.source)
            target_policy = next(ds for ds in suite_config.datasets if ds.name == edge.target)
            
            source_df = datasets[edge.source]
            target_df = datasets[edge.target]
            
            logger.info(f"Validating flow: {edge.source} -> {edge.target}")
            result = assert_no_pii_leakage(
                source_df,
                target_df,
                source_policy,
                target_policy,
                edge,
                suite_config.thresholds.max_violations_to_show,
            )
            suite_result.assertion_results.append(result)
        
        # Summary
        suite_result.total_assertions = len(suite_result.assertion_results)
        suite_result.passed_assertions = sum(1 for ar in suite_result.assertion_results if ar.passed)
        suite_result.failed_assertions = suite_result.total_assertions - suite_result.passed_assertions
        
        typer.echo(f"\nLineage Validation Results:")
        typer.echo(f"Flows Checked: {suite_result.total_assertions}")
        typer.echo(f"Passed: {suite_result.passed_assertions}")
        typer.echo(f"Failed: {suite_result.failed_assertions}")
        
        if suite_result.failed_assertions > 0:
            typer.echo("\n✗ Leakage detected in flows:", fg=typer.colors.RED)
            for ar in suite_result.assertion_results:
                if not ar.passed:
                    typer.echo(f"  - {ar.dataset}: {ar.message}")
            raise typer.Exit(1)
        else:
            typer.echo("\n✓ All flows validated successfully", fg=typer.colors.GREEN)
        
    except Exception as e:
        logger.exception("Flow validation failed")
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def report(
    input: str = typer.Option(..., "--input", "-i", help="Input JSON findings file"),
    output: str = typer.Option(..., "--output", "-o", help="Output HTML report file"),
):
    """
    Generate HTML report from JSON findings.
    """
    try:
        logger.info(f"Loading findings from: {input}")
        findings_dict = load_from_json(input)
        
        # Reconstruct SuiteResult from dict
        from piileaktest.models import SuiteResult, AssertionResult, Finding, PIIType, MaskingType, Severity
        from datetime import datetime
        
        assertion_results = []
        for ar_dict in findings_dict.get('assertion_results', []):
            findings = [
                Finding(
                    dataset=f['dataset'],
                    column=f['column'],
                    pii_type=PIIType(f['pii_type']),
                    masking_type=MaskingType(f['masking_type']),
                    row_index=f.get('row_index'),
                    redacted_sample=f.get('redacted_sample'),
                    count=f['count'],
                    severity=Severity(f['severity']),
                    message=f['message'],
                )
                for f in ar_dict.get('findings', [])
            ]
            
            assertion_results.append(
                AssertionResult(
                    assertion_type=ar_dict['assertion_type'],
                    dataset=ar_dict['dataset'],
                    passed=ar_dict['passed'],
                    message=ar_dict['message'],
                    severity=Severity(ar_dict['severity']),
                    findings=findings,
                )
            )
        
        suite_result = SuiteResult(
            suite_name=findings_dict.get('suite_name', 'PIILeakTest'),
            timestamp=datetime.fromisoformat(findings_dict['timestamp']),
            total_datasets=findings_dict['total_datasets'],
            total_assertions=findings_dict['total_assertions'],
            passed_assertions=findings_dict['passed_assertions'],
            failed_assertions=findings_dict['failed_assertions'],
            overall_passed=findings_dict['overall_passed'],
            execution_time_seconds=findings_dict['execution_time_seconds'],
            summary=findings_dict.get('summary', {}),
            assertion_results=assertion_results,
        )
        
        export_to_html(suite_result, output)
        typer.echo(f"HTML report generated: {output}")
        
    except Exception as e:
        logger.exception("Report generation failed")
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    typer.echo(f"PIILeakTest v{__version__}")


if __name__ == "__main__":
    app()

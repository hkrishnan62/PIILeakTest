"""HTML reporter for PIILeakTest results."""

from pathlib import Path
from jinja2 import Template
from piileaktest.models import SuiteResult

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PIILeakTest Report - {{ suite_name }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2em;
        }
        .header {
            border-bottom: 3px solid #3498db;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .status {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            margin-top: 10px;
        }
        .status-pass {
            background: #27ae60;
            color: white;
        }
        .status-fail {
            background: #e74c3c;
            color: white;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }
        .summary-card h3 {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        .assertion {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .assertion-fail {
            border-left-color: #e74c3c;
        }
        .assertion-pass {
            border-left-color: #27ae60;
        }
        .assertion h3 {
            margin-bottom: 10px;
            color: #2c3e50;
        }
        .assertion-meta {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        .severity {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 10px;
        }
        .severity-CRITICAL {
            background: #c0392b;
            color: white;
        }
        .severity-HIGH {
            background: #e74c3c;
            color: white;
        }
        .severity-MEDIUM {
            background: #f39c12;
            color: white;
        }
        .severity-LOW {
            background: #95a5a6;
            color: white;
        }
        .severity-INFO {
            background: #3498db;
            color: white;
        }
        .findings {
            margin-top: 15px;
        }
        .finding {
            background: white;
            border: 1px solid #dee2e6;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .finding-header {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .finding-detail {
            color: #6c757d;
            font-size: 0.9em;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            background: #f8f9fa;
            font-weight: bold;
            color: #2c3e50;
        }
        .code {
            background: #f1f3f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PIILeakTest Report</h1>
            <p class="timestamp">Generated: {{ timestamp }}</p>
            <div class="status {% if overall_passed %}status-pass{% else %}status-fail{% endif %}">
                {% if overall_passed %}✓ ALL CHECKS PASSED{% else %}✗ FAILURES DETECTED{% endif %}
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Datasets</h3>
                <div class="value">{{ total_datasets }}</div>
            </div>
            <div class="summary-card">
                <h3>Total Assertions</h3>
                <div class="value">{{ total_assertions }}</div>
            </div>
            <div class="summary-card">
                <h3>Passed</h3>
                <div class="value" style="color: #27ae60;">{{ passed_assertions }}</div>
            </div>
            <div class="summary-card">
                <h3>Failed</h3>
                <div class="value" style="color: #e74c3c;">{{ failed_assertions }}</div>
            </div>
            <div class="summary-card">
                <h3>Execution Time</h3>
                <div class="value" style="font-size: 1.5em;">{{ "%.2f"|format(execution_time_seconds) }}s</div>
            </div>
        </div>

        <h2 style="margin: 30px 0 20px 0; color: #2c3e50;">Assertion Results</h2>
        
        {% for assertion in assertion_results %}
        <div class="assertion {% if assertion.passed %}assertion-pass{% else %}assertion-fail{% endif %}">
            <h3>
                {% if assertion.passed %}✓{% else %}✗{% endif %}
                {{ assertion.assertion_type }} - {{ assertion.dataset }}
            </h3>
            <div class="assertion-meta">
                <span class="severity severity-{{ assertion.severity }}">{{ assertion.severity }}</span>
                <span>{{ assertion.message }}</span>
            </div>
            
            {% if assertion.findings %}
            <div class="findings">
                <strong>Findings ({{ assertion.findings|length }}):</strong>
                {% for finding in assertion.findings %}
                <div class="finding">
                    <div class="finding-header">
                        <span class="severity severity-{{ finding.severity }}">{{ finding.severity }}</span>
                        Column: <span class="code">{{ finding.column }}</span> | 
                        PII Type: <span class="code">{{ finding.pii_type }}</span> |
                        Masking: <span class="code">{{ finding.masking_type }}</span>
                    </div>
                    <div class="finding-detail">
                        {{ finding.message }}
                        {% if finding.redacted_sample %}
                        <br>Sample: <span class="code">{{ finding.redacted_sample }}</span>
                        {% endif %}
                        {% if finding.row_index is not none %}
                        <br>Row Index: {{ finding.row_index }}
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endfor %}

        <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d;">
            <p>Generated by PIILeakTest v0.1.0</p>
            <p style="font-size: 0.9em; margin-top: 5px;">
                ETL Testing Framework for PII Leakage Detection
            </p>
        </div>
    </div>
</body>
</html>
"""


def export_to_html(result: SuiteResult, output_path: str) -> None:
    """
    Export suite results to HTML format.

    Args:
        result: SuiteResult object to export
        output_path: Path to output HTML file
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    template = Template(HTML_TEMPLATE)

    html_content = template.render(
        suite_name=result.suite_name,
        timestamp=result.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        overall_passed=result.overall_passed,
        total_datasets=result.total_datasets,
        total_assertions=result.total_assertions,
        passed_assertions=result.passed_assertions,
        failed_assertions=result.failed_assertions,
        execution_time_seconds=result.execution_time_seconds,
        assertion_results=[
            {
                "assertion_type": ar.assertion_type,
                "dataset": ar.dataset,
                "passed": ar.passed,
                "message": ar.message,
                "severity": ar.severity.value,
                "findings": [
                    {
                        "dataset": f.dataset,
                        "column": f.column,
                        "pii_type": f.pii_type.value,
                        "masking_type": f.masking_type.value,
                        "row_index": f.row_index,
                        "redacted_sample": f.redacted_sample,
                        "count": f.count,
                        "severity": f.severity.value,
                        "message": f.message,
                    }
                    for f in ar.findings
                ],
            }
            for ar in result.assertion_results
        ],
    )

    with open(output_file, "w") as f:
        f.write(html_content)

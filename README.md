# PIILeakTest

**ETL Testing Framework for Detecting PII Leakage in Data Pipelines**

PIILeakTest is a Python testing framework designed to detect, track, and prevent Personally Identifiable Information (PII) leakage across data transformation pipelines. It helps data engineers ensure compliance with privacy regulations (GDPR, CCPA, etc.) by validating that sensitive data is properly masked, hashed, or removed as it flows through ETL stages.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Features

- **🔍 Automated PII Detection**: Detects 11+ types of PII including emails, SSNs, credit cards, phone numbers, and more
- **🔗 Data Lineage Tracking**: Validates that PII policies are enforced across pipeline stages
- **✅ Policy-Based Testing**: Define what PII is allowed, forbidden, or must be masked at each pipeline stage
- **🎭 Masking Validation**: Verifies proper masking, hashing, and tokenization of sensitive data
- **📊 Multiple Detectors**: Uses pattern matching, Luhn algorithm, entropy analysis, and column heuristics
- **📈 Rich Reporting**: Generate HTML and JSON reports with detailed findings and severity levels
- **🚀 CI/CD Ready**: Configurable severity thresholds to fail builds on policy violations
- **📁 Multi-Format Support**: Works with CSV, JSON, Parquet files

## Quick Start

### Installation

```bash
# From PyPI (when published)
pip install piileaktest

# From source
git clone https://github.com/hkrishnan62/PIILeakTest.git
cd PIILeakTest
pip install -e .
```

### Basic Usage

#### 1. Ad-hoc File Scan

Quickly scan a single file for PII:

```bash
piileaktest scan data.csv --forbidden email,ssn,phone
```

#### 2. Suite-Based Testing (Recommended)

Create a test suite configuration file (`suite.yaml`):

```yaml
datasets:
  - name: source_data
    path: data/raw_customers.csv
    allowed_pii_types:
      - email
      - phone
      - full_name
    forbidden_pii_types: []

  - name: analytics_data
    path: data/analytics_export.csv
    allowed_pii_types: []
    forbidden_pii_types:
      - email
      - phone
      - ssn
      - credit_card

lineage:
  - source: source_data
    target: analytics_data

sampling:
  mode: head
  rows: 1000

thresholds:
  entropy_threshold: 4.5
  fail_on_severity:
    - CRITICAL
    - HIGH
```

Run the test suite:

```bash
piileaktest run-suite suite.yaml --output reports/
```

This generates:
- `reports/findings.json` - Machine-readable results
- `reports/report.html` - Human-readable report with visualizations

### Run the Demo

```bash
cd examples/
bash run_demo.sh
```

## How It Works

PIILeakTest validates your data pipeline in three key ways:

### 1. **Dataset Policy Enforcement**

Each dataset can define:
- **Allowed PII Types**: PII that's permitted in this dataset
- **Forbidden PII Types**: PII that must NOT appear (triggers failures)
- **Masking Requirements**: PII types that must be masked/hashed
- **Hash Allowances**: PII that can appear in hashed form

### 2. **Lineage-Aware Testing**

Define data flows between datasets:
```yaml
lineage:
  - source: raw_customers
    target: staging_customers
  - source: staging_customers
    target: analytics_export
```

PIILeakTest validates that:
- PII doesn't leak to downstream stages where it's forbidden
- Masking is applied at the correct pipeline stage
- Sensitive data is progressively removed/protected

### 3. **Multi-Layer PII Detection**

The framework uses multiple detection strategies:

| Detector | Purpose | Examples |
|----------|---------|----------|
| **Pattern Matching** | Regex-based detection | Emails, SSNs, Credit Cards, IP addresses |
| **Luhn Algorithm** | Credit card validation | 16-digit card numbers |
| **Entropy Analysis** | Detects high-entropy tokens | API keys, session tokens |
| **Column Heuristics** | Name-based detection | Columns named "email", "ssn", etc. |

## Supported PII Types

- `email` - Email addresses
- `phone` - Phone numbers (US/International)
- `ssn` - Social Security Numbers
- `credit_card` - Credit card numbers (with Luhn validation)
- `ip_address` - IPv4 addresses
- `passport` - Passport numbers
- `dob` - Date of birth
- `zip_code` - US ZIP codes
- `full_name` - Personal names
- `account_number` - Account/customer IDs
- `high_entropy_token` - API keys, tokens, secrets

## CLI Commands

### `scan` - Ad-hoc File Scan

```bash
piileaktest scan <file> [OPTIONS]

Options:
  -f, --forbidden TEXT   Comma-separated forbidden PII types
  -o, --output TEXT      Output file for JSON results
  --format TEXT          File format (csv, json, parquet)
```

### `run-suite` - Execute Test Suite

```bash
piileaktest run-suite <config.yaml> [OPTIONS]

Options:
  -o, --output TEXT      Output directory for reports
  --fail-fast            Stop on first assertion failure
  --verbose              Enable verbose logging
```

### `version` - Show Version

```bash
piileaktest version
```

## Configuration Reference

### Dataset Policy

```yaml
datasets:
  - name: dataset_name           # Unique identifier
    path: data/file.csv           # Path to data file
    format: csv                   # csv, json, parquet
    allowed_pii_types:            # PII allowed in this dataset
      - email
      - phone
    forbidden_pii_types:          # PII that MUST NOT appear
      - ssn
      - credit_card
    masking_required_for:         # PII that must be masked
      - ssn
    hash_allowed_for:             # PII allowed in hashed form
      - email
```

### Thresholds

```yaml
thresholds:
  entropy_threshold: 4.5                  # Bits for high-entropy detection
  max_violations_to_show: 10              # Limit violations in reports
  fail_on_severity:                       # CI failure criteria
    - CRITICAL
    - HIGH
```

### Sampling

```yaml
sampling:
  mode: head      # head, random, full
  rows: 1000      # Number of rows to sample
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/hkrishnan62/PIILeakTest.git
cd PIILeakTest

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=piileaktest --cov-report=html

# Format code
black piileaktest/ tests/

# Lint
ruff check piileaktest/
```

### Project Structure

```
piileaktest/
├── assertions/          # Policy assertion logic
│   ├── allowed_pii_assertion.py
│   ├── leakage_path_assertion.py
│   ├── masking_assertion.py
│   └── no_pii_assertion.py
├── detectors/           # PII detection engines
│   ├── column_heuristics.py
│   ├── entropy.py
│   ├── luhn.py
│   └── value_patterns.py
├── lineage/             # Data flow tracking
│   ├── flow_loader.py
│   └── graph_trace.py
├── reporting/           # Result formatting
│   ├── html_reporter.py
│   └── json_reporter.py
└── utils/               # Shared utilities
    ├── logging.py
    ├── redaction.py
    └── sampling.py
```

## Use Cases

### 1. **Data Warehouse Validation**

Ensure raw data is properly sanitized before reaching analytics layers:

```yaml
lineage:
  - source: raw_customers      # All PII allowed
    target: staging            # SSN must be masked
  - source: staging
    target: warehouse          # Only tokenized IDs
  - source: warehouse
    target: analytics          # No PII at all
```

### 2. **GDPR Compliance Testing**

Validate that EU customer data is properly anonymized:

```yaml
datasets:
  - name: eu_customers
    forbidden_pii_types:
      - email
      - phone
      - ip_address
      - dob
    hash_allowed_for:
      - full_name
```

### 3. **CI/CD Pipeline Integration**

Add to your GitHub Actions workflow:

```yaml
- name: Check for PII Leakage
  run: |
    piileaktest run-suite tests/pii-suite.yaml
    if [ $? -ne 0 ]; then
      echo "PII leakage detected!"
      exit 1
    fi
```

## Limitations

- **Sampling**: By default, only analyzes first 1000 rows for performance
- **False Positives**: Pattern-based detection may flag non-PII data
- **Language Support**: Primarily focused on English/US formats
- **File Size**: Large files (>1GB) may require custom sampling strategies

## Roadmap

- [ ] Support for SQL query scanning
- [ ] Integration with dbt for data transformation testing
- [ ] Cloud storage connectors (S3, BigQuery, Snowflake)
- [ ] Custom PII type definitions
- [ ] ML-based PII detection
- [ ] Differential privacy metrics
- [ ] Real-time streaming data validation

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure:
- Tests pass: `pytest`
- Code is formatted: `black piileaktest/`
- No linting errors: `ruff check piileaktest/`

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Built for data engineers who care about privacy and compliance.

## Support

- **Issues**: [GitHub Issues](https://github.com/hkrishnan62/PIILeakTest/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hkrishnan62/PIILeakTest/discussions)

---

**⚠️ Disclaimer**: PIILeakTest is a testing tool and should be part of a comprehensive data privacy strategy. It does not guarantee complete PII detection or compliance with privacy regulations. Always consult with legal and security professionals for compliance requirements.
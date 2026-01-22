#!/bin/bash
# Demo script to run PIILeakTest suite

echo "=========================================="
echo "PIILeakTest Demo"
echo "=========================================="
echo ""

# Run the full test suite
echo "Running PIILeakTest suite..."
piileaktest run-suite examples/suite.yaml --output reports

echo ""
echo "Demo complete! Check the reports/ directory for results."
echo "  - reports/findings.json (JSON format)"
echo "  - reports/report.html (HTML format)"

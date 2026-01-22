"""Smoke tests for CLI commands."""

import pytest
import subprocess
import sys
from pathlib import Path


def test_cli_version():
    """Test that version command works."""
    result = subprocess.run(
        [sys.executable, "-m", "piileaktest.cli", "version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "PIILeakTest" in result.stdout


def test_cli_help():
    """Test that help command works."""
    result = subprocess.run(
        [sys.executable, "-m", "piileaktest.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "PIILeakTest" in result.stdout or "piileaktest" in result.stdout


def test_scan_command_help():
    """Test that scan command help works."""
    result = subprocess.run(
        [sys.executable, "-m", "piileaktest.cli", "scan", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan" in result.stdout.lower()


def test_run_suite_command_help():
    """Test that run-suite command help works."""
    result = subprocess.run(
        [sys.executable, "-m", "piileaktest.cli", "run-suite", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "suite" in result.stdout.lower()

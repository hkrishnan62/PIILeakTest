"""Configuration loader for PIILeakTest."""

import yaml
from pathlib import Path
from typing import Dict, Any
from piileaktest.models import SuiteConfig


def load_suite_config(config_path: str) -> SuiteConfig:
    """
    Load test suite configuration from YAML file.

    Args:
        config_path: Path to the YAML configuration file

    Returns:
        SuiteConfig object

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(path, "r") as f:
        raw_config = yaml.safe_load(f)

    if not raw_config:
        raise ValueError(f"Empty configuration file: {config_path}")

    try:
        return SuiteConfig(**raw_config)
    except Exception as e:
        raise ValueError(f"Invalid configuration: {e}")


def load_policy_from_dict(policy_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Load policy from dictionary (for CLI inline policies).

    Args:
        policy_dict: Dictionary containing policy configuration

    Returns:
        Validated policy dictionary
    """
    required_keys = ["allowed_pii_types", "forbidden_pii_types"]
    for key in required_keys:
        if key not in policy_dict:
            policy_dict[key] = []

    return policy_dict

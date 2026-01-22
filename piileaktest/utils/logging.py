"""Utility functions for consistent logging."""

import logging
import sys
from typing import Optional


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Setup a logger with consistent formatting.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get or create a logger."""
    if name is None:
        name = "piileaktest"
    return logging.getLogger(name)

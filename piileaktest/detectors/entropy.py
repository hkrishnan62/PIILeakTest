"""Entropy-based detection for high-entropy tokens (secrets, keys)."""

import math
import re
from typing import Optional


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Args:
        data: Input string
        
    Returns:
        Entropy value (bits per character)
    """
    if not data:
        return 0.0
    
    # Count frequency of each character
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def is_high_entropy_token(value: str, threshold: float = 4.5) -> bool:
    """
    Check if a value is a high-entropy token (likely a secret/key).
    
    High entropy tokens are often:
    - API keys
    - Authentication tokens
    - Cryptographic keys
    - Session IDs
    
    Args:
        value: String to check
        threshold: Entropy threshold (default 4.5 bits per character)
        
    Returns:
        True if entropy exceeds threshold and looks like a token
    """
    if not isinstance(value, str) or len(value) < 16:
        return False
    
    # Common patterns for tokens
    # Alphanumeric with reasonable length
    if not re.match(r'^[a-zA-Z0-9_\-+=/.]{16,}$', value):
        return False
    
    entropy = calculate_shannon_entropy(value)
    return entropy >= threshold


def detect_common_token_patterns(value: str) -> Optional[str]:
    """
    Detect common token/key patterns.
    
    Args:
        value: String to check
        
    Returns:
        Token type if detected, None otherwise
    """
    if not isinstance(value, str):
        return None
    
    patterns = {
        'aws_key': re.compile(r'^AKIA[0-9A-Z]{16}$'),
        'jwt': re.compile(r'^eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+$'),
        'github_token': re.compile(r'^gh[pousr]_[a-zA-Z0-9]{36,}$'),
        'uuid': re.compile(
            r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        ),
    }
    
    for token_type, pattern in patterns.items():
        if pattern.match(value):
            return token_type
    
    return None

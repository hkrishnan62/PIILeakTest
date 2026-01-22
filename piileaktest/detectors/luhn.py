"""Luhn algorithm validator for credit card numbers."""

import re
from piileaktest.models import MaskingType


def luhn_checksum(card_number: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm.
    
    Args:
        card_number: String containing digits
        
    Returns:
        True if valid according to Luhn algorithm
    """
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10 == 0


def is_credit_card(value: str) -> bool:
    """
    Check if a value is a valid credit card number.
    
    Args:
        value: String to check
        
    Returns:
        True if value appears to be a valid credit card
    """
    if not isinstance(value, str):
        return False
    
    # Remove common separators
    cleaned = re.sub(r'[\s\-]', '', value)
    
    # Check if it's all digits and reasonable length (13-19 digits)
    if not cleaned.isdigit() or len(cleaned) < 13 or len(cleaned) > 19:
        return False
    
    # Validate with Luhn algorithm
    return luhn_checksum(cleaned)


def detect_credit_card_masking(value: str) -> MaskingType:
    """
    Detect the type of masking applied to a credit card number.
    
    Args:
        value: Credit card value (possibly masked)
        
    Returns:
        MaskingType indicating the masking level
    """
    if not isinstance(value, str):
        return MaskingType.PLAINTEXT
    
    # Check for hash (32, 40, or 64 hex characters)
    if re.match(r'^[a-fA-F0-9]{32,64}$', value):
        return MaskingType.HASH
    
    # Check for partial masking: ****1234 or **** **** **** 1234
    if '*' in value or 'X' in value.upper():
        return MaskingType.PARTIAL_MASK
    
    # Check if it's a valid plaintext card
    if is_credit_card(value):
        return MaskingType.PLAINTEXT
    
    return MaskingType.PLAINTEXT

"""Utility functions for redacting sensitive data in outputs."""

import re


def redact_email(email: str) -> str:
    """
    Redact email address for safe display.

    Example: john.doe@example.com -> j***@e***.com
    """
    if "@" not in email:
        return mask_string(email)

    local, domain = email.split("@", 1)
    if "." in domain:
        domain_parts = domain.split(".")
        domain_name = domain_parts[0]
        domain_ext = ".".join(domain_parts[1:])
        return f"{local[0]}***@{domain_name[0]}***.{domain_ext}"
    return f"{local[0]}***@{domain[0]}***"


def redact_ssn(ssn: str) -> str:
    """
    Redact SSN for safe display.

    Example: 123-45-6789 -> ***-**-6789
    """
    # Keep last 4 digits
    if len(ssn) >= 4:
        return "***-**-" + ssn[-4:]
    return "***"


def redact_phone(phone: str) -> str:
    """
    Redact phone number for safe display.

    Example: (555) 123-4567 -> (***) ***-4567
    """
    # Extract digits
    digits = re.sub(r"\D", "", phone)
    if len(digits) >= 4:
        return f"(***) ***-{digits[-4:]}"
    return "***"


def redact_credit_card(card: str) -> str:
    """
    Redact credit card for safe display.

    Example: 4532123456789012 -> ****1234
    """
    digits = re.sub(r"\D", "", card)
    if len(digits) >= 4:
        return "****" + digits[-4:]
    return "****"


def mask_string(s: str, keep_chars: int = 1) -> str:
    """
    Generic string masking.

    Args:
        s: String to mask
        keep_chars: Number of characters to keep at start

    Returns:
        Masked string
    """
    if len(s) <= keep_chars:
        return "*" * len(s)
    return s[:keep_chars] + "*" * (len(s) - keep_chars)


def redact_value(value: str, pii_type: str) -> str:
    """
    Redact a value based on PII type.

    Args:
        value: The value to redact
        pii_type: Type of PII (email, ssn, phone, credit_card, etc.)

    Returns:
        Redacted value
    """
    value_str = str(value)

    redactors = {
        "email": redact_email,
        "ssn": redact_ssn,
        "phone": redact_phone,
        "credit_card": redact_credit_card,
    }

    redactor = redactors.get(pii_type.lower(), mask_string)
    return redactor(value_str)

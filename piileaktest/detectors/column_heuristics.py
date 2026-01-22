"""Column heuristics for detecting PII based on column names."""

import re
from typing import List, Set
from piileaktest.models import PIIType


# Common column name patterns for PII types
PII_COLUMN_PATTERNS = {
    PIIType.EMAIL: [
        r'email',
        r'e_mail',
        r'mail',
        r'contact_email',
        r'user_email',
    ],
    PIIType.PHONE: [
        r'phone',
        r'telephone',
        r'mobile',
        r'cell',
        r'contact_number',
        r'phone_number',
    ],
    PIIType.SSN: [
        r'ssn',
        r'social_security',
        r'social_security_number',
        r'ss_number',
    ],
    PIIType.CREDIT_CARD: [
        r'credit_card',
        r'card_number',
        r'cc_number',
        r'card_num',
        r'payment_card',
    ],
    PIIType.IP_ADDRESS: [
        r'ip_address',
        r'ip_addr',
        r'ipaddress',
        r'client_ip',
        r'user_ip',
    ],
    PIIType.DOB: [
        r'dob',
        r'date_of_birth',
        r'birth_date',
        r'birthdate',
        r'birthday',
    ],
    PIIType.ZIP_CODE: [
        r'zip',
        r'zipcode',
        r'zip_code',
        r'postal_code',
        r'postcode',
    ],
    PIIType.FULL_NAME: [
        r'full_name',
        r'fullname',
        r'customer_name',
        r'user_name',
        r'name',
    ],
    PIIType.ACCOUNT_NUMBER: [
        r'account_number',
        r'account_num',
        r'acct_number',
        r'account_id',
        r'bank_account',
    ],
    PIIType.PASSPORT: [
        r'passport',
        r'passport_number',
        r'passport_num',
        r'passport_id',
    ],
}


def identify_pii_columns(column_names: List[str]) -> dict[str, Set[PIIType]]:
    """
    Identify potential PII columns based on column names.
    
    Args:
        column_names: List of column names from the dataset
        
    Returns:
        Dictionary mapping column names to set of potential PII types
    """
    results = {}
    
    for col in column_names:
        col_lower = col.lower().strip()
        potential_types = set()
        
        for pii_type, patterns in PII_COLUMN_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, col_lower):
                    potential_types.add(pii_type)
                    break
        
        if potential_types:
            results[col] = potential_types
    
    return results


def is_likely_pii_column(column_name: str) -> bool:
    """
    Check if a column name suggests it contains PII.
    
    Args:
        column_name: The column name to check
        
    Returns:
        True if column name suggests PII content
    """
    col_lower = column_name.lower().strip()
    
    for patterns in PII_COLUMN_PATTERNS.values():
        for pattern in patterns:
            if re.search(pattern, col_lower):
                return True
    
    return False

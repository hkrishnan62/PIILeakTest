"""Tests for Luhn credit card validator."""

import pytest
from piileaktest.detectors.luhn import is_credit_card, detect_credit_card_masking
from piileaktest.models import MaskingType


class TestLuhnValidator:
    def test_valid_credit_cards(self):
        # Valid test credit card numbers
        assert is_credit_card("4532015112830366")  # Visa
        assert is_credit_card("5425233430109903")  # Mastercard
        assert is_credit_card("374245455400126")  # Amex

    def test_invalid_credit_cards(self):
        assert not is_credit_card("1234567890123456")
        assert not is_credit_card("0000000000000000")
        assert not is_credit_card("123")

    def test_credit_card_with_spaces(self):
        assert is_credit_card("4532 0151 1283 0366")

    def test_credit_card_with_dashes(self):
        assert is_credit_card("4532-0151-1283-0366")

    def test_masking_detection_plaintext(self):
        masking = detect_credit_card_masking("4532015112830366")
        assert masking == MaskingType.PLAINTEXT

    def test_masking_detection_partial(self):
        masking = detect_credit_card_masking("****0366")
        assert masking == MaskingType.PARTIAL_MASK

    def test_masking_detection_hash(self):
        masking = detect_credit_card_masking("5d41402abc4b2a76b9719d911017c592")
        assert masking == MaskingType.HASH

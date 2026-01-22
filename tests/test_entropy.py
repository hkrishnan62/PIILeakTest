"""Tests for entropy detector."""

import pytest
from piileaktest.detectors.entropy import (
    calculate_shannon_entropy,
    is_high_entropy_token,
    detect_common_token_patterns,
)


class TestEntropyDetector:
    def test_shannon_entropy_uniform(self):
        # "aaaa" has low entropy
        entropy = calculate_shannon_entropy("aaaa")
        assert entropy == 0.0

    def test_shannon_entropy_varied(self):
        # Mixed characters have higher entropy
        entropy = calculate_shannon_entropy("abcdefgh")
        assert entropy > 2.5

    def test_high_entropy_token_detection(self):
        # JWT-like token with slightly lower threshold since base64 encoding
        # can have lower entropy than random strings
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        assert is_high_entropy_token(token, threshold=4.3)

    def test_low_entropy_not_detected(self):
        # Simple repeated pattern
        assert not is_high_entropy_token("aaaaaaaaaaaaaaaa")

    def test_short_string_not_token(self):
        # Too short to be a token
        assert not is_high_entropy_token("abc")

    def test_detect_jwt_pattern(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        pattern = detect_common_token_patterns(jwt)
        assert pattern == "jwt"

    def test_detect_aws_key_pattern(self):
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        pattern = detect_common_token_patterns(aws_key)
        assert pattern == "aws_key"

    def test_no_common_pattern(self):
        random_string = "just_a_normal_string"
        pattern = detect_common_token_patterns(random_string)
        assert pattern is None

"""Tests for Shannon entropy calculation."""

from __future__ import annotations

import math

from ipa_analyzer.utils.entropy import shannon_entropy


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_character_repeated(self):
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_two_equal_characters(self):
        """'ab' repeated should have entropy of 1.0 bit."""
        result = shannon_entropy("ab")
        assert math.isclose(result, 1.0, rel_tol=1e-9)

    def test_four_equal_characters(self):
        """'abcd' should have entropy of 2.0 bits."""
        result = shannon_entropy("abcd")
        assert math.isclose(result, 2.0, rel_tol=1e-9)

    def test_high_entropy_string(self):
        """A random-looking string should have high entropy."""
        result = shannon_entropy("aB3$xZ9!kL7@mN2&")
        assert result > 3.5

    def test_low_entropy_string(self):
        """A repetitive string should have low entropy."""
        result = shannon_entropy("aaabbb")
        assert result < 1.5

    def test_aws_key_like_string(self):
        """AWS-key-like strings should have moderate-to-high entropy."""
        result = shannon_entropy("AKIAIOSFODNN7EXAMPLE")
        assert result > 3.0

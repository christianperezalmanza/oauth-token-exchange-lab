"""
Unit tests for PKCE (Proof Key for Code Exchange) implementation.

Tests the generation and validation of PKCE code verifier and challenge.
"""

import pytest
import base64
import hashlib
import re


# Import the function from client.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Mock environment variables before importing client
os.environ.update({
    'OKTA_DOMAIN': 'https://test.okta.com',
    'CLIENT_ID': 'test_client',
    'CLIENT_SECRET': 'test_secret',
    'SERVICE_CLIENT_ID': 'test_service',
    'SERVICE_CLIENT_SECRET': 'test_service_secret',
    'RESOURCE_SERVER_ID': 'test_resource',
    'AUDIENCE': 'test.com',
    'REDIRECT_URI': 'http://test.com/callback',
    'RESOURCE_SERVER_URI': 'http://test.com/api'
})

from client import generate_pkce_pair


@pytest.mark.unit
class TestPKCE:
    """Test PKCE generation and validation"""

    def test_generate_pkce_pair_returns_two_values(self):
        """PKCE generation should return verifier and challenge"""
        code_verifier, code_challenge = generate_pkce_pair()

        assert code_verifier is not None
        assert code_challenge is not None
        assert isinstance(code_verifier, str)
        assert isinstance(code_challenge, str)

    def test_code_verifier_length(self):
        """Code verifier should be between 43-128 characters (RFC 7636)"""
        code_verifier, _ = generate_pkce_pair()

        assert 43 <= len(code_verifier) <= 128

    def test_code_verifier_character_set(self):
        """Code verifier should be URL-safe base64 without padding"""
        code_verifier, _ = generate_pkce_pair()

        # Should only contain URL-safe base64 characters
        pattern = re.compile(r'^[A-Za-z0-9_-]+$')
        assert pattern.match(code_verifier)

        # Should not have padding
        assert '=' not in code_verifier

    def test_code_challenge_is_sha256_of_verifier(self):
        """Code challenge should be SHA256 hash of verifier"""
        code_verifier, code_challenge = generate_pkce_pair()

        # Manually compute what the challenge should be
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        assert code_challenge == expected_challenge

    def test_code_challenge_character_set(self):
        """Code challenge should be URL-safe base64 without padding"""
        _, code_challenge = generate_pkce_pair()

        # Should only contain URL-safe base64 characters
        pattern = re.compile(r'^[A-Za-z0-9_-]+$')
        assert pattern.match(code_challenge)

        # Should not have padding
        assert '=' not in code_challenge

    def test_generate_different_pairs(self):
        """Each call should generate unique verifier/challenge pairs"""
        pair1 = generate_pkce_pair()
        pair2 = generate_pkce_pair()
        pair3 = generate_pkce_pair()

        # All verifiers should be unique
        verifiers = [pair1[0], pair2[0], pair3[0]]
        assert len(verifiers) == len(set(verifiers))

        # All challenges should be unique
        challenges = [pair1[1], pair2[1], pair3[1]]
        assert len(challenges) == len(set(challenges))

    def test_challenge_length(self):
        """Code challenge should be 43 characters (base64url of SHA256)"""
        _, code_challenge = generate_pkce_pair()

        # SHA256 is 32 bytes, base64url without padding is 43 chars
        assert len(code_challenge) == 43

    def test_pkce_pair_consistency(self):
        """Same verifier should always produce same challenge"""
        code_verifier, original_challenge = generate_pkce_pair()

        # Manually recompute challenge from verifier
        recomputed_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        assert original_challenge == recomputed_challenge

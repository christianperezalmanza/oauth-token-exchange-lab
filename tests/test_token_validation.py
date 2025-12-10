"""
Unit tests for JWT token validation in api.py.

Tests the token validation logic including signature verification,
expiration checks, issuer validation, audience validation, and scope checks.
"""

import pytest
import jwt
import time
from unittest.mock import Mock, patch, MagicMock


# Import the function from api.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Mock environment variables before importing api
os.environ.update({
    'OKTA_DOMAIN': 'https://test.okta.com',
    'AUDIENCE': 'test.com'
})

from api import validate_token, ISSUER, EXPECTED_AUDIENCE, REQUIRED_SCOPES


@pytest.mark.unit
class TestTokenValidation:
    """Test token validation logic"""

    def create_test_token(self, payload, private_key=None):
        """Helper to create a test JWT token"""
        if private_key is None:
            # Use a test key for signing
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

        return jwt.encode(payload, private_key, algorithm="RS256")

    def test_validate_token_with_missing_sub(self, mocker):
        """Token without 'sub' claim should be rejected"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': EXPECTED_AUDIENCE,
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': REQUIRED_SCOPES
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to return payload without 'sub'
        mocker.patch('api.jwt.decode', return_value=payload)

        result = validate_token(token, verbose=False)

        assert result is None

    def test_validate_token_with_wrong_audience(self, mocker):
        """Token with wrong audience should be rejected"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': 'wrong-audience.com',
            'sub': 'user123',
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': REQUIRED_SCOPES
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to return payload
        mocker.patch('api.jwt.decode', return_value=payload)

        result = validate_token(token, verbose=False)

        assert result is None

    def test_validate_token_with_missing_scopes(self, mocker):
        """Token without required scopes should be rejected"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': EXPECTED_AUDIENCE,
            'sub': 'user123',
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': ['some:other:scope']  # Wrong scopes
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to return payload
        mocker.patch('api.jwt.decode', return_value=payload)

        result = validate_token(token, verbose=False)

        assert result is None

    def test_validate_token_with_partial_scopes(self, mocker):
        """Token with only some required scopes should be rejected"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': EXPECTED_AUDIENCE,
            'sub': 'user123',
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': [REQUIRED_SCOPES[0]]  # Only first required scope
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to return payload
        mocker.patch('api.jwt.decode', return_value=payload)

        result = validate_token(token, verbose=False)

        assert result is None

    def test_validate_token_with_string_scopes(self, mocker):
        """Token with scopes as space-separated string should work"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': EXPECTED_AUDIENCE,
            'sub': 'user123',
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': ' '.join(REQUIRED_SCOPES)  # String instead of list
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to return payload
        mocker.patch('api.jwt.decode', return_value=payload)

        result = validate_token(token, verbose=False)

        assert result == payload

    def test_validate_token_with_valid_payload(self, mocker):
        """Token with all valid claims should be accepted"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': EXPECTED_AUDIENCE,
            'sub': 'user123',
            'email': 'user@test.com',
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': REQUIRED_SCOPES
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to return payload
        mocker.patch('api.jwt.decode', return_value=payload)

        result = validate_token(token, verbose=False)

        assert result == payload

    def test_validate_token_expired(self, mocker):
        """Expired token should be rejected"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': EXPECTED_AUDIENCE,
            'sub': 'user123',
            'exp': current_time - 3600,  # Expired 1 hour ago
            'iat': current_time - 7200,
            'scp': REQUIRED_SCOPES
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to raise ExpiredSignatureError
        mocker.patch('api.jwt.decode', side_effect=jwt.ExpiredSignatureError)

        result = validate_token(token, verbose=False)

        assert result is None

    def test_validate_token_invalid_issuer(self, mocker):
        """Token with invalid issuer should be rejected"""
        current_time = int(time.time())
        payload = {
            'iss': 'https://wrong-issuer.com',
            'aud': EXPECTED_AUDIENCE,
            'sub': 'user123',
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': REQUIRED_SCOPES
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to raise InvalidIssuerError
        mocker.patch('api.jwt.decode', side_effect=jwt.InvalidIssuerError)

        result = validate_token(token, verbose=False)

        assert result is None

    def test_validate_token_cannot_decode(self, mocker):
        """Malformed token should be rejected"""
        token = "not.a.valid.jwt.token"

        result = validate_token(token, verbose=False)

        assert result is None

    def test_validate_token_signing_key_failure(self, mocker):
        """Token with invalid signing key should be rejected"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': EXPECTED_AUDIENCE,
            'sub': 'user123',
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': REQUIRED_SCOPES
        }

        token = self.create_test_token(payload)

        # Mock jwt.decode for unverified payload
        mocker.patch('api.jwt.decode', return_value=payload)

        # Mock the JWKS client to fail
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_jwks_client.return_value.get_signing_key_from_jwt.side_effect = Exception("Key not found")

        result = validate_token(token, verbose=False)

        assert result is None

    def test_validate_token_with_extra_scopes(self, mocker):
        """Token with required scopes plus extra scopes should be accepted"""
        current_time = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': EXPECTED_AUDIENCE,
            'sub': 'user123',
            'exp': current_time + 3600,
            'iat': current_time,
            'scp': REQUIRED_SCOPES + ['extra:scope', 'another:scope']
        }

        token = self.create_test_token(payload)

        # Mock the JWKS client
        mock_jwks_client = mocker.patch('api.PyJWKClient')
        mock_signing_key = Mock()
        mock_signing_key.key = Mock()
        mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = mock_signing_key

        # Mock jwt.decode to return payload
        mocker.patch('api.jwt.decode', return_value=payload)

        result = validate_token(token, verbose=False)

        assert result == payload

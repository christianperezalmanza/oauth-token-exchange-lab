"""
Unit tests for DPoP (Demonstrating Proof of Possession) implementation.

Tests the creation and structure of DPoP proof JWTs.
"""

import pytest
import jwt
import json
import time


# Import the functions from client.py
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

from client import create_dpop_proof, get_jwk_thumbprint, dpop_public_key


@pytest.mark.unit
class TestDPoP:
    """Test DPoP proof generation"""

    def test_create_dpop_proof_returns_jwt(self):
        """DPoP proof should be a valid JWT"""
        proof = create_dpop_proof("POST", "https://example.com/token")

        assert proof is not None
        assert isinstance(proof, str)
        assert proof.count('.') == 2  # JWT has 3 parts separated by 2 dots

    def test_dpop_proof_header_structure(self):
        """DPoP proof header should have correct typ and jwk"""
        proof = create_dpop_proof("POST", "https://example.com/token")

        # Decode header without verification
        header = jwt.get_unverified_header(proof)

        assert header['typ'] == 'dpop+jwt'
        assert header['alg'] == 'RS256'
        assert 'jwk' in header
        assert header['jwk']['kty'] == 'RSA'
        assert 'n' in header['jwk']
        assert 'e' in header['jwk']

    def test_dpop_proof_payload_structure(self):
        """DPoP proof payload should have required claims"""
        http_method = "POST"
        url = "https://example.com/token"

        proof = create_dpop_proof(http_method, url)

        # Decode payload without verification
        payload = jwt.decode(proof, options={"verify_signature": False})

        assert 'jti' in payload  # Unique identifier
        assert 'htm' in payload  # HTTP method
        assert 'htu' in payload  # HTTP URI
        assert 'iat' in payload  # Issued at

        assert payload['htm'] == http_method
        assert payload['htu'] == url

    def test_dpop_proof_with_nonce(self):
        """DPoP proof should include nonce when provided"""
        nonce = "test-nonce-12345"
        proof = create_dpop_proof("POST", "https://example.com/token", nonce=nonce)

        payload = jwt.decode(proof, options={"verify_signature": False})

        assert 'nonce' in payload
        assert payload['nonce'] == nonce

    def test_dpop_proof_without_nonce(self):
        """DPoP proof should not include nonce when not provided"""
        proof = create_dpop_proof("POST", "https://example.com/token")

        payload = jwt.decode(proof, options={"verify_signature": False})

        assert 'nonce' not in payload

    def test_dpop_proof_iat_is_current_time(self):
        """DPoP proof iat should be close to current time"""
        before = int(time.time())
        proof = create_dpop_proof("POST", "https://example.com/token")
        after = int(time.time())

        payload = jwt.decode(proof, options={"verify_signature": False})

        assert before <= payload['iat'] <= after

    def test_dpop_proof_jti_is_unique(self):
        """Each DPoP proof should have a unique jti"""
        proof1 = create_dpop_proof("POST", "https://example.com/token")
        proof2 = create_dpop_proof("POST", "https://example.com/token")
        proof3 = create_dpop_proof("POST", "https://example.com/token")

        payload1 = jwt.decode(proof1, options={"verify_signature": False})
        payload2 = jwt.decode(proof2, options={"verify_signature": False})
        payload3 = jwt.decode(proof3, options={"verify_signature": False})

        jtis = [payload1['jti'], payload2['jti'], payload3['jti']]
        assert len(jtis) == len(set(jtis))  # All unique

    def test_dpop_proof_signature_valid(self):
        """DPoP proof signature should be valid"""
        proof = create_dpop_proof("POST", "https://example.com/token")

        # Decode with signature verification using public key
        header = jwt.get_unverified_header(proof)

        # Extract public key from JWT header
        jwk = header['jwk']

        # Verify signature using public key
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        import base64

        def base64url_decode(data):
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data)

        n = int.from_bytes(base64url_decode(jwk['n']), 'big')
        e = int.from_bytes(base64url_decode(jwk['e']), 'big')

        public_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key(default_backend())

        # This will raise an exception if signature is invalid
        payload = jwt.decode(
            proof,
            public_key,
            algorithms=["RS256"],
            options={"verify_signature": True}
        )

        assert payload is not None

    def test_get_jwk_thumbprint_format(self):
        """JWK thumbprint should be valid base64url without padding"""
        thumbprint = get_jwk_thumbprint(dpop_public_key)

        assert thumbprint is not None
        assert isinstance(thumbprint, str)
        assert '=' not in thumbprint  # No padding
        assert len(thumbprint) == 43  # SHA256 thumbprint length

    def test_get_jwk_thumbprint_consistency(self):
        """Same key should always produce same thumbprint"""
        thumbprint1 = get_jwk_thumbprint(dpop_public_key)
        thumbprint2 = get_jwk_thumbprint(dpop_public_key)

        assert thumbprint1 == thumbprint2

    def test_dpop_proof_http_method_variations(self):
        """DPoP proof should work with different HTTP methods"""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

        for method in methods:
            proof = create_dpop_proof(method, "https://example.com/resource")
            payload = jwt.decode(proof, options={"verify_signature": False})

            assert payload['htm'] == method

    def test_dpop_proof_url_variations(self):
        """DPoP proof should work with different URLs"""
        urls = [
            "https://example.com/token",
            "https://api.example.com/v1/resource",
            "http://localhost:8080/callback",
        ]

        for url in urls:
            proof = create_dpop_proof("POST", url)
            payload = jwt.decode(proof, options={"verify_signature": False})

            assert payload['htu'] == url

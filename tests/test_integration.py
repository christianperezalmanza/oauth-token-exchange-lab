"""
Integration tests for OAuth 2.0 Token Exchange flow.

Tests the end-to-end flow with mocked Okta endpoints.
"""

import pytest
import responses
import json
import time


# Import required modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Mock environment variables before importing
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

from client import get_tokens, exchange_token, TOKEN_ENDPOINT


@pytest.mark.integration
class TestOAuthFlow:
    """Test OAuth flow with mocked Okta endpoints"""

    @responses.activate
    def test_get_tokens_success(self):
        """Test successful token exchange with authorization code"""
        # Mock the token endpoint
        mock_response = {
            'access_token': 'mock_access_token_12345',
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': 'openid profile email',
            'id_token': 'mock_id_token_12345'
        }

        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json=mock_response,
            status=200
        )

        # Call the function
        tokens = get_tokens('test_auth_code', 'test_code_verifier')

        # Verify the response
        assert 'access_token' in tokens
        assert tokens['access_token'] == 'mock_access_token_12345'
        assert tokens['token_type'] == 'Bearer'

        # Verify the request was made correctly
        assert len(responses.calls) == 1
        request = responses.calls[0].request

        assert 'grant_type=authorization_code' in request.body
        assert 'code=test_auth_code' in request.body
        assert 'code_verifier=test_code_verifier' in request.body

    @responses.activate
    def test_get_tokens_error_response(self):
        """Test error handling when token endpoint returns error"""
        # Mock error response
        mock_response = {
            'error': 'invalid_grant',
            'error_description': 'Authorization code is invalid or expired'
        }

        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json=mock_response,
            status=400
        )

        # Call the function
        tokens = get_tokens('invalid_code', 'test_code_verifier')

        # Should return error response
        assert 'error' in tokens

    @responses.activate
    def test_get_tokens_network_error(self):
        """Test network error handling for token request"""
        # Mock network error with 500 status
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json={'error': 'server_error'},
            status=500
        )

        # Call the function
        tokens = get_tokens('test_auth_code', 'test_code_verifier')

        # Should return error
        assert 'error' in tokens

    @responses.activate
    def test_exchange_token_success(self):
        """Test successful token exchange"""
        # Mock the token endpoint for exchange
        mock_response = {
            'access_token': 'exchanged_token_12345',
            'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': 'api:access:read api:access:write'
        }

        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json=mock_response,
            status=200
        )

        # Call the function
        new_token = exchange_token('original_access_token')

        # Verify the response
        assert new_token == 'exchanged_token_12345'

        # Verify the request
        assert len(responses.calls) == 1
        request = responses.calls[0].request

        assert 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange' in request.body
        assert 'subject_token=original_access_token' in request.body
        assert 'DPoP' in request.headers

    @responses.activate
    def test_exchange_token_with_dpop_nonce(self):
        """Test token exchange with DPoP nonce challenge"""
        # First request returns nonce error
        error_response = {
            'error': 'use_dpop_nonce',
            'error_description': 'DPoP nonce is required'
        }

        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json=error_response,
            status=400,
            headers={'DPoP-Nonce': 'test-nonce-12345'}
        )

        # Second request succeeds
        success_response = {
            'access_token': 'exchanged_token_with_nonce',
            'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }

        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json=success_response,
            status=200
        )

        # Call the function
        new_token = exchange_token('original_access_token')

        # Verify the response
        assert new_token == 'exchanged_token_with_nonce'

        # Verify two requests were made
        assert len(responses.calls) == 2

        # First request should not have nonce
        first_request = responses.calls[0].request
        assert 'DPoP' in first_request.headers

        # Second request should have nonce in DPoP proof
        second_request = responses.calls[1].request
        assert 'DPoP' in second_request.headers

    @responses.activate
    def test_exchange_token_failure(self):
        """Test token exchange failure"""
        # Mock error response
        error_response = {
            'error': 'invalid_request',
            'error_description': 'Invalid subject token'
        }

        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json=error_response,
            status=400
        )

        # Call the function
        new_token = exchange_token('invalid_token')

        # Should return None on failure
        assert new_token is None

        # Verify the request was made
        assert len(responses.calls) == 1


@pytest.mark.integration
class TestAPIEndpoints:
    """Test API endpoints with Flask test client"""

    @pytest.fixture
    def client(self):
        """Create Flask test client"""
        from api import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get('/health')

        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'

    def test_protected_endpoint_no_auth(self, client):
        """Test protected endpoint without Authorization header"""
        response = client.get('/protected')

        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data

    def test_protected_endpoint_invalid_auth_header(self, client):
        """Test protected endpoint with invalid Authorization header"""
        response = client.get('/protected', headers={'Authorization': 'Invalid header'})

        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data

    def test_protected_endpoint_invalid_token(self, client, mocker):
        """Test protected endpoint with invalid token"""
        # Mock validate_token to return None
        mocker.patch('api.validate_token', return_value=None)

        response = client.get('/protected', headers={'Authorization': 'Bearer invalid_token'})

        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data

    def test_protected_endpoint_valid_token(self, client, mocker):
        """Test protected endpoint with valid token"""
        # Mock validate_token to return a valid payload
        mock_payload = {
            'sub': 'user123',
            'email': 'user@test.com',
            'name': 'Test User',
            'scp': ['api:access:read', 'api:access:write']
        }

        mocker.patch('api.validate_token', return_value=mock_payload)

        response = client.get('/protected', headers={'Authorization': 'Bearer valid_token'})

        assert response.status_code == 200
        data = response.get_json()

        assert data['authenticated'] is True
        assert data['message'] == 'Access granted to API!'
        assert data['user']['user_id'] == 'user123'
        assert data['user']['email'] == 'user@test.com'
        assert data['user']['name'] == 'Test User'


@pytest.mark.integration
class TestEndToEndFlow:
    """Test end-to-end flow scenarios"""

    @responses.activate
    def test_full_oauth_flow_success(self, mocker):
        """Test complete OAuth flow from code to API access"""
        # Step 1: Mock token exchange for authorization code
        token_response = {
            'access_token': 'user_access_token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }

        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json=token_response,
            status=200
        )

        # Step 2: Mock token exchange
        exchange_response = {
            'access_token': 'resource_scoped_token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }

        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json=exchange_response,
            status=200
        )

        # Execute flow
        tokens = get_tokens('auth_code', 'code_verifier')
        assert 'access_token' in tokens

        new_token = exchange_token(tokens['access_token'])
        assert new_token == 'resource_scoped_token'

        # Verify requests were made in order
        assert len(responses.calls) == 2

    def test_token_lifecycle(self):
        """Test token timing and lifecycle"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        # Create a test token
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        current_time = int(time.time())
        payload = {
            'iss': 'https://test.okta.com/oauth2/default',
            'aud': 'test.com',
            'sub': 'user123',
            'iat': current_time,
            'exp': current_time + 3600,
            'scp': ['api:access:read', 'api:access:write']
        }

        import jwt
        token = jwt.encode(payload, private_key, algorithm="RS256")

        # Verify token structure
        decoded = jwt.decode(token, options={"verify_signature": False})

        assert decoded['iat'] == current_time
        assert decoded['exp'] == current_time + 3600
        assert decoded['exp'] - decoded['iat'] == 3600  # 1 hour lifetime

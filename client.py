import requests
from flask import Flask, request
from urllib.parse import urlencode
import hashlib
import base64
import secrets
import jwt
import time
import os
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def validate_config():
    """Validate that all required environment variables are set"""
    required_vars = [
        'OKTA_DOMAIN',
        'CLIENT_ID',
        'CLIENT_SECRET',
        'SERVICE_CLIENT_ID',
        'SERVICE_CLIENT_SECRET',
        'RESOURCE_SERVER_ID',
        'AUDIENCE',
        'REDIRECT_URI',
        'RESOURCE_SERVER_URI'
    ]
    missing = [var for var in required_vars if not os.getenv(var)]

    if missing:
        print("\n" + "="*70)
        print(" ERROR: Missing Required Environment Variables")
        print("="*70)
        print(f"\n  Missing: {', '.join(missing)}")
        print("\n  Please create a .env file based on .env.example")
        print("  and configure the required variables.")
        print("\n" + "="*70 + "\n")
        exit(1)

# Validate configuration on startup
validate_config()

OKTA_DOMAIN = os.getenv('OKTA_DOMAIN')

# Native app configuration (handles user authentication)
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI')

# Service app configuration (performs token exchange - API Services type in Okta)
# This app exchanges user tokens for resource-scoped tokens
SERVICE_CLIENT_ID = os.getenv('SERVICE_CLIENT_ID')
SERVICE_CLIENT_SECRET = os.getenv('SERVICE_CLIENT_SECRET')

# Resource server configuration (target API for token exchange)
RESOURCE_SERVER_URI = os.getenv('RESOURCE_SERVER_URI')
RESOURCE_SERVER_ID = os.getenv('RESOURCE_SERVER_ID')

# Okta endpoints
AUTHORIZATION_ENDPOINT = f'{OKTA_DOMAIN}/oauth2/default/v1/authorize'
TOKEN_ENDPOINT = f'{OKTA_DOMAIN}/oauth2/default/v1/token'

# Authorization Server Audience (required for token exchange)
AUDIENCE = os.getenv('AUDIENCE')

# HTTP request timeout in seconds
REQUEST_TIMEOUT = 30

app = Flask(__name__)

# Thread-safe auth flow state
class AuthState:
    def __init__(self):
        self.authorization_code = None
        self.state = None
        self.code_verifier = None
        self.code_challenge = None
        self.event = threading.Event()
    
    def set_code(self, code):
        self.authorization_code = code
        self.event.set()
    
    def wait_for_code(self, timeout=300):
        return self.event.wait(timeout)

auth_state = AuthState()

# Generate PKCE code verifier and challenge
def generate_pkce_pair():
    # Generate a random code verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Create code challenge by hashing the verifier with SHA256
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    
    return code_verifier, code_challenge

# Generate DPoP key pair (reused for session)
dpop_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
dpop_public_key = dpop_private_key.public_key()

# Get JWK thumbprint for the public key
def get_jwk_thumbprint(public_key):
    public_numbers = public_key.public_numbers()
    
    # Convert to base64url without padding
    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    
    n = b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big'))
    e = b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big'))
    
    jwk = {
        "e": e,
        "kty": "RSA",
        "n": n
    }
    
    # Create thumbprint
    import json
    jwk_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = hashlib.sha256(jwk_json.encode()).digest()
    return base64.urlsafe_b64encode(thumbprint).rstrip(b'=').decode('utf-8')

def create_dpop_proof(http_method, url, nonce=None):
    """Create a DPoP proof JWT"""
    public_numbers = dpop_public_key.public_numbers()
    
    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    
    # JWK representation of public key
    jwk = {
        "kty": "RSA",
        "e": b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')),
        "n": b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big'))
    }
    
    # DPoP proof claims
    payload = {
        "jti": secrets.token_urlsafe(16),
        "htm": http_method,
        "htu": url,
        "iat": int(time.time())
    }
    
    # Add nonce if provided
    if nonce:
        payload["nonce"] = nonce
    
    # Sign with private key
    dpop_proof = jwt.encode(
        payload,
        dpop_private_key,
        algorithm="RS256",
        headers={"typ": "dpop+jwt", "jwk": jwk}
    )
    
    return dpop_proof

@app.route('/callback')
def callback():
    """Handle OAuth callback with state validation for CSRF protection"""
    # Validate state parameter to prevent CSRF attacks
    received_state = request.args.get('state')
    if not received_state or received_state != auth_state.state:
        return 'Error: Invalid state parameter. Possible CSRF attack.', 400
    
    code = request.args.get('code')
    if not code:
        error = request.args.get('error', 'unknown_error')
        error_desc = request.args.get('error_description', 'No description provided')
        return f'Error: {error} - {error_desc}', 400
    
    auth_state.set_code(code)
    return 'Authorization code received! You can close this window.'

def get_tokens(code, code_verifier):
    """Exchange authorization code for tokens"""
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': code_verifier
    }
    try:
        response = requests.post(TOKEN_ENDPOINT, data=data, timeout=REQUEST_TIMEOUT, verify=True)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        return {'error': 'request_timeout', 'error_description': 'Token request timed out'}
    except requests.exceptions.RequestException as e:
        return {'error': 'request_failed', 'error_description': str(e)}
    except ValueError:
        return {'error': 'invalid_response', 'error_description': 'Invalid JSON response'}

def exchange_token(access_token):
    """
    Exchange the user's access token for a new token scoped to the resource server.
    Uses OAuth 2.0 Token Exchange (RFC 8693).
    The service app credentials are used to authenticate the exchange request.
    """
    # Use service app credentials (API Services app with Token Exchange grant)
    credentials = f"{SERVICE_CLIENT_ID}:{SERVICE_CLIENT_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    data = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token': access_token,
        'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        'audience': AUDIENCE,
        'resource': RESOURCE_SERVER_ID,
        'scope': 'api:access:read api:access:write',  # Custom scopes for the API
    }

    # First attempt - get nonce from error response
    dpop_proof = create_dpop_proof("POST", TOKEN_ENDPOINT)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Authorization': f'Basic {encoded_credentials}',
        'DPoP': dpop_proof
    }
    
    print(f"\nToken Exchange Request:")
    print(f"   Endpoint: {TOKEN_ENDPOINT}")
    print(f"   Service Client ID: {SERVICE_CLIENT_ID}")
    print(f"   Audience: {AUDIENCE}")
    print(f"   Target Resource Server ID: {RESOURCE_SERVER_ID}")
    print(f"   Grant Type: token-exchange")

    try:
        response = requests.post(TOKEN_ENDPOINT, data=data, headers=headers, timeout=REQUEST_TIMEOUT, verify=True)
    except requests.exceptions.RequestException as e:
        print(f"\nToken exchange request failed: {e}")
        return None
    
    # If nonce required, retry with nonce
    if response.status_code == 400:
        try:
            error_data = response.json()
            if error_data.get('error') == 'use_dpop_nonce':
                nonce = response.headers.get('DPoP-Nonce')
                if nonce:
                    print(f"   Retrying with DPoP nonce: {nonce}")
                    dpop_proof = create_dpop_proof("POST", TOKEN_ENDPOINT, nonce)
                    headers['DPoP'] = dpop_proof
                    try:
                        response = requests.post(TOKEN_ENDPOINT, data=data, headers=headers, timeout=REQUEST_TIMEOUT, verify=True)
                    except requests.exceptions.RequestException as e:
                        print(f"\nRetry request failed: {e}")
                        return None
        except (ValueError, KeyError) as e:
            print(f"\nFailed to parse error response: {e}")
    
    if response.status_code != 200:
        print(f"\nToken exchange failed: {response.status_code}")
        print(f"Response: {response.text}")
        
        try:
            error_details = response.json()
            print(f"\nError: {error_details.get('error')}")
            print(f"Description: {error_details.get('error_description')}")
        except (ValueError, KeyError):
            print(f"\nCould not parse error response")
            
        return None

    result = response.json()
    new_token = result.get('access_token')
    print(f"Token exchange successful")
    print(f"New token: {new_token[:20]}..." if new_token else "No token received")
 
    return new_token

if __name__ == '__main__':
    # NOTE: For production, use a proper WSGI server like gunicorn or uwsgi
    # Example: gunicorn -w 4 -b 0.0.0.0:8080 client:app
    
    # Generate fresh PKCE pair for this authorization flow
    code_verifier, code_challenge = generate_pkce_pair()
    auth_state.code_verifier = code_verifier
    auth_state.code_challenge = code_challenge
    
    # Generate random state for CSRF protection
    auth_state.state = secrets.token_urlsafe(32)
    
    # Start Flask server in a separate thread (development only)
    threading.Thread(target=lambda: app.run(port=8080, debug=False), daemon=True).start()
    
    # Give Flask time to start
    time.sleep(1)

    # Open browser for user authentication
    auth_params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid profile email',
        'redirect_uri': REDIRECT_URI,
        'state': auth_state.state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    auth_url = f"{AUTHORIZATION_ENDPOINT}?{urlencode(auth_params)}"
    
    print(f"Open this url {auth_url} in your browser for authentication...")

    # Wait for the authorization code with timeout
    if not auth_state.wait_for_code(timeout=300):
        print("\nTimeout waiting for authorization code")
        exit(1)

    # Exchange code for tokens
    tokens = get_tokens(auth_state.authorization_code, code_verifier)
    
    if 'error' in tokens:
        print(f"Error getting tokens: {tokens}")
        exit(1)

    access_token = tokens['access_token']
    print(f"\nUser authenticated successfully")
    print(f"Initial access token: {access_token[:30]}...")

    # Perform token exchange to get a token for the resource server
    print(f"\nExchanging token for resource server access...")
    new_token = exchange_token(access_token)
    
    if not new_token:
        print("Token exchange failed. Check Okta configuration.")
        exit(1)

    time.sleep(3)

    # Use the exchanged token to call the protected API
    print(f"\nCalling protected API with exchanged token...")
    try:
        api_response = requests.get(
            RESOURCE_SERVER_URI, 
            headers={'Authorization': f'Bearer {new_token}'},
            timeout=REQUEST_TIMEOUT,
            verify=True
        )
        api_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"\nAPI request failed: {e}")
        exit(1)
    
    print(f'\nAPI Response ({api_response.status_code}):')
    print(api_response.json() if api_response.headers.get('content-type', '').startswith('application/json') else api_response.text)
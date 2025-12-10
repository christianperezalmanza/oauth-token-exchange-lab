"""
OAuth 2.0 Token Exchange Demo - Protected API
=============================================

This API validates JWT tokens from Okta and enforces:
1. Valid signature (signed by trusted Okta authorization server)
2. Not expired
3. Correct issuer and audience
4. User context (has 'sub' claim)
5. Required scopes

The verbose validation helps debug token issues by checking each
validation step separately and providing detailed error messages.
"""

from flask import Flask, request, jsonify
import jwt
from jwt.jwks_client import PyJWKClient
import time
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# =============================================================================
# Configuration
# =============================================================================

def validate_config():
    """Validate that all required environment variables are set"""
    required_vars = ['OKTA_DOMAIN', 'AUDIENCE']
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
JWKS_URL = f'{OKTA_DOMAIN}/oauth2/default/v1/keys'
ISSUER = f'{OKTA_DOMAIN}/oauth2/default'

# Expected audience (from authorization server configuration)
EXPECTED_AUDIENCE = os.getenv('AUDIENCE')

# Required scopes for access
REQUIRED_SCOPES = ['api:access:read', 'api:access:write']

# Enable verbose logging for debugging
VERBOSE_VALIDATION = True

app = Flask(__name__)

# =============================================================================
# Token Validation
# =============================================================================

def validate_token(token, verbose=VERBOSE_VALIDATION):
    """
    Validate JWT token step-by-step with detailed logging.
    
    Returns token payload if valid, None otherwise.
    """
    if verbose:
        print("\n" + "="*70)
        print(" TOKEN VALIDATION")
        print("="*70)
    
    # Step 1: Inspect claims (unverified)
    try:
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        
        if verbose:
            print("\n Token Claims:")
            print(json.dumps(unverified_payload, indent=2))
        
        # Check timing
        current_time = int(time.time())
        iat = unverified_payload.get('iat')
        exp = unverified_payload.get('exp')
        
        if verbose:
            print(f"\n Timing Check:")
            print(f"   Current: {current_time} ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(current_time))})")
            if iat:
                print(f"   Issued:  {iat} ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(iat))})")
                if current_time < iat:
                    print(f"   WARNING:  Token issued {iat - current_time}s in future (clock skew)")
            if exp:
                print(f"   Expires: {exp} ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(exp))})")
                print(f"   TTL: {exp - current_time}s")
                
    except Exception as e:
        if verbose:
            print(f"FAIL: Failed to decode token: {e}")
        return None
    
    # Step 2: Verify signature
    if verbose:
        print(f"\n Signature Verification:")
    
    jwks_client = PyJWKClient(JWKS_URL)
    
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        if verbose:
            print(f"   PASS: Retrieved signing key")
    except Exception as e:
        if verbose:
            print(f"   FAIL: Failed to get signing key: {e}")
        return None
    
    # Step 3: Full validation
    if verbose:
        print(f"\n JWT Validation:")
    
    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            leeway=10,  # Allow 10 seconds clock skew tolerance
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": False  # Manual check below
            }
        )
        if verbose:
            print(f"   PASS: Signature valid")
            print(f"   PASS: Not expired")
            print(f"   PASS: Issuer: {ISSUER}")
        
    except jwt.ExpiredSignatureError:
        if verbose:
            print(f"   FAIL: Token expired")
        return None
    except jwt.ImmatureSignatureError:
        if verbose:
            print(f"   FAIL: Token not yet valid (clock skew)")
        return None
    except jwt.InvalidIssuerError:
        if verbose:
            print(f"   FAIL: Issuer mismatch")
        return None
    except jwt.InvalidTokenError as e:
        if verbose:
            print(f"   FAIL: Invalid token: {e}")
        return None
    
    # Step 4: User context
    if verbose:
        print(f"\n User Context:")
    
    if 'sub' not in payload:
        if verbose:
            print(f"   FAIL: Missing 'sub' claim")
        return None
    
    if verbose:
        print(f"   PASS: User: {payload.get('sub')}")
        if payload.get('email'):
            print(f"   PASS: Email: {payload.get('email')}")
    
    # Step 5: Audience
    if verbose:
        print(f"\n Audience Check:")
    
    audience = payload.get('aud')
    
    if audience != EXPECTED_AUDIENCE:
        if verbose:
            print(f"   FAIL: Expected: {EXPECTED_AUDIENCE}")
            print(f"   FAIL: Got: {audience}")
        return None
    
    if verbose:
        print(f"   PASS: Audience: {audience}")
    
    # Step 6: Scopes
    if verbose:
        print(f"\n Scope Check:")
    
    token_scopes = payload.get('scp', [])
    if isinstance(token_scopes, str):
        token_scopes = token_scopes.split(' ')
    
    matching_scopes = [s for s in REQUIRED_SCOPES if s in token_scopes]
    
    if not all(scope in token_scopes for scope in REQUIRED_SCOPES):
        if verbose:
            print(f"   FAIL: Required: {REQUIRED_SCOPES}")
            print(f"   FAIL: Got: {token_scopes}")
        return None
    
    if verbose:
        print(f"   PASS: Scopes: {token_scopes}")
        print("\n" + "="*70)
        print("PASS: VALIDATION SUCCESSFUL")
        print("="*70 + "\n")
    
    return payload

# =============================================================================
# API Endpoints
# =============================================================================

@app.route('/protected')
def protected():
    """Protected endpoint that requires a valid JWT token"""
    
    # Extract token from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401
    
    token = auth_header.split(' ')[1]
    
    # Validate token
    payload = validate_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid or unauthorized token'}), 401
    
    # Return user info
    return jsonify({
        'message': 'Access granted to API!',
        'authenticated': True,
        'user': {
            'user_id': payload.get('sub'),
            'email': payload.get('email'),
            'name': payload.get('name'),
            'scopes': payload.get('scp', [])
        }
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

# =============================================================================
# Main Execution
# =============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print(" API Server Starting")
    print("="*70)
    print(f"\n   JWKS URL: {JWKS_URL}")
    print(f"   Issuer: {ISSUER}")
    print(f"   Expected Audience: {EXPECTED_AUDIENCE}")
    print(f"   Required Scopes: {REQUIRED_SCOPES}")
    print(f"\n   Endpoints:")
    print(f"   - GET /protected (requires valid JWT)")
    print(f"   - GET /health")
    print("\n" + "="*70 + "\n")
    
    app.run(host='0.0.0.0', port=5000)

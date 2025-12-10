# OAuth 2.0 Token Exchange Lab

A hands-on demonstration of OAuth 2.0 Token Exchange (RFC 8693) using Okta as the identity provider. This lab shows how to exchange a user's access token for a resource-scoped token with enhanced security using PKCE and DPoP.

## What This Lab Demonstrates

1. **OAuth 2.0 Authorization Code Flow** with PKCE (Proof Key for Code Exchange)
2. **Token Exchange (RFC 8693)** - exchanging user tokens for resource-scoped tokens
3. **DPoP (Demonstrating Proof of Possession)** - enhanced token security
4. **JWT Token Validation** - comprehensive step-by-step validation
5. **Scope-based Authorization** - fine-grained access control

## Architecture Overview

```
┌─────────────┐                                      ┌─────────────┐
│             │   1. Authorization Request           │             │
│             │   (with PKCE challenge)              │             │
│   Browser   │─────────────────────────────────────>│    Okta     │
│             │                                      │             │
│             │<─────────────────────────────────────│             │
└──────┬──────┘   2. User authenticates              └──────┬──────┘
       │                                                    │
       │                                                    │
       │ 3. Auth code                                       │
       │                                                    │
       v                                                    │
┌─────────────┐                                             │
│             │   4. Exchange code for token                │
│             │   (with PKCE verifier)                      │
│             │────────────────────────────────────────────>│
│             │                                             │
│             │<────────────────────────────────────────────│
│   Client    │   5. User access token                      │
│   (Flask)   │                                             │
│             │   6. Token Exchange Request                 │
│             │   (with DPoP proof)                         │
│             │────────────────────────────────────────────>│
│             │                                             │
│             │<────────────────────────────────────────────│
│             │   7. Resource-scoped token                  │
└──────┬──────┘                                             │
       │                                                    │
       │ 8. API Request                                     │
       │ (with exchanged token)                             │
       v                                                    │
┌─────────────┐                                             │
│             │   9. Validate token signature               │
│             │────────────────────────────────────────────>│
│  Protected  │   (fetch JWKS)                              │
│     API     │                                             │
│             │<────────────────────────────────────────────┘
└─────────────┘   10. Public keys
```

## Prerequisites

- Python 3.8 or higher
- An Okta Developer account (free at https://developer.okta.com/)
- Make (optional, for convenience commands)

## Setup Instructions

### 1. Clone and Install Dependencies

```bash
# Install dependencies
make install

# Or manually:
pip install -r requirements.txt
```

### 2. Configure Okta

You need to create two applications in Okta:

#### A. Native Application (for user authentication)

1. Log into your Okta Admin Console
2. Go to **Applications** → **Applications** → **Create App Integration**
3. Select **OIDC - OpenID Connect**
4. Select **Native Application**
5. Configure:
   - **App integration name**: OAuth Client Demo
   - **Grant types**: Authorization Code, Refresh Token
   - **Sign-in redirect URIs**: `http://client.local.com:8080/callback`
   - **Assignments**: Assign to yourself or test users
6. Save and note the **Client ID** and **Client Secret**

#### B. API Services Application (for token exchange)

1. Go to **Applications** → **Applications** → **Create App Integration**
2. Select **API Services**
3. Configure:
   - **App integration name**: Token Exchange Service
   - **Grant types**: Enable "Token Exchange"
4. Save and note the **Client ID** and **Client Secret**

#### C. Authorization Server Configuration

1. Go to **Security** → **API** → **Authorization Servers**
2. Select **default** or create a new one
3. Go to the **Scopes** tab and add:
   - `api:access:read` - Read access to API
   - `api:access:write` - Write access to API
4. Go to the **Access Policies** tab
5. Create a new policy or edit existing:
   - Add a rule that allows Token Exchange grant type
   - Assign to your API Services application

#### D. Resource Server

1. Go to **Applications** → **Applications**
2. Find or create your API resource
3. Note the **Resource ID** (looks like `0oaXXXXXXXXXXXXXX`)

### 3. Configure Environment Variables

```bash
# Create .env file from template
make setup

# Or manually:
cp .env.example .env
```

Edit `.env` with your Okta configuration:

```bash
# Your Okta domain
OKTA_DOMAIN=https://your-domain.okta.com

# Native app credentials
CLIENT_ID=0oaXXXXXXXXXXXXXX
CLIENT_SECRET=your_client_secret

# Service app credentials
SERVICE_CLIENT_ID=0oaXXXXXXXXXXXXXX
SERVICE_CLIENT_SECRET=your_service_secret

# Resource server
RESOURCE_SERVER_ID=0oaXXXXXXXXXXXXXX

# Audience (from authorization server)
AUDIENCE=example.com

# URIs (usually don't need to change these)
REDIRECT_URI=http://client.local.com:8080/callback
RESOURCE_SERVER_URI=http://api.local.com:5000/protected
```

### 4. Configure Local DNS

Add these entries to your `/etc/hosts` file:

```bash
127.0.0.1 client.local.com
127.0.0.1 api.local.com
```

On Linux/Mac:
```bash
sudo nano /etc/hosts
```

On Windows (as Administrator):
```bash
notepad C:\Windows\System32\drivers\etc\hosts
```

## Running the Lab

### Option 1: Using Make (Recommended)

```bash
# Terminal 1: Start the API server
make run-api

# Terminal 2: Start the client
make run-client
```

### Option 2: Direct Python

```bash
# Terminal 1: Start the API server
python api.py

# Terminal 2: Start the client
python client.py
```

### What Happens

1. The client will print an authorization URL
2. Open that URL in your browser
3. Log in with your Okta credentials
4. You'll be redirected back to the client
5. The client will:
   - Exchange the authorization code for an access token
   - Exchange the access token for a resource-scoped token
   - Call the protected API with the new token
6. The API will validate the token and return user information

## Testing

This lab includes comprehensive tests to validate the OAuth flow and security implementations.

### Run All Tests

```bash
make test
```

### Run Specific Test Suites

```bash
# Unit tests only (PKCE, DPoP, token validation)
make test-unit

# Integration tests only (mocked OAuth flows)
make test-integration
```

### Test Coverage Report

```bash
# Generate coverage report
make test-cov

# Open HTML report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### What's Tested

**Unit Tests** (`tests/test_*.py`):
- **PKCE Generation** (`test_pkce.py`)
  - Code verifier/challenge format
  - SHA256 hashing correctness
  - Randomness and uniqueness
  - RFC 7636 compliance

- **DPoP Proof Creation** (`test_dpop.py`)
  - JWT structure and headers
  - Required claims (jti, htm, htu, iat)
  - Nonce handling
  - Signature validation
  - JWK thumbprint generation

- **Token Validation** (`test_token_validation.py`)
  - Signature verification
  - Expiration checks
  - Issuer validation
  - Audience verification
  - Scope enforcement
  - User context validation

**Integration Tests** (`tests/test_integration.py`):
- Authorization code exchange flow
- Token exchange with DPoP
- DPoP nonce challenge handling
- API endpoint protection
- End-to-end OAuth flow
- Error handling scenarios

### Test Requirements

Tests use mocked Okta endpoints, so they run without actual Okta credentials:
- `pytest` - Test framework
- `pytest-mock` - Mocking utilities
- `pytest-cov` - Coverage reporting
- `responses` - HTTP request mocking

All dependencies are in `requirements.txt`.

## Utilities

### Test API Health

```bash
make test-health
```

### Decode and Inspect JWT Tokens

```bash
# Show payload
make decode-token TOKEN=eyJhbGc...

# Or use directly
python decode_token.py eyJhbGc...

# Show header
python decode_token.py eyJhbGc... --header

# Show everything
python decode_token.py eyJhbGc... --all
```

### Clean Up

```bash
make clean
```

## Key Security Features

### PKCE (Proof Key for Code Exchange)
- Protects against authorization code interception
- Uses SHA-256 code challenge/verifier pair
- Required for public clients

### Token Exchange (RFC 8693)
- Exchanges user tokens for resource-scoped tokens
- Reduces token privileges to minimum required
- Improves security by limiting token scope

### DPoP (Demonstrating Proof of Possession)
- Binds tokens to specific clients
- Uses public/private key cryptography
- Prevents token theft and replay attacks

### JWT Validation
The API validates:
1. Token signature (using Okta's public keys)
2. Token expiration
3. Issuer verification
4. Audience verification
5. User context (sub claim)
6. Required scopes

## Troubleshooting

### "Missing Required Environment Variables"
- Make sure you created the `.env` file: `make setup`
- Verify all values are set correctly

### "Connection refused" or DNS errors
- Check `/etc/hosts` entries for client.local.com and api.local.com
- Make sure the API is running before starting the client

### "Token exchange failed"
- Verify the service app has Token Exchange grant enabled
- Check that the authorization server policy allows token exchange
- Ensure scopes are defined in the authorization server

### "Invalid token" from API
- Use `make decode-token TOKEN=<token>` to inspect the token
- Check that AUDIENCE matches in both client and API
- Verify token hasn't expired

## Project Structure

```
.
├── api.py              # Protected API with JWT validation
├── client.py           # OAuth client with token exchange
├── decode_token.py     # JWT inspection utility
├── requirements.txt    # Python dependencies
├── pytest.ini          # Pytest configuration
├── .env.example        # Environment variable template
├── .env                # Your configuration (not in git)
├── .gitignore          # Git ignore patterns
├── Makefile            # Convenience commands
├── README.md           # This file
└── tests/              # Test suite
    ├── __init__.py
    ├── test_pkce.py              # PKCE logic tests
    ├── test_dpop.py              # DPoP proof tests
    ├── test_token_validation.py  # Token validation tests
    └── test_integration.py       # End-to-end flow tests
```

## Learning Resources

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [Token Exchange RFC 8693](https://tools.ietf.org/html/rfc8693)
- [DPoP RFC 9449](https://tools.ietf.org/html/rfc9449)
- [Okta Developer Documentation](https://developer.okta.com/docs/)

## License

This is a demonstration project for educational purposes.

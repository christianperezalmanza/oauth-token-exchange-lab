#!/usr/bin/env python3
"""
JWT Token Inspector
===================

This utility decodes and inspects JWT tokens WITHOUT validating the signature.
Useful for debugging token issues and understanding token structure.

Usage:
    python decode_token.py <token>
    python decode_token.py <token> --header
    python decode_token.py <token> --all

Examples:
    python decode_token.py eyJhbGc...
    python decode_token.py eyJhbGc... --header
    python decode_token.py eyJhbGc... --all
"""

import jwt
import sys
import json
import time
from datetime import datetime


def format_timestamp(ts):
    """Format Unix timestamp to human-readable date"""
    if ts:
        return f"{ts} ({datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')})"
    return "N/A"


def decode_token(token, show_header=False, show_all=False):
    """
    Decode JWT token without signature verification.

    Args:
        token: JWT token string
        show_header: Show JWT header
        show_all: Show both header and payload
    """
    try:
        # Decode header
        header = jwt.get_unverified_header(token)

        # Decode payload (without verification)
        payload = jwt.decode(token, options={"verify_signature": False})

        print("\n" + "="*70)
        print(" JWT TOKEN INSPECTOR")
        print("="*70)

        if show_header or show_all:
            print("\n HEADER:")
            print("-"*70)
            print(json.dumps(header, indent=2))

        if not show_header or show_all:
            print("\n PAYLOAD:")
            print("-"*70)
            print(json.dumps(payload, indent=2))

            # Show timing information
            current_time = int(time.time())
            iat = payload.get('iat')
            exp = payload.get('exp')

            print("\n TIMING INFORMATION:")
            print("-"*70)
            print(f"   Current time: {format_timestamp(current_time)}")

            if iat:
                print(f"   Issued at:    {format_timestamp(iat)}")
                age = current_time - iat
                print(f"   Token age:    {age}s ({age // 60} minutes)")

            if exp:
                print(f"   Expires at:   {format_timestamp(exp)}")
                ttl = exp - current_time
                if ttl > 0:
                    print(f"   Time to live: {ttl}s ({ttl // 60} minutes)")
                else:
                    print(f"   EXPIRED:      {abs(ttl)}s ago ({abs(ttl) // 60} minutes ago)")

            # Show key claims
            print("\n KEY CLAIMS:")
            print("-"*70)
            print(f"   Issuer (iss):   {payload.get('iss', 'N/A')}")
            print(f"   Subject (sub):  {payload.get('sub', 'N/A')}")
            print(f"   Audience (aud): {payload.get('aud', 'N/A')}")

            scopes = payload.get('scp', payload.get('scope', 'N/A'))
            if isinstance(scopes, list):
                scopes = ' '.join(scopes)
            print(f"   Scopes:         {scopes}")

            if payload.get('email'):
                print(f"   Email:          {payload.get('email')}")
            if payload.get('name'):
                print(f"   Name:           {payload.get('name')}")

        print("\n" + "="*70 + "\n")

    except jwt.DecodeError as e:
        print(f"\nERROR: Failed to decode token: {e}")
        print("Make sure you're providing a valid JWT token.\n")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Unexpected error: {e}\n")
        sys.exit(1)


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nERROR: No token provided")
        print("\nUsage: python decode_token.py <token>")
        print("       python decode_token.py <token> --header")
        print("       python decode_token.py <token> --all")
        sys.exit(1)

    token = sys.argv[1]
    show_header = '--header' in sys.argv
    show_all = '--all' in sys.argv

    decode_token(token, show_header=show_header, show_all=show_all)


if __name__ == '__main__':
    main()

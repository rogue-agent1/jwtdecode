#!/usr/bin/env python3
"""jwtdecode - Decode and inspect JWT tokens without verification.

Parse JWT tokens, display claims, check expiration, and analyze structure.

Usage:
    jwtdecode <token>
    jwtdecode <token> --check          # check if expired
    jwtdecode <token> --json           # raw JSON output
    echo <token> | jwtdecode -         # read from stdin
"""
import argparse
import base64
import json
import sys
from datetime import datetime, timezone


def b64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> dict:
    """Decode a JWT token into its parts."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")

    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception as e:
        raise ValueError(f"Invalid header: {e}")

    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        raise ValueError(f"Invalid payload: {e}")

    return {"header": header, "payload": payload, "signature": parts[2]}


KNOWN_CLAIMS = {
    "iss": "Issuer",
    "sub": "Subject",
    "aud": "Audience",
    "exp": "Expires",
    "nbf": "Not Before",
    "iat": "Issued At",
    "jti": "JWT ID",
    "name": "Name",
    "email": "Email",
    "role": "Role",
    "roles": "Roles",
    "scope": "Scope",
    "azp": "Authorized Party",
    "nonce": "Nonce",
    "at_hash": "Access Token Hash",
    "c_hash": "Code Hash",
    "auth_time": "Auth Time",
    "sid": "Session ID",
    "org_id": "Organization ID",
    "tenant": "Tenant",
}

KNOWN_ALGS = {
    "HS256": "HMAC-SHA256 (symmetric)",
    "HS384": "HMAC-SHA384 (symmetric)",
    "HS512": "HMAC-SHA512 (symmetric)",
    "RS256": "RSA-SHA256 (asymmetric)",
    "RS384": "RSA-SHA384 (asymmetric)",
    "RS512": "RSA-SHA512 (asymmetric)",
    "ES256": "ECDSA-SHA256 (asymmetric)",
    "ES384": "ECDSA-SHA384 (asymmetric)",
    "ES512": "ECDSA-SHA512 (asymmetric)",
    "PS256": "RSA-PSS-SHA256 (asymmetric)",
    "EdDSA": "Edwards-curve DSA (asymmetric)",
    "none": "⚠️  UNSIGNED (dangerous!)",
}


def format_timestamp(ts):
    """Format a Unix timestamp."""
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        diff = dt - now
        if diff.total_seconds() > 0:
            rel = f"in {_human_delta(diff.total_seconds())}"
        else:
            rel = f"{_human_delta(-diff.total_seconds())} ago"
        return f"{dt.strftime('%Y-%m-%d %H:%M:%S UTC')} ({rel})"
    except (OSError, ValueError):
        return str(ts)


def _human_delta(secs):
    if secs < 60:
        return f"{secs:.0f}s"
    if secs < 3600:
        return f"{secs/60:.0f}m"
    if secs < 86400:
        return f"{secs/3600:.1f}h"
    return f"{secs/86400:.1f}d"


def display(token_str: str, check_only=False, as_json=False):
    """Display decoded JWT."""
    try:
        jwt = decode_jwt(token_str)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    header = jwt["header"]
    payload = jwt["payload"]

    if as_json:
        print(json.dumps({"header": header, "payload": payload}, indent=2))
        return

    # Header
    alg = header.get("alg", "unknown")
    alg_desc = KNOWN_ALGS.get(alg, alg)
    print(f"  ═══ Header ═══")
    print(f"  Algorithm: {alg} — {alg_desc}")
    if alg == "none":
        print(f"  ⚠️  WARNING: Token is unsigned!")
    for k, v in header.items():
        if k != "alg":
            print(f"  {k}: {v}")
    print()

    # Payload
    print(f"  ═══ Payload ({len(payload)} claims) ═══")
    time_claims = {"exp", "iat", "nbf", "auth_time"}
    for k, v in payload.items():
        label = KNOWN_CLAIMS.get(k, k)
        if k in time_claims and isinstance(v, (int, float)):
            print(f"  {label} ({k}): {format_timestamp(v)}")
        else:
            val_str = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
            print(f"  {label} ({k}): {val_str}")
    print()

    # Expiration check
    exp = payload.get("exp")
    if exp:
        now = datetime.now(tz=timezone.utc).timestamp()
        if exp < now:
            print(f"  🔴 EXPIRED ({_human_delta(now - exp)} ago)")
        else:
            print(f"  🟢 Valid (expires {_human_delta(exp - now)} from now)")
    else:
        print(f"  ⚠️  No expiration claim")

    # Signature
    sig_len = len(jwt["signature"])
    print(f"\n  Signature: {sig_len} chars (base64url)")

    if check_only:
        sys.exit(1 if (exp and exp < datetime.now(tz=timezone.utc).timestamp()) else 0)


def main():
    parser = argparse.ArgumentParser(description="Decode and inspect JWT tokens")
    parser.add_argument("token", help="JWT token (or - for stdin)")
    parser.add_argument("--check", action="store_true", help="Exit 1 if expired")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    token = sys.stdin.read().strip() if args.token == "-" else args.token
    display(token, check_only=args.check, as_json=args.json)


if __name__ == "__main__":
    main()

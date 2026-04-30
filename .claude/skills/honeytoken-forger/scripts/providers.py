"""
providers.py — Honeytoken format registry.

Defines the structural specification for each supported provider's tokens.
Each entry is a Provider dataclass containing:
    - prefix: the canonical token prefix (e.g., "AKIA", "ghp_")
    - body_length: number of random characters in the body (excluding prefix and checksum)
    - charset: characters legal in the body
    - checksum: which checksum scheme to append (None | "crc32_base62")
    - validator: regex used by real secret scanners (TruffleHog, Gitleaks)
                 to validate tokens of this type

Sources:
    AWS:    AWS IAM Access Key format documentation
    GitHub: https://github.blog/security/application-security/behind-githubs-new-authentication-token-formats/
    Stripe: https://docs.stripe.com/keys
    Slack:  https://api.slack.com/authentication/token-types
    npm:    https://docs.npmjs.com/about-access-tokens

Last verified: 2026-04-30. Token formats drift every 3-5 years; check vendor
docs before relying on this registry for production canary deployments.
"""

import re
import secrets
import string
from dataclasses import dataclass, field
from typing import Callable, Optional

from checksum import crc32_base62


# ---------------------------------------------------------------------------
# Charset constants
# ---------------------------------------------------------------------------

BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
ALPHANUMERIC = BASE62  # alias
HEX_LOWER = string.digits + "abcdef"
# AWS access-key body uses uppercase Base32 minus the digits 0/1/8/9 — but
# in practice AWS only emits uppercase letters and digits 2-7 + some others.
# Real AKIA bodies match: [A-Z0-9]{16}
AWS_ACCESS_KEY_BODY = string.ascii_uppercase + string.digits
# AWS secret access keys: 40 chars, base64-ish but with a custom alphabet
# that excludes some chars to avoid shell-quoting headaches.
AWS_SECRET_BODY = string.ascii_letters + string.digits + "+/"


# ---------------------------------------------------------------------------
# Provider dataclass
# ---------------------------------------------------------------------------

@dataclass
class Provider:
    """Structural spec for a single provider's honeytoken format."""
    name: str
    prefix: str
    body_length: int
    charset: str
    validator: re.Pattern
    # If checksum is set, the function takes the (prefix + body) string and
    # returns a string to append (e.g., 6-char CRC32 Base62 for GitHub).
    checksum: Optional[Callable[[str], str]] = None
    description: str = ""
    # Optional secondary "secret" companion (for AWS-style key/secret pairs).
    companion_length: Optional[int] = None
    companion_charset: Optional[str] = None
    companion_validator: Optional[re.Pattern] = None


# ---------------------------------------------------------------------------
# Token generation primitive
# ---------------------------------------------------------------------------

def _random_string(charset: str, length: int) -> str:
    """Cryptographically secure random string from the given charset."""
    return "".join(secrets.choice(charset) for _ in range(length))


def forge(provider: Provider) -> dict:
    """
    Generate one honeytoken for the given provider.

    Returns:
        A dict with keys:
            - "token":     the generated token string (or primary key, for AWS)
            - "secret":    companion secret (only set for providers with a pair)
            - "validates": True if the generated token passes its own validator
    """
    body = _random_string(provider.charset, provider.body_length)
    token = provider.prefix + body
    if provider.checksum is not None:
        token = token + provider.checksum(token)

    result = {
        "token": token,
        "validates": bool(provider.validator.fullmatch(token)),
    }

    if provider.companion_length is not None:
        secret = _random_string(provider.companion_charset, provider.companion_length)
        result["secret"] = secret
        if provider.companion_validator is not None:
            result["secret_validates"] = bool(
                provider.companion_validator.fullmatch(secret)
            )

    return result


# ---------------------------------------------------------------------------
# Registry — every supported provider, with format spec and validator regex
# ---------------------------------------------------------------------------

REGISTRY: dict[str, Provider] = {

    # AWS Access Keys
    # Access Key ID: AKIA + 16 base32 uppercase chars
    # Secret:        40 chars, Base64-style charset
    # Source: AWS IAM developer documentation
    "aws": Provider(
        name="aws",
        prefix="AKIA",
        body_length=16,
        charset=AWS_ACCESS_KEY_BODY,
        validator=re.compile(r"AKIA[A-Z0-9]{16}"),
        checksum=None,
        description="AWS IAM Access Key ID + Secret Access Key pair",
        companion_length=40,
        companion_charset=AWS_SECRET_BODY,
        companion_validator=re.compile(r"[A-Za-z0-9+/]{40}"),
    ),

    # GitHub Personal Access Token (classic)
    # Format: ghp_ + 30 Base62 + 6-char CRC32-Base62 checksum (total 40 char body)
    # Source: github.blog April 2021 token format announcement
    "github": Provider(
        name="github",
        prefix="ghp_",
        body_length=30,
        charset=BASE62,
        validator=re.compile(r"ghp_[A-Za-z0-9]{36}"),
        checksum=crc32_base62,
        description="GitHub Personal Access Token (classic) with CRC32-Base62 checksum",
    ),

    # Stripe Secret Key (live mode)
    # Format: sk_live_ + 24 alphanumeric
    # Source: Stripe API documentation
    "stripe": Provider(
        name="stripe",
        prefix="sk_live_",
        body_length=24,
        charset=BASE62,
        validator=re.compile(r"sk_live_[A-Za-z0-9]{24}"),
        checksum=None,
        description="Stripe live-mode secret key",
    ),

    # Slack Bot User OAuth Token
    # Format: xoxb- + 11 digits - 12 digits - 24 alphanumeric
    # Source: Slack API token-type documentation
    # Implemented as: prefix "xoxb-" + body that matches the full pattern.
    # We synthesize the entire body here because charset varies by segment.
    "slack": Provider(
        name="slack",
        prefix="xoxb-",
        body_length=0,  # custom-built in forge_slack below
        charset="",
        validator=re.compile(r"xoxb-\d{11}-\d{12}-[A-Za-z0-9]{24}"),
        checksum=None,
        description="Slack Bot User OAuth token",
    ),

    # npm Access Token
    # Format: npm_ + 36 Base62
    # Source: npm documentation on automation/access tokens
    "npm": Provider(
        name="npm",
        prefix="npm_",
        body_length=36,
        charset=BASE62,
        validator=re.compile(r"npm_[A-Za-z0-9]{36}"),
        checksum=None,
        description="npm automation access token",
    ),
}


# ---------------------------------------------------------------------------
# Slack needs a custom forge function because its body has three segments
# with different charsets/lengths.
# ---------------------------------------------------------------------------

def forge_slack() -> dict:
    """Generate a Slack xoxb- bot token with correct three-segment body."""
    seg1 = _random_string(string.digits, 11)
    seg2 = _random_string(string.digits, 12)
    seg3 = _random_string(BASE62, 24)
    token = f"xoxb-{seg1}-{seg2}-{seg3}"
    return {
        "token": token,
        "validates": bool(REGISTRY["slack"].validator.fullmatch(token)),
    }


def forge_provider(name: str) -> dict:
    """Forge a token for the named provider. Slack uses a custom path."""
    if name == "slack":
        return forge_slack()
    if name not in REGISTRY:
        raise ValueError(f"Unknown provider: {name!r}. Known: {list(REGISTRY)}")
    return forge(REGISTRY[name])


# ---------------------------------------------------------------------------
# Self-test — run `python3 providers.py` to verify every provider produces
# tokens that pass its own validator regex.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    failures = []
    for provider_name in REGISTRY:
        for trial in range(20):
            result = forge_provider(provider_name)
            if not result["validates"]:
                failures.append(
                    f"{provider_name} trial {trial}: {result['token']!r} failed validator"
                )
            if "secret_validates" in result and not result["secret_validates"]:
                failures.append(
                    f"{provider_name} trial {trial}: secret {result['secret']!r} failed validator"
                )

    if failures:
        print(f"providers.py — FAILURES ({len(failures)}):")
        for f in failures:
            print(f"  {f}")
        raise SystemExit(1)

    # Demo output — one of each
    print("providers.py — all 5 providers passed 20 trials each.")
    print()
    print("Sample tokens (NOT REAL — for demo only):")
    for name in REGISTRY:
        result = forge_provider(name)
        print(f"  {name:8s} -> {result['token']}")
        if "secret" in result:
            print(f"  {'':8s}    secret: {result['secret']}")

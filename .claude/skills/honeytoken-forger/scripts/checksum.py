"""
checksum.py — Deterministic checksum and encoding functions.

This module is the load-bearing core of the honeytoken-forger skill.
LLMs cannot reliably compute CRC32 or Luhn checksums; this script can.

Functions:
    base62_encode(n)       — Encode a non-negative integer in Base62 (0-9, A-Z, a-z)
    crc32_base62(payload)  — Compute CRC32 of payload bytes, return Base62 string padded to 6 chars
    luhn_check_digit(s)    — Compute the Luhn check digit for a numeric string
    luhn_complete(s)       — Append the Luhn check digit to a numeric string
    luhn_validate(s)       — Validate that a numeric string has a correct Luhn check digit

References:
    GitHub token format (April 2021):
        https://github.blog/security/application-security/behind-githubs-new-authentication-token-formats/
    Luhn algorithm: ISO/IEC 7812-1:2017
"""

import zlib
import string

# Standard Base62 alphabet — used by GitHub for the CRC32 portion of tokens
BASE62_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase


def base62_encode(n: int) -> str:
    """
    Encode a non-negative integer in Base62.

    Examples:
        base62_encode(0)         -> "0"
        base62_encode(61)        -> "z"
        base62_encode(62)        -> "10"
        base62_encode(3844)      -> "100"
    """
    if n < 0:
        raise ValueError("base62_encode requires a non-negative integer")
    if n == 0:
        return "0"
    digits = []
    while n > 0:
        n, rem = divmod(n, 62)
        digits.append(BASE62_ALPHABET[rem])
    return "".join(reversed(digits))


def crc32_base62(payload: str, width: int = 6) -> str:
    """
    Compute the CRC32 checksum of `payload` and return it as a Base62 string,
    left-padded with '0' to exactly `width` characters.

    This matches the GitHub token-format specification for the trailing
    checksum on ghp_/gho_/ghu_/ghs_/ghr_/ghp_pat_ tokens.

    Args:
        payload: the token body (without prefix or trailing checksum)
        width:   the fixed width of the returned Base62 string (default 6)

    Returns:
        A Base62-encoded CRC32 checksum padded to `width` characters.
    """
    crc = zlib.crc32(payload.encode("ascii"))
    encoded = base62_encode(crc)
    if len(encoded) > width:
        # CRC32 is 32-bit; max Base62 length is 6. This should never happen.
        raise RuntimeError(f"Base62 CRC32 exceeded {width} chars: {encoded}")
    return encoded.rjust(width, "0")


def luhn_check_digit(numeric_str: str) -> int:
    """
    Compute the Luhn check digit for a numeric string.

    The Luhn algorithm is used by Visa, MasterCard, Amex, etc. to validate
    that a credit card number is structurally plausible (catches typos and
    randomly-guessed numbers). It does NOT prove the card exists.

    Args:
        numeric_str: digits only, no spaces or dashes

    Returns:
        The single check digit (0-9) that, when appended, makes the
        full number Luhn-valid.
    """
    if not numeric_str.isdigit():
        raise ValueError(f"luhn_check_digit requires digits only, got: {numeric_str!r}")

    total = 0
    # Process from the right; the future check digit sits at position 0.
    # The rightmost input digit is at position 1 (gets doubled), then
    # alternates.
    for i, ch in enumerate(reversed(numeric_str)):
        digit = int(ch)
        if i % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (10 - (total % 10)) % 10


def luhn_complete(numeric_str: str) -> str:
    """Append the Luhn check digit to a numeric string."""
    return numeric_str + str(luhn_check_digit(numeric_str))


def luhn_validate(numeric_str: str) -> bool:
    """
    Verify that a numeric string ends with a correct Luhn check digit.

    Args:
        numeric_str: full number including the trailing check digit

    Returns:
        True if Luhn-valid, False otherwise.
    """
    if not numeric_str.isdigit() or len(numeric_str) < 2:
        return False
    body, check = numeric_str[:-1], int(numeric_str[-1])
    return luhn_check_digit(body) == check


# ---------------------------------------------------------------------------
# Self-test — run `python3 checksum.py` to verify correctness.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Base62 sanity
    assert base62_encode(0) == "0"
    assert base62_encode(61) == "z"
    assert base62_encode(62) == "10"

    # CRC32 stability (any string -> same checksum every run)
    a = crc32_base62("hello")
    b = crc32_base62("hello")
    assert a == b, "CRC32 must be deterministic"
    assert len(a) == 6, f"CRC32 Base62 must pad to 6 chars, got {len(a)}"

    # Luhn — known-good test vector: "7992739871" + check digit "3"
    # Source: Wikipedia Luhn algorithm article (test number).
    assert luhn_check_digit("7992739871") == 3
    assert luhn_validate("79927398713")
    assert not luhn_validate("79927398710")

    # Luhn round-trip
    completed = luhn_complete("411111111111111")
    assert luhn_validate(completed), f"luhn_complete output should validate: {completed}"

    print("checksum.py — all self-tests passed.")

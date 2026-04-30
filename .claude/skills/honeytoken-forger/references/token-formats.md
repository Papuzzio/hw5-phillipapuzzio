# Provider Token Format Reference

This document records the structural specifications for every provider in the
honeytoken-forger registry. Format changes from upstream vendors (new prefixes,
length changes, checksum additions) require a corresponding update here and in
`scripts/providers.py`.

**Last verified:** 2026-04-30
**Re-verification cadence:** every 12 months, or sooner if a vendor announces a token-format change.

---

## AWS Access Keys

**Format:** `AKIA[A-Z0-9]{16}` (Access Key ID) + 40-char Base64-style secret

**Examples (from public AWS documentation, structurally accurate):**
```
AKIAIOSFODNN7EXAMPLE
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Prefixes in use:**
- `AKIA` — long-term IAM user access keys
- `ASIA` — temporary STS session credentials
- `AROA` — IAM role IDs (not credentials, but same structural family)

**Charset:**
- Access Key ID body: uppercase letters and digits only — `[A-Z0-9]`
- Secret Access Key: 40 chars from `[A-Za-z0-9+/]`

**Checksum:** None embedded in the string itself. AWS validates by querying IAM at authentication time.

**Source:** AWS IAM developer documentation. The `AKIA` prefix is documented in the AWS access-key-types reference.

---

## GitHub Personal Access Tokens

**Format (classic PAT):** `ghp_` + 30 Base62 chars + 6-char CRC32-Base62 checksum = 40 chars after the prefix.

**Example structure:**
```
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345aBcDeF
└─┬─┘└──────────────┬─────────────────┘└─┬──┘
prefix       30 random Base62          CRC32-Base62
```

**All prefixes (April 2021 format):**
- `ghp_` — personal access token (classic)
- `gho_` — OAuth access token
- `ghu_` — user-to-server token (GitHub Apps)
- `ghs_` — server-to-server token (GitHub Apps)
- `ghr_` — refresh token
- `github_pat_` — fine-grained personal access token (different structure: 22 + `_` + 59 chars)

**Charset:** `[A-Za-z0-9]` (Base62) for the body; the trailing checksum uses the same alphabet.

**Checksum:** **CRC32 of the (prefix + 30-char body), encoded in Base62, left-padded to 6 chars.** This is the load-bearing math the script must compute correctly.

**Why this matters:** GitHub introduced this format in April 2021 specifically so that secret-scanning tools (TruffleHog, Gitleaks, GitHub's own first-party scanner) can distinguish real tokens from random strings that happen to match the regex. A `ghp_` string with the right length but a wrong checksum is silently dropped by every modern scanner.

**Source:** [GitHub Engineering blog, "Behind GitHub's new authentication token formats" (April 2021)](https://github.blog/security/application-security/behind-githubs-new-authentication-token-formats/)

---

## Stripe API Keys

**Format:** `sk_live_` + 24 alphanumeric chars (live mode) or `sk_test_` + 24 alphanumeric chars (test mode).

**Example structure:**
```
sk_live_EXAMPLE_DECOY_NOT_REAL_X
└──┬───┘└────────────┬───────────┘
mode        24 alphanumeric
```

*Note: the docs example here was scrubbed to a clearly-fake placeholder because the original (Stripe's own published example token) was flagged as a real key by GitHub Push Protection — itself proof the format spec in this file is accurate.*

**Prefixes in use:**
- `sk_live_` — live secret key (production)
- `sk_test_` — test mode secret key (sandbox; cannot move money)
- `pk_live_`, `pk_test_` — publishable keys (front-end safe)
- `rk_live_`, `rk_test_` — restricted keys
- Newer formats prepend `sk_live_5…` style prefixes for high-volume accounts; the registry currently models the canonical short form.

**Charset:** `[A-Za-z0-9]` for the 24-char body.

**Checksum:** None embedded in the string. Stripe validates server-side at authentication.

**Source:** [Stripe API documentation, "API keys" section](https://docs.stripe.com/keys)

---

## Slack Bot User OAuth Tokens

**Format:** `xoxb-` + 11 digits + `-` + 12 digits + `-` + 24 alphanumeric chars.

**Example structure:**
```
xoxb-EXAMPLE_TM1-EXAMPLE_BOT1-EXAMPLE_DECOY_NOT_REAL_X
└─┬─┘└────┬─────┘└─────┬──────┘└────────────┬────────┘
prefix  team-id      bot-id            secret body
       (11 digits) (12 digits)         (24 base62)
```

*Note: the docs example here was scrubbed to a clearly-fake placeholder (underscores break the digit and alphanumeric segment regexes) because the original was flagged as a real Slack token by GitHub Push Protection — itself proof the format spec in this file is accurate.*

**Prefix variants:**
- `xoxb-` — bot user OAuth token
- `xoxp-` — user OAuth token
- `xoxa-` — workspace token
- `xoxr-` — refresh token (newer)

**Charset:**
- First two segments: digits only
- Third segment: `[A-Za-z0-9]`

**Checksum:** None embedded.

**Source:** [Slack API token-types documentation](https://api.slack.com/authentication/token-types)

---

## npm Access Tokens

**Format:** `npm_` + 36 Base62 chars.

**Example structure:**
```
npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab
└─┬─┘└────────────────┬───────────────────┘
prefix          36 Base62 chars
```

**Charset:** `[A-Za-z0-9]` for the 36-char body.

**Checksum:** None embedded. npm registry validates server-side.

**Source:** [npm Docs, "About access tokens"](https://docs.npmjs.com/about-access-tokens)

---

## Format-Drift Watchlist

These items should be re-checked at the next 12-month verification:

- **GitHub fine-grained PATs** (`github_pat_…`) use a two-segment 22+59 structure that is not yet modeled in the registry. Adding this requires a `github-pat-fine-grained` entry with a custom checksum function (CRC32 over the 59-char second segment).
- **AWS** introduced new prefix `ABIA` for AWS STS service bearer tokens. Currently out of scope.
- **Stripe** account-level keys (introduced in 2024) carry an account-id segment after `sk_live_`; the canonical short form modeled here is still emitted alongside.
- **Slack** has rolled out `xoxe.xoxb-` rotation tokens for refresh; not yet modeled.

---

## Why a single registry file matters

Centralising format facts in this file rather than embedding them in `providers.py` means:

1. The Python module stays small and focused on generation logic.
2. Future updates to vendor docs map to a single file edit, not a hunt across the codebase.
3. Auditors can verify the skill's claims against vendor-published format documentation without reading Python.

If a vendor changes their token format, update **both** this file and `scripts/providers.py` in the same commit.

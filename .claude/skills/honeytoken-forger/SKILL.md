---
name: honeytoken-forger
description: Forges format-correct honeytokens (decoy credentials) for AWS, GitHub, Stripe, Slack, and npm that pass real secret-scanner validators (TruffleHog, Gitleaks, GitHub's own scanner) by computing CRC32-Base62 and Luhn checksums correctly. Use this skill whenever the user asks to forge, generate, mint, create, or produce honeytokens, canarytokens, decoy credentials, fake API keys, tripwire credentials, blue-team deception artifacts, scanner-test fixtures, or any kind of bait credential. Also use it when the user wants to populate a deliberately-leaked config file, set up canary tripwires for a repo or S3 bucket, or test a secret-scanning pipeline. Every output is labeled NOT_REAL with a SHA-256-keyed audit manifest; the skill refuses to remove that label without explicit dual-use acknowledgement.
---

# honeytoken-forger

Generates format-correct decoy credentials for blue-team deception, canary deployments, and secret-scanner test harnesses. The deterministic checksum math (CRC32-Base62 for GitHub, Luhn for any payment-style honeytokens) is handled by the bundled Python script — Claude alone cannot compute these reliably, which is why generated decoys must come from the script, not from the model.

## When to use this skill

Trigger on any of:

- "forge / generate / mint / create / produce" combined with "honeytoken / canarytoken / decoy / tripwire / bait / fake credential / fake API key / fake token"
- A user asking to seed a repo, S3 bucket, config file, database row, or backup with deliberately-leaked-looking credentials
- A user setting up detection rules for TruffleHog, Gitleaks, GitHub secret scanning, AWS CloudTrail canaries, or a SIEM tripwire
- A user wanting test fixtures that exercise their secret-scanning CI/CD pipeline
- A user asking for "AWS keys / GitHub PATs / Stripe keys / Slack tokens / npm tokens that look real but are not real"

## When NOT to use this skill

- The user asks for **real** working credentials — refuse and direct them to the actual provider's IAM / token-issuance flow.
- The user asks to forge tokens for a provider not in the registry (Twitter, Microsoft, GCP, Atlassian, etc.) — say which providers are supported and offer to extend the registry.
- The user wants tokens with the NOT_REAL banner stripped *without* the explicit `--i-know-what-im-doing` acknowledgement — refuse, per the script's built-in policy.
- The user wants the skill to authenticate against the real provider — that is functionally impossible by design (these tokens grant zero access).

## Inputs

- `providers` — comma-separated list from: `aws, github, stripe, slack, npm`
- `count` — number of tokens per provider (default 1)
- `label` — short identifier embedded in the banner and manifest (e.g., `staging-canary`, `prod-tripwire-q2`)
- `output` — directory to write to (default `./decoys`)
- `--no-banner` *(rare)* — strip the NOT_REAL banner; requires `--i-know-what-im-doing`

## Outputs

For each requested token, the script writes:

1. A provider-specific text file (e.g., `aws_credentials_1.txt`, `github_pat_1.txt`) with a NOT_REAL banner header.
2. An aggregate `MANIFEST.json` with one entry per token containing:
   - `provider`, `filename`, `label`, `generated_at` (UTC ISO 8601)
   - `token_sha256` and (for AWS) `secret_sha256` — never the raw tokens
   - `decoy_only: true`
   - `validator_passed: true/false` — whether the token passed its own validator regex
   - `banner_included: true/false`

## How to invoke

The script lives at `scripts/forge.py` in this skill directory.

```bash
python3 .claude/skills/honeytoken-forger/scripts/forge.py \
  --providers aws,github,stripe \
  --count 1 \
  --label staging-canary \
  --output ./decoys
```

To list supported providers without generating anything:

```bash
python3 .claude/skills/honeytoken-forger/scripts/forge.py --list-providers
```

## Exit codes

- `0` — success, all tokens written
- `2` — bad arguments (e.g., unknown provider name); nothing written
- `3` — refused (e.g., `--no-banner` without `--i-know-what-im-doing`); nothing written
- `4` — internal validator failure (a generated token did not pass its own regex; should never happen — file a bug)

## Why this needs a script (not just a prompt)

Real secret scanners (TruffleHog, Gitleaks, GitHub's first-party scanner) reject tokens that fail provider-specific structural checks. Two of the supported providers embed checksums that are deterministic but non-trivial:

- **GitHub PATs** carry a 6-character CRC32-Base62 checksum in the trailing position. A randomly-typed `ghp_…` string passes the regex but fails the checksum and is silently dropped by every modern scanner. The script computes CRC32 in `zlib` and Base62-encodes it correctly; an LLM left to its own devices produces strings that fail this check the majority of the time.
- **Payment-card-style PAN honeytokens** (not currently in the registry but supported by `checksum.luhn_complete`) require a Luhn check digit. Every payment processor since 1954 rejects non-Luhn-valid numbers in milliseconds. Same problem: LLMs hallucinate the check digit; Python computes it.

Without correct checksums, a "honeytoken" is a useless string that no scanner will react to — which means no tripwire fires when an attacker finds it. **The math is the difference between a working trap and a decorative comment.**

## Safety / dual-use posture

Honeytokens are dual-use: the same artifact that detects an intruder could, in principle, be planted to cast suspicion on an innocent party or used as a fraud lure. The skill enforces three guardrails:

1. **Banner-by-default.** Every output file begins with a `# NOT_REAL — honeytoken …` banner with timestamp and label. The banner cannot be dropped without `--i-know-what-im-doing`.
2. **No raw tokens in the manifest.** The manifest stores only SHA-256 hashes of generated tokens, so the audit trail does not double as a leak.
3. **Provenance label required.** Every honeytoken carries a label (default `unlabeled` if the user does not supply one) identifying the deployment context.

If a user attempts to bypass the banner without acknowledgement, the script refuses with exit code 3 and explains the rationale rather than failing silently.

## Limitations

- Token format specifications drift every 3–5 years (GitHub revised its formats in 2021; npm followed). The registry was last verified on 2026-04-30 — see `references/token-formats.md`. Re-check vendor docs before relying on this skill for production canary deployments older than ~24 months.
- The skill does **not** register the generated tokens with the actual provider. To turn a generated string into a working tripwire, the operator must separately:
  - Configure CloudTrail / GuardDuty alerts on the AWS Access Key ID
  - Subscribe to GitHub's secret-scanning notifications for the repo where the PAT is planted
  - Wire up Stripe / Slack / npm provider-specific monitoring
- The skill generates tokens but does not place them. Strategic placement (database row, S3 bucket, fake admin's `~/.aws/credentials`, etc.) is the operator's responsibility and is the higher-leverage half of the deception.

## Test cases

Three documented test cases live alongside the script and are verified during development:

1. **Normal** — `--providers aws,github,stripe --count 1 --label demo-week5`. Exit 0; three banner-prefixed files plus a manifest with `validator_passed: true` for all entries.
2. **Edge** — `--providers aws,facebook,github` (unknown provider). Exit 2; stderr names `facebook` and lists valid providers; no output directory created (atomic failure).
3. **Cautious** — `--providers stripe --no-banner` (without `--i-know-what-im-doing`). Exit 3; refusal message explains the policy and suggests an alternative; no output directory created.

## Files

- `scripts/forge.py` — CLI entrypoint
- `scripts/providers.py` — provider registry (AWS, GitHub, Stripe, Slack, npm)
- `scripts/checksum.py` — CRC32-Base62, Luhn, Base62 (the load-bearing math)
- `references/token-formats.md` — provider-format citations and last-verified date

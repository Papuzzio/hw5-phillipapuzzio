# honeytoken-forger

> A Claude Code skill that forges checksum-valid honeytokens (AWS, GitHub, Stripe, Slack, npm) for blue-team deception. The Python script computes CRC32-Base62 and Luhn checksums LLMs cannot, producing decoys that survive real secret-scanner validation and fire tripwires when used.

**Author:** Phillip Apuzzio
**Course:** Week 5 — Build a Reusable AI Skill

---

## What this skill does

`honeytoken-forger` is a Claude Code skill that generates **format-correct decoy credentials** for five major providers. The generated tokens are deliberately fake — they grant zero access to anything — but they are structurally indistinguishable from real credentials and will be flagged as live findings by every modern secret scanner (TruffleHog, Gitleaks, GitHub's first-party scanner, AWS CloudTrail-based canary detectors).

The point of a honeytoken is to be discovered by an attacker who has breached your perimeter. The moment they try to authenticate with the decoy, your monitoring fires — you have caught them. This skill produces the bait. The defender wires the alarm.

| Provider | Format | Checksum |
|---|---|---|
| AWS | `AKIA[A-Z0-9]{16}` + 40-char secret | None embedded |
| GitHub | `ghp_` + 30 Base62 + **CRC32-Base62 checksum** | CRC32-Base62 (load-bearing) |
| Stripe | `sk_live_` + 24 alphanumeric | None embedded |
| Slack | `xoxb-NNNNNNNNNNN-NNNNNNNNNNNN-XXXXXXXXXXXXXXXXXXXXXXXX` | None embedded |
| npm | `npm_` + 36 Base62 | None embedded |

A standalone Luhn-check-digit utility is included in `scripts/checksum.py` for adding payment-card-style PAN honeytokens to the registry in future revisions.

---

## Why I chose this skill

The Week 5 assignment requires a skill where a **script is genuinely load-bearing** — where prose alone, or an LLM responding from natural language, cannot do the job. Honeytoken generation hits that requirement squarely:

- **Real secret scanners reject tokens that fail provider-specific checksums.** GitHub's April 2021 token format embeds a 6-character CRC32-Base62 checksum in the trailing position of every `ghp_` token. A `ghp_` string with the right length but a wrong checksum is silently dropped by every scanner. If the scanner discards the bait, no tripwire fires.
- **LLMs cannot compute CRC32 reliably.** Asking Claude or GPT to "generate a fake GitHub token" produces strings that pass the regex but fail the checksum. They are useless as honeytokens.
- **Python computes CRC32 correctly in three lines** (`zlib.crc32` + Base62 encode + left-pad). The math is the difference between a working trap and a decorative comment.

The skill plays directly to my professional context as an Application Security Engineer: blue-team deception, secret-scanner detection rules, and canary tripwires are real techniques used by real defenders. None of the work in this repo touches classified material — every format spec is sourced from public vendor documentation.

---

## How to use it

### Quick start

From inside Claude Code, with this repo as the working directory, ask naturally:

> *"Forge me three honeytokens for AWS, GitHub, and Stripe. Label them `staging-canary` and put them in `./decoys/`."*

Claude Code reads `.claude/skills/honeytoken-forger/SKILL.md`, recognizes the trigger words, and runs the bundled script.

### Direct CLI invocation

```bash
python3 .claude/skills/honeytoken-forger/scripts/forge.py \
  --providers aws,github,stripe \
  --count 1 \
  --label staging-canary \
  --output ./decoys
```

### List supported providers

```bash
python3 .claude/skills/honeytoken-forger/scripts/forge.py --list-providers
```

---

## What the script does

The skill bundles three Python modules under `scripts/`, each with a single responsibility:

### `checksum.py` — the deterministic math

Three functions an LLM cannot do reliably:

- `base62_encode(n)` — converts non-negative integers to GitHub's 62-character alphabet (`0-9A-Za-z`).
- `crc32_base62(payload)` — computes CRC32 of the payload via `zlib.crc32`, encodes the result in Base62, left-pads to exactly 6 characters. This matches GitHub's published token-format specification.
- `luhn_check_digit(s)` / `luhn_validate(s)` — the 1954 Luhn algorithm used by every payment processor on Earth. Required for any future credit-card-style PAN honeytokens.

Each function has self-tests at the bottom of the file. Running `python3 checksum.py` prints `checksum.py — all self-tests passed.` if every assertion holds.

### `providers.py` — the format registry

A dataclass-based registry of every supported provider. Each `Provider` entry stores prefix, body length, charset, validator regex (the same regex real secret scanners use), and an optional checksum function. The module exposes `forge_provider(name)`, which generates one token, runs it back through its own validator regex as a self-test, and refuses to emit anything that fails.

The self-test runs **20 trials per provider × 5 providers = 100 token generations** and verifies every one passes its own validator. Running `python3 providers.py` prints a one-of-each sample at the end.

### `forge.py` — the CLI

Argparse-based entry point that ties the registry to the filesystem. Adds three things on top of generation:

1. **NOT_REAL banner enforcement.** Every output file begins with a banner naming the timestamp, label, and source skill. The banner cannot be removed without `--no-banner` AND `--i-know-what-im-doing` together.
2. **Audit manifest.** Every run produces `MANIFEST.json` in the output directory, with one entry per token containing SHA-256 hash, label, generation timestamp (UTC, ISO 8601), `decoy_only: true`, and validator-pass status. The raw tokens are never recorded in the manifest — only their hashes.
3. **Distinct exit codes.** `0` success, `2` bad arguments, `3` cautious-case refusal, `4` internal validator failure (should never happen).

---

## Test cases

Three test cases are documented and verified during development. All three were run and passed before SKILL.md was finalized.

### 1. Normal case

```bash
python3 .claude/skills/honeytoken-forger/scripts/forge.py \
  --providers aws,github,stripe --count 1 --label demo-week5 --output ./examples/decoys
```

**Result:** Exit `0`. Three banner-prefixed files (`aws_credentials_1.txt`, `github_pat_1.txt`, `stripe_sk_1.txt`) plus a manifest with `validator_passed: true` for all entries. The GitHub PAT's trailing 6 characters are a valid CRC32-Base62 checksum of the preceding payload.

### 2. Edge case — unknown provider

```bash
python3 .claude/skills/honeytoken-forger/scripts/forge.py \
  --providers aws,facebook,github --count 1 --label edge-test --output ./examples/decoys-unknown
```

**Result:** Exit `2`. Stderr names the unknown provider (`facebook`) and lists the five valid options. **No output directory is created** — the script validates input before any filesystem operation, so a partial-write scenario is impossible. Even if a single bad provider appears in a list of fifty good ones, nothing reaches disk.

### 3. Cautious case — banner refusal

```bash
python3 .claude/skills/honeytoken-forger/scripts/forge.py \
  --providers stripe --count 1 --label cautious-test --output ./examples/should-not-exist --no-banner
```

**Result:** Exit `3`. Stderr explains why the banner exists (audit trail / fraud-vs-deception distinction), names the escape hatch (`--i-know-what-im-doing`), and suggests an alternative for the user's likely actual goal. **No output directory is created.** This is the load-bearing safety property of the skill: it will not write a token-shaped string to disk without provenance unless the operator explicitly accepts the dual-use risk.

---

## What worked well

- **Atomic failure on bad input.** The script validates all provider names and all flag combinations before any filesystem operation. This was a deliberate choice and it makes the skill safe to use in scripted contexts where partial writes would be silently corrupting.
- **Self-validating registry.** Every generated token is run through its own validator regex before being emitted. The script refuses to write a token that does not match the validator real scanners would use. This catches registry-spec drift early.
- **Refusal that teaches.** The cautious-case stderr message does not just say "no" — it explains the underlying policy (the banner is what distinguishes a deception artifact from a fraud artifact), names the escape hatch, and suggests a likely-better alternative. This is the behavior the assignment rubric explicitly asks for in the cautious case.
- **Progressive disclosure.** SKILL.md stays under 120 lines (within Anthropic's recommended budget); detailed format citations live in `references/token-formats.md` and only load when Claude needs to extend the registry.
- **No raw tokens in the manifest.** The audit trail records SHA-256 hashes only. The manifest is safe to commit and share without doubling as a leak.

---

## Limitations

- **Format-drift risk.** Provider token formats change every 3–5 years (GitHub revised theirs in 2021; npm followed). The registry was last verified on 2026-04-30 against vendor-published documentation. See `.claude/skills/honeytoken-forger/references/token-formats.md` for the format-drift watchlist.
- **Generation, not deployment.** The skill produces format-correct strings. Turning a string into a working tripwire requires the operator to separately wire detection — e.g., subscribing to GitHub's secret-scanning notifications, configuring CloudTrail alerts on the AWS Access Key ID, etc. Strategic placement of the honeytoken (database row, S3 bucket, fake admin's `~/.aws/credentials`) is the higher-leverage half of the deception and is out of scope for this skill.
- **Five providers only.** The current registry covers AWS, GitHub (classic PAT), Stripe (live secret key), Slack (bot user OAuth), and npm. Notable absences:
  - GitHub fine-grained PATs (`github_pat_…`) — different two-segment structure, different checksum scheme.
  - GCP service account keys (JSON-shaped, not single-string).
  - Atlassian, Twilio, OpenAI, Anthropic, etc.
  Adding a provider requires one new entry in `scripts/providers.py` and a section in `references/token-formats.md`.
- **Dual-use surface.** A maliciously-modified version of this script (banner stripped, manifest disabled) could in principle generate convincing fraud lures. The committed version refuses to do this and exits with code 3 if asked. Anyone forking the repo and removing the refusal is making a deliberate choice — and leaving a clear git-blame trail when they do.

---

## Validation event — GitHub's own scanner caught the bait

On the first push of this repo to GitHub, **GitHub Secret Scanning Push Protection blocked the push**, flagging the sample Stripe and Slack honeytokens in `examples/` as real-looking credentials.

This is the most direct possible validation that the skill works. The thesis of `honeytoken-forger` is that a script must compute provider-specific structural and checksum constraints correctly — otherwise the generated decoys are silently dropped by real scanners and never trigger any tripwire. GitHub's first-party scanner is the most-deployed secret scanner on Earth, and it could not distinguish these decoys from real credentials.

In response, the raw token files (`*.txt` under `examples/`) are now gitignored. The `MANIFEST.json` files are still committed because they record only SHA-256 hashes, never the tokens themselves — so the audit trail survives without re-tripping Push Protection. Anyone who clones this repo can regenerate matching tokens locally with the documented test commands.

The Push Protection block is preserved as evidence in the repo's GitHub Security tab.

---

## Repository layout

````
hw5-phillipapuzzio/
├── .claude/
│   └── skills/
│       └── honeytoken-forger/
│           ├── SKILL.md
│           ├── scripts/
│           │   ├── checksum.py     (Base62, CRC32-Base62, Luhn)
│           │   ├── providers.py    (5-provider registry, self-validating)
│           │   └── forge.py        (CLI, banner enforcement, manifest)
│           └── references/
│               └── token-formats.md (vendor citations + drift watchlist)
├── examples/
│   └── decoys/                      (sample output from the normal-case run)
├── README.md                        (this file)
└── .gitignore
````

---

## References

- [GitHub Engineering: Behind GitHub's new authentication token formats (April 2021)](https://github.blog/security/application-security/behind-githubs-new-authentication-token-formats/)
- [Stripe API documentation: API keys](https://docs.stripe.com/keys)
- [Slack API: Token types](https://api.slack.com/authentication/token-types)
- [npm Docs: About access tokens](https://docs.npmjs.com/about-access-tokens)
- [Anthropic: Claude Code skills documentation](https://code.claude.com/docs/en/skills)
- [Anthropic skills repository](https://github.com/anthropics/skills)

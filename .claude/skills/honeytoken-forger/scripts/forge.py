#!/usr/bin/env python3
"""
forge.py — Honeytoken CLI.

Generates format-correct decoy credentials for blue-team deception
(canarytokens, tripwires, scanner detection rules).

Examples:
    # Forge 3 AWS honeytokens, label "lab-test", write to ./decoys/
    python3 forge.py --providers aws --count 3 --label lab-test --output ./decoys

    # Forge one of each kind
    python3 forge.py --providers aws,github,stripe,slack,npm --label demo --output ./decoys

    # List available providers
    python3 forge.py --list-providers

SAFETY:
    Every generated token is written with a NOT_REAL banner and recorded in
    MANIFEST.json with a `"decoy_only": true` flag. The --no-banner flag
    requires the explicit --i-know-what-im-doing acknowledgement; without it,
    the script refuses to remove the banner.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running as `python3 forge.py` from inside the scripts/ directory,
# or as a module. Add the script's own directory to sys.path so sibling
# imports resolve.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from providers import REGISTRY, forge_provider  # noqa: E402


BANNER_TEMPLATE = (
    "# NOT_REAL — honeytoken, generated {ts}, label={label}\n"
    "# Do not use as real credentials. These are decoys for blue-team detection.\n"
    "# Source: honeytoken-forger skill — see MANIFEST.json for audit trail.\n"
)

OUTPUT_TEMPLATES = {
    "aws": (
        "{banner}"
        "[default]\n"
        "aws_access_key_id     = {token}\n"
        "aws_secret_access_key = {secret}\n"
    ),
    "github": "{banner}{token}\n",
    "stripe": "{banner}{token}\n",
    "slack":  "{banner}{token}\n",
    "npm":    "{banner}{token}\n",
}

OUTPUT_FILENAMES = {
    "aws":    "aws_credentials_{i}.txt",
    "github": "github_pat_{i}.txt",
    "stripe": "stripe_sk_{i}.txt",
    "slack":  "slack_xoxb_{i}.txt",
    "npm":    "npm_token_{i}.txt",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="forge.py",
        description="Forge format-correct honeytokens for blue-team deception.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--providers",
        type=str,
        help="Comma-separated provider names (e.g., aws,github,stripe). "
             "Use --list-providers to see all.",
    )
    p.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of tokens to forge per provider (default: 1)",
    )
    p.add_argument(
        "--label",
        type=str,
        default="unlabeled",
        help="Identifier embedded in the banner and manifest. Required for "
             "tracing which deployment the token belongs to.",
    )
    p.add_argument(
        "--output",
        type=str,
        default="./decoys",
        help="Output directory (default: ./decoys)",
    )
    p.add_argument(
        "--no-banner",
        action="store_true",
        help="Remove the NOT_REAL banner. REQUIRES --i-know-what-im-doing.",
    )
    p.add_argument(
        "--i-know-what-im-doing",
        action="store_true",
        help="Acknowledge the dual-use risk of removing the banner.",
    )
    p.add_argument(
        "--list-providers",
        action="store_true",
        help="List all supported providers and exit.",
    )
    return p.parse_args()


def cautious_refusal_message() -> str:
    return (
        "\n"
        "REFUSED: --no-banner requires --i-know-what-im-doing.\n"
        "\n"
        "Honeytokens MUST be labeled NOT_REAL when written to disk. The banner\n"
        "is the audit trail that distinguishes a deception artifact from a fraud\n"
        "artifact. Without it, this output is indistinguishable from a real\n"
        "leaked credential.\n"
        "\n"
        "If you genuinely need an unbannered token (e.g., for an automated\n"
        "scanner test harness that strips comments), pass both --no-banner AND\n"
        "--i-know-what-im-doing, and ensure your downstream pipeline records\n"
        "provenance separately.\n"
        "\n"
        "Suggestion: if you want a token that 'looks real' for a demo, leave the\n"
        "banner in — attackers will not see it; only auditors and your future\n"
        "self will.\n"
    )


def build_banner(label: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return BANNER_TEMPLATE.format(ts=ts, label=label)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main() -> int:
    args = parse_args()

    if args.list_providers:
        print("Supported providers:")
        for name, prov in REGISTRY.items():
            print(f"  {name:8s} — {prov.description}")
        return 0

    if not args.providers:
        print("ERROR: --providers is required (or use --list-providers).",
              file=sys.stderr)
        return 2

    # Cautious-case enforcement: refuse to drop the banner without acknowledgment.
    if args.no_banner and not args.i_know_what_im_doing:
        print(cautious_refusal_message(), file=sys.stderr)
        return 3

    requested = [p.strip() for p in args.providers.split(",") if p.strip()]
    unknown = [p for p in requested if p not in REGISTRY]
    if unknown:
        print(f"ERROR: unknown provider(s): {unknown}. "
              f"Known: {list(REGISTRY)}", file=sys.stderr)
        return 2

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    banner = "" if args.no_banner else build_banner(args.label)
    manifest = []

    for provider_name in requested:
        for i in range(1, args.count + 1):
            result = forge_provider(provider_name)
            template = OUTPUT_TEMPLATES[provider_name]
            filename = OUTPUT_FILENAMES[provider_name].format(i=i)

            content = template.format(
                banner=banner,
                token=result["token"],
                secret=result.get("secret", ""),
            )

            filepath = output_dir / filename
            filepath.write_text(content)

            entry = {
                "provider": provider_name,
                "filename": filename,
                "token_sha256": sha256_hex(result["token"]),
                "label": args.label,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "decoy_only": True,
                "validator_passed": result["validates"],
                "banner_included": not args.no_banner,
            }
            if "secret" in result:
                entry["secret_sha256"] = sha256_hex(result["secret"])
            manifest.append(entry)

    manifest_path = output_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"Forged {len(manifest)} honeytoken(s) -> {output_dir}/")
    for entry in manifest:
        print(f"  {entry['filename']:30s} "
              f"({entry['provider']}, validator={'PASS' if entry['validator_passed'] else 'FAIL'})")
    print(f"  MANIFEST.json (audit trail with SHA-256 hashes, decoy_only=true)")

    if any(not e["validator_passed"] for e in manifest):
        print("WARNING: at least one token failed its own validator. "
              "This should never happen — please file a bug.", file=sys.stderr)
        return 4

    return 0


if __name__ == "__main__":
    sys.exit(main())

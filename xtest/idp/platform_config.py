"""Render a platform service config for a given IdP provider.

Patches a copy of an existing platform YAML (e.g. platform/opentdf-dev.yaml)
so the platform trusts the provider's issuer/audience and runs the provider's
ERS mode — no hand-editing of config. SDKs then follow automatically: they
read `platform_issuer` from the platform well-known and OIDC-discover the
token endpoint from it.

Usage:
    uv run python -m idp.platform_config keycloak \
        --base ../platform/opentdf-dev.yaml --out tmp/opentdf-idp-keycloak.yaml
"""

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from idp.provider import load_provider


def render_overlay(provider_name: str, base_path: Path) -> dict[str, Any]:
    resolved = load_provider(provider_name)
    if not resolved.ready:
        raise SystemExit(
            f"provider {provider_name!r} has unresolved environment secrets: "
            f"{', '.join(resolved.missing_secrets)}"
        )
    provider = resolved.provider
    config: dict[str, Any] = yaml.safe_load(base_path.read_text())
    auth = config.setdefault("server", {}).setdefault("auth", {})
    auth["issuer"] = provider.issuer
    auth["audience"] = provider.audience
    auth.setdefault("dpop", {})["enforce"] = provider.platform_overlay.dpop_enforce
    if provider.platform_overlay.casbin_extension:
        auth.setdefault("policy", {})["extension"] = (
            provider.platform_overlay.casbin_extension
        )
    if provider.platform_overlay.casbin_groups_claim:
        auth.setdefault("policy", {})["groups_claim"] = (
            provider.platform_overlay.casbin_groups_claim
        )
    config.setdefault("services", {}).setdefault("entityresolution", {})["mode"] = (
        provider.ers.mode
    )
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render a platform config overlay for an IdP provider."
    )
    parser.add_argument("provider", help="provider name (idp/providers/<name>.yaml)")
    parser.add_argument(
        "--base", type=Path, required=True, help="base platform YAML to patch"
    )
    parser.add_argument(
        "--out", type=Path, required=True, help="output path for the rendered YAML"
    )
    args = parser.parse_args(argv)
    config = render_overlay(args.provider, args.base)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(yaml.safe_dump(config, sort_keys=False))
    auth = config["server"]["auth"]
    print(f"wrote {args.out} (issuer={auth['issuer']}, audience={auth['audience']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

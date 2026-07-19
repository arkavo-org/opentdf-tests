"""Per-provider OIDC configuration for the IdP conformance suite.

Each provider is a YAML file in idp/providers/. Secrets are never committed:
string fields may reference environment variables with `${VAR}` or
`${VAR:-default}` syntax; unresolved variables are collected so callers can
skip (PR runs) or fail (nightly `--idp-strict` runs) with a precise reason.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

PROVIDERS_DIR = Path(__file__).parent / "providers"

_ENV_REF = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}")


class Capabilities(BaseModel):
    """What the IdP supports.

    `dpop=None` means unknown: it is reported as a coverage gap (skip with
    reason), never as a pass or a fail.
    """

    dpop: bool | None = None
    # Can mint an access token for a different audience (negative-test input).
    custom_audience: bool = False
    # Token lifetime is configurable low enough to test real expiry.
    configurable_token_lifetime: bool = False


class ErsConfig(BaseModel):
    mode: Literal["keycloak", "claims", "multi-strategy"] = "claims"
    required_claims: list[str] = Field(default_factory=lambda: ["sub"])


class PlatformOverlay(BaseModel):
    dpop_enforce: bool = False


class IdpProvider(BaseModel):
    name: str
    display_name: str = ""
    # local: always available (Keycloak dev realm). external: needs secrets.
    tier: Literal["local", "external"] = "external"
    # Who re-ups the tenant credentials when they expire.
    owner: str = ""
    # False while the tenant/secrets don't exist yet: the provider never gates
    # a run (skips with a pointer to its setup runbook, even --idp-strict) and
    # the nightly matrix excludes it. Flip to true once the tenant is live.
    onboarded: bool = True
    issuer: str
    audience: str
    client_id: str
    client_secret: str
    # Some IdPs bind DPoP per-client (Keycloak); most use the same client.
    dpop_client_id: str | None = None
    dpop_client_secret: str | None = None
    # Extra form fields for the token request (e.g. Auth0's `audience`).
    token_endpoint_params: dict[str, str] = Field(default_factory=dict)
    # Audience value to request for the wrong-audience negative test.
    wrong_audience: str | None = None
    # A real access token that has since expired (safe to commit: it's
    # expired). Enables the expired-token negative test without needing a
    # short-lifetime client.
    expired_token: str | None = None
    capabilities: Capabilities = Field(default_factory=Capabilities)
    ers: ErsConfig = Field(default_factory=ErsConfig)
    platform_overlay: PlatformOverlay = Field(default_factory=PlatformOverlay)

    def dpop_credentials(self) -> tuple[str, str]:
        return (
            self.dpop_client_id or self.client_id,
            self.dpop_client_secret or self.client_secret,
        )


@dataclass
class ResolvedProvider:
    provider: IdpProvider
    missing_secrets: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.missing_secrets


def _interpolate(value: Any, missing: list[str]) -> Any:
    if isinstance(value, str):

        def repl(match: re.Match[str]) -> str:
            var, default = match.group(1), match.group(2)
            env = os.environ.get(var)
            if env:
                return env
            if default is not None:
                return default
            if var not in missing:
                missing.append(var)
            return ""

        return _ENV_REF.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v, missing) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v, missing) for v in value]
    return value


def list_providers() -> list[str]:
    return sorted(p.stem for p in PROVIDERS_DIR.glob("*.yaml"))


def load_provider(name: str) -> ResolvedProvider:
    path = PROVIDERS_DIR / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(
            f"no IdP provider config for {name!r} at {path} "
            f"(available: {', '.join(list_providers())})"
        )
    raw = yaml.safe_load(path.read_text())
    missing: list[str] = []
    data = _interpolate(raw, missing)
    return ResolvedProvider(
        provider=IdpProvider.model_validate(data), missing_secrets=missing
    )

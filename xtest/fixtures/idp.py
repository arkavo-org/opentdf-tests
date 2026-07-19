"""Fixtures and CLI options for the IdP conformance suite (test_idp_conformance.py).

Provider selection is via `--idp-providers "keycloak auth0"` (default:
keycloak). Any test requesting the `idp` fixture is parametrized once per
selected provider; OIDC artifacts (discovery, JWKS, tokens) are cached for
the pytest session.
"""

import os
import typing

import pytest
import requests

from idp.oidc import (
    DiscoveryDocument,
    TokenResponse,
    fetch_discovery,
    fetch_jwks,
    get_client_credentials_token,
)
from idp.provider import IdpProvider, ResolvedProvider, list_providers, load_provider


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--idp-providers",
        help="space-separated IdP provider names from idp/providers/ (default: keycloak)",
    )
    parser.addoption(
        "--idp-strict",
        action="store_true",
        help="fail (not skip) on missing provider secrets or a platform/issuer mismatch",
    )


def _selected_provider_names(config: pytest.Config) -> list[str]:
    opt = config.getoption("--idp-providers")
    names = opt.split() if opt else ["keycloak"]
    available = list_providers()
    unknown = [n for n in names if n not in available]
    if unknown:
        raise pytest.UsageError(
            f"unknown IdP provider(s): {', '.join(unknown)}; "
            f"available: {', '.join(available)}"
        )
    return names


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "idp" in metafunc.fixturenames:
        names = _selected_provider_names(metafunc.config)
        metafunc.parametrize("idp", names, indirect=True, scope="session")


class IdpSession:
    """Resolved provider config plus lazily-fetched OIDC artifacts, session-cached."""

    def __init__(self, resolved: ResolvedProvider, strict: bool) -> None:
        self.resolved = resolved
        self.strict = strict
        self._discovery: DiscoveryDocument | None = None
        self._jwks: dict[str, typing.Any] | None = None
        self._token: TokenResponse | None = None

    @property
    def provider(self) -> IdpProvider:
        return self.resolved.provider

    @property
    def platform_url(self) -> str:
        return os.environ.get("PLATFORMURL", "http://localhost:8080")

    @property
    def discovery(self) -> DiscoveryDocument:
        if self._discovery is None:
            self._discovery = fetch_discovery(self.provider.issuer)
        return self._discovery

    @property
    def jwks(self) -> dict[str, typing.Any]:
        if self._jwks is None:
            self._jwks = fetch_jwks(self.discovery.jwks_uri)
        return self._jwks

    def token(self, *, extra_params: dict[str, str] | None = None) -> TokenResponse:
        """Client-credentials token from the provider.

        The default-grant token is memoized; tokens requested with altered
        grant params (e.g. a wrong audience) are always freshly minted.
        """
        if extra_params is not None:
            return get_client_credentials_token(
                self.discovery.token_endpoint,
                self.provider.client_id,
                self.provider.client_secret,
                extra_params=extra_params,
            )
        if self._token is None or self._token.expired():
            self._token = get_client_credentials_token(
                self.discovery.token_endpoint,
                self.provider.client_id,
                self.provider.client_secret,
                extra_params=dict(self.provider.token_endpoint_params),
            )
        return self._token

    def check_platform_trusts_provider(self) -> None:
        """Guard: skip (fail in strict mode) if the platform isn't set up for this IdP."""
        try:
            response = requests.get(
                f"{self.platform_url}/.well-known/opentdf-configuration", timeout=10
            )
            well_known = response.json() if response.status_code == 200 else {}
        except requests.RequestException:
            return  # platform down; the checks themselves surface the failure
        platform_issuer = well_known.get("platform_issuer")
        if not platform_issuer or platform_issuer == self.provider.issuer:
            return
        msg = (
            f"platform is not configured for IdP {self.provider.name!r}: "
            f"platform_issuer={platform_issuer!r}, "
            f"provider issuer={self.provider.issuer!r}. Render an overlay with "
            "`uv run python -m idp.platform_config` and restart the platform."
        )
        if self.strict:
            pytest.fail(msg)
        pytest.skip(msg)


@pytest.fixture(scope="session")
def idp(request: pytest.FixtureRequest) -> IdpSession:
    resolved = load_provider(typing.cast(str, request.param))
    strict = bool(request.config.getoption("--idp-strict"))
    if not resolved.ready:
        msg = (
            f"IdP provider {resolved.provider.name!r} is missing environment "
            f"secrets: {', '.join(resolved.missing_secrets)}"
        )
        if strict:
            pytest.fail(msg)
        pytest.skip(msg)
    session = IdpSession(resolved, strict)
    session.check_platform_trusts_provider()
    return session

"""Minimal OIDC discovery, JWKS, and token client.

Hand-rolled on `requests` (matching the rest of xtest) so the suite can talk
to any OIDC provider without pulling in an auth library.
"""

import time
from dataclasses import dataclass, field
from typing import Any

import requests

from idp.dpop import DPoPKey, jwt_payload

HTTP_TIMEOUT = 15


@dataclass(frozen=True)
class DiscoveryDocument:
    issuer: str
    jwks_uri: str
    token_endpoint: str
    raw: dict[str, Any]


def fetch_discovery(issuer: str) -> DiscoveryDocument:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        raise AssertionError(f"OIDC discovery request failed for {issuer}: {e}") from e
    assert response.status_code == 200, (
        f"OIDC discovery failed for {issuer}: "
        f"{response.status_code} {response.text[:300]}"
    )
    data = response.json()
    return DiscoveryDocument(
        issuer=data["issuer"],
        jwks_uri=data["jwks_uri"],
        token_endpoint=data["token_endpoint"],
        raw=data,
    )


def fetch_jwks(jwks_uri: str) -> dict[str, Any]:
    try:
        response = requests.get(jwks_uri, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        raise AssertionError(f"JWKS request failed for {jwks_uri}: {e}") from e
    assert response.status_code == 200, (
        f"JWKS fetch failed for {jwks_uri}: "
        f"{response.status_code} {response.text[:300]}"
    )
    return response.json()


@dataclass
class TokenResponse:
    access_token: str
    token_type: str
    raw: dict[str, Any]
    acquired_at: float = field(default_factory=time.time)

    @property
    def payload(self) -> dict[str, Any]:
        return jwt_payload(self.access_token)

    def expired(self, skew: int = 30) -> bool:
        exp = self.payload.get("exp", 0)
        return time.time() > exp - skew


def get_client_credentials_token(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    *,
    extra_params: dict[str, str] | None = None,
    dpop_key: DPoPKey | None = None,
) -> TokenResponse:
    """Client-credentials grant, with optional DPoP proof + nonce retry (RFC 9449)."""
    data = {"grant_type": "client_credentials"}
    data.update(extra_params or {})

    def post(nonce: str | None = None) -> requests.Response:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if dpop_key is not None:
            headers["DPoP"] = dpop_key.sign_dpop_proof(
                htm="POST", htu=token_endpoint, nonce=nonce
            )
        try:
            return requests.post(
                token_endpoint,
                auth=(client_id, client_secret),
                data=data,
                headers=headers,
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as e:
            raise AssertionError(
                f"token request to {token_endpoint} failed: {e}"
            ) from e

    response = post()
    # RFC 9449 nonce challenges may come back as 400 or 401 — retry once with
    # the issued nonce in either case.
    nonce = response.headers.get("DPoP-Nonce")
    if response.status_code in (400, 401) and nonce and dpop_key is not None:
        response = post(nonce)

    assert response.status_code == 200, (
        f"client_credentials grant failed at {token_endpoint}: "
        f"{response.status_code} {response.text[:500]}"
    )
    body = response.json()
    return TokenResponse(
        access_token=body["access_token"],
        token_type=body.get("token_type", ""),
        raw=body,
    )

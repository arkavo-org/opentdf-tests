"""Black-box IdP conformance checks (GitHub discussion opentdf#3327).

Provider-agnostic checks that exercise the platform's auth surface against
any OIDC provider described by a config in idp/providers/. Each check is a
pass/fail/skip with a short reason, so the junit output doubles as a
compatibility matrix.

Run against the local Keycloak (validates the suite itself):

    uv run pytest test_idp_conformance.py -v

Run against an external provider (platform must be configured for it — see
`uv run python -m idp.platform_config --help` and docs/idp-conformance.md):

    uv run pytest test_idp_conformance.py --idp-providers auth0 -v
"""

import filecmp
import json
from pathlib import Path

import pytest
import requests

import tdfs
from fixtures.idp import IdpSession
from idp.dpop import DPoPKey, jwt_header, time_now
from idp.oidc import get_client_credentials_token

pytestmark = pytest.mark.no_audit_logs

LIST_ATTRIBUTES_PATH = "/policy.attributes.AttributesService/ListAttributes"
ERS_CREATE_CHAIN_PATH = (
    "/entityresolution.EntityResolutionService/CreateEntityChainFromJwt"
)

_SDK_PREFERENCE: tuple[tdfs.sdk_type, ...] = ("go", "java", "js")


def _connect_headers() -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Connect-Protocol-Version": "1",
        "Content-Type": "application/json",
    }


def _platform_post(
    idp: IdpSession,
    path: str,
    *,
    access_token: str | None = None,
    auth_scheme: str = "Bearer",
    dpop_proof: str | None = None,
    body: dict | None = None,
) -> requests.Response:
    headers = _connect_headers()
    url = f"{idp.platform_url}{path}"
    if access_token is not None:
        headers["Authorization"] = f"{auth_scheme} {access_token}"
    if dpop_proof is not None:
        headers["DPoP"] = dpop_proof
    return requests.post(url, json=body or {}, headers=headers, timeout=15)


def _token_audiences(payload: dict) -> set[str]:
    aud = payload.get("aud", [])
    return {aud} if isinstance(aud, str) else set(aud)


def _tampered_signature(token: str) -> str:
    header, payload, signature = token.split(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    assert flipped != signature
    return f"{header}.{payload}.{flipped}"


# --- Discovery & JWKS ------------------------------------------------------


def test_discovery_document(idp: IdpSession) -> None:
    """The provider's discovery document is reachable and well-formed."""
    discovery = idp.discovery
    assert discovery.issuer == idp.provider.issuer, (
        f"discovery issuer {discovery.issuer!r} != configured issuer "
        f"{idp.provider.issuer!r} (the platform compares issuer strings exactly)"
    )
    assert discovery.jwks_uri.startswith("https://") or discovery.jwks_uri.startswith(
        "http://"
    )
    assert discovery.token_endpoint.startswith(
        "https://"
    ) or discovery.token_endpoint.startswith("http://")
    grant_types = discovery.raw.get("grant_types_supported")
    if grant_types is not None:
        assert "client_credentials" in grant_types, (
            f"provider does not advertise client_credentials: {grant_types}"
        )


def test_jwks_fetch(idp: IdpSession) -> None:
    """The provider's JWKS is reachable and contains signing keys."""
    keys = idp.jwks.get("keys", [])
    assert keys, "JWKS contains no keys"
    for key in keys:
        assert key.get("kty"), f"JWKS key missing kty: {key}"
        assert key.get("kid"), f"JWKS key missing kid: {key}"


# --- Token acquisition & validation ----------------------------------------


def test_client_credentials_token(idp: IdpSession) -> None:
    """Client-credentials flow produces a token with the expected shape."""
    token = idp.token()
    payload = token.payload
    assert payload.get("iss") == idp.discovery.issuer, (
        f"token iss {payload.get('iss')!r} != discovery issuer {idp.discovery.issuer!r}"
    )
    assert idp.provider.audience in _token_audiences(payload), (
        f"platform audience {idp.provider.audience!r} not in token aud "
        f"{payload.get('aud')!r}"
    )
    assert payload.get("exp", 0) > time_now(), "token already expired"
    assert payload.get("sub"), "token has no sub claim"


def test_platform_accepts_provider_token(idp: IdpSession) -> None:
    """The platform accepts this provider's token on a protected endpoint."""
    response = _platform_post(
        idp, LIST_ATTRIBUTES_PATH, access_token=idp.token().access_token
    )
    assert response.status_code != 401, (
        f"platform rejected a valid token: {response.status_code} {response.text[:300]}"
    )
    # 200 expected; 403 means the token is trusted but casbin denies the call —
    # acceptable for conformance (authN works; authZ is a separate surface).
    assert response.status_code in (200, 403), (
        f"unexpected status: {response.status_code} {response.text[:300]}"
    )


def test_ers_resolves_entity(idp: IdpSession) -> None:
    """ERS resolves the provider token into an entity chain."""
    token = idp.token()
    response = _platform_post(
        idp,
        ERS_CREATE_CHAIN_PATH,
        access_token=token.access_token,
        body={"tokens": [{"id": "t0", "jwt": token.access_token}]},
    )
    assert response.status_code == 200, (
        f"ERS rejected the provider token: {response.status_code} {response.text[:500]}"
    )
    data = response.json()
    chains = data.get("entityChains") or data.get("entity_chains") or []
    assert chains, f"ERS returned no entity chains: {data}"
    if idp.provider.ers.mode == "claims":
        sub = token.payload.get("sub")
        assert sub and sub in json.dumps(data), (
            f"claims-mode ERS response does not reflect token sub {sub!r}"
        )


# --- DPoP -------------------------------------------------------------------


def test_dpop_proof_of_possession(idp: IdpSession) -> None:
    """DPoP-bound token + proof round-trip (capability-gated)."""
    capability = idp.provider.capabilities.dpop
    if capability is None:
        pytest.skip(
            f"DPoP support unknown for {idp.provider.name}; set "
            "capabilities.dpop in idp/providers after a manual check"
        )
    if not capability:
        pytest.skip(f"{idp.provider.name} does not support DPoP")
    pfs = tdfs.get_platform_features()
    pfs.skip_if_unsupported("dpop")

    key = DPoPKey.generate()
    client_id, client_secret = idp.provider.dpop_credentials()
    token = get_client_credentials_token(
        idp.discovery.token_endpoint,
        client_id,
        client_secret,
        extra_params=dict(idp.provider.token_endpoint_params),
        dpop_key=key,
    )
    if token.payload.get("cnf", {}).get("jkt") != key.thumbprint:
        msg = (
            f"{idp.provider.name} issued a {token.token_type!r} token despite a "
            "valid DPoP proof — DPoP binding is not configured for this client "
            f"(capabilities.dpop is true but no cnf.jkt was bound)"
        )
        if idp.strict:
            pytest.fail(msg)
        pytest.skip(msg)

    url = f"{idp.platform_url}{LIST_ATTRIBUTES_PATH}"

    def call(nonce: str | None = None) -> requests.Response:
        proof = key.sign_dpop_proof(
            htm="POST", htu=url, access_token=token.access_token, nonce=nonce
        )
        return _platform_post(
            idp,
            LIST_ATTRIBUTES_PATH,
            access_token=token.access_token,
            auth_scheme="DPoP",
            dpop_proof=proof,
        )

    response = call()
    issued_nonce = response.headers.get("DPoP-Nonce")
    if response.status_code == 401 and issued_nonce:
        response = call(issued_nonce)
    assert response.status_code != 401, (
        f"platform rejected a valid DPoP proof: {response.status_code} "
        f"{response.text[:300]}"
    )


# --- Negative checks ---------------------------------------------------------


def test_wrong_audience_rejected(idp: IdpSession) -> None:
    """A token minted for a different audience must be rejected."""
    if not idp.provider.capabilities.custom_audience:
        pytest.skip(f"{idp.provider.name} cannot mint a custom-audience token")
    wrong = idp.provider.wrong_audience
    assert wrong, "capabilities.custom_audience=true requires wrong_audience"
    params = dict(idp.provider.token_endpoint_params)
    # Auth0-style audience override; providers with other mechanisms should
    # express them via token_endpoint_params templating.
    params["audience"] = wrong
    token = idp.token(extra_params=params)
    assert wrong in _token_audiences(token.payload), (
        f"provider did not mint a wrong-audience token: {token.payload.get('aud')!r}"
    )
    response = _platform_post(
        idp, LIST_ATTRIBUTES_PATH, access_token=token.access_token
    )
    assert response.status_code == 401, (
        f"platform accepted a wrong-audience token: {response.status_code}"
    )


def test_tampered_signature_rejected(idp: IdpSession) -> None:
    """A token with an altered signature must be rejected."""
    token = idp.token()
    tampered = _tampered_signature(token.access_token)
    response = _platform_post(idp, LIST_ATTRIBUTES_PATH, access_token=tampered)
    assert response.status_code == 401, (
        f"platform accepted a tampered token: {response.status_code}"
    )


def test_unknown_signer_rejected(idp: IdpSession) -> None:
    """A well-formed JWT signed by an unknown key (unknown kid) must be rejected.

    Also exercises the platform's JWKS refetch-on-unknown-kid (rotation) path.
    """
    now = time_now()
    forged = DPoPKey.generate().sign(
        {
            "iss": idp.discovery.issuer,
            "aud": idp.provider.audience,
            "sub": "xtest-unknown-signer",
            "iat": now,
            "exp": now + 300,
        }
    )
    assert jwt_header(forged).get("alg") == "RS256"
    response = _platform_post(idp, LIST_ATTRIBUTES_PATH, access_token=forged)
    assert response.status_code == 401, (
        f"platform accepted a token from an unknown signer: {response.status_code}"
    )


def test_expired_token_rejected(idp: IdpSession) -> None:
    """An expired token must be rejected (needs a committed expired token)."""
    expired = idp.provider.expired_token
    if not expired:
        pytest.skip(
            f"no expired_token committed for {idp.provider.name} (mint one, let "
            "it expire, then add it to the provider config — it's safe: it's expired)"
        )
    response = _platform_post(idp, LIST_ATTRIBUTES_PATH, access_token=expired)
    assert response.status_code == 401, (
        f"platform accepted an expired token: {response.status_code}"
    )


# --- End-to-end ---------------------------------------------------------------


def _first_available_sdk() -> tdfs.SDK | None:
    for name in _SDK_PREFERENCE:
        try:
            return tdfs.SDK(name, "main")
        except FileNotFoundError:
            pass
        versions = sorted(tdfs.all_versions_of(name), key=str)
        if versions:
            return versions[0]
    return None


def test_tdf_roundtrip(
    idp: IdpSession,
    pt_file: Path,
    tmp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Encrypt a TDF, decrypt it with a token from this IdP — rewrap must succeed.

    Uses an attribute-free TDF so no entitlement provisioning is needed; the
    check proves the full encrypt → KAS rewrap → decrypt path under this IdP.
    """
    sdk = _first_available_sdk()
    if sdk is None:
        pytest.skip("no SDK CLI installed (sdk/{go,java,js}/dist/main/cli.sh)")
    monkeypatch.setenv("CLIENTID", idp.provider.client_id)
    monkeypatch.setenv("CLIENTSECRET", idp.provider.client_secret)
    ct_file = tmp_dir / f"idp-conformance-{idp.provider.name}-{sdk.sdk}.tdf"
    sdk.encrypt(pt_file, ct_file, mime_type="text/plain", container="tdf")
    assert ct_file.is_file()
    rt_file = tmp_dir / f"idp-conformance-{idp.provider.name}-{sdk.sdk}.untdf"
    sdk.decrypt(ct_file, rt_file, "tdf")
    assert filecmp.cmp(pt_file, rt_file, shallow=False)

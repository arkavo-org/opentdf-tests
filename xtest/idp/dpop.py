"""DPoP (RFC 9449) proof machinery shared by test_dpop.py and the IdP suite.

Extracted verbatim from test_dpop.py (names made public on the move) so both
the Keycloak-specific DPoP tests and the provider-agnostic conformance checks
use one implementation.
"""

import base64
import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_int(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return b64u(value.to_bytes(length, "big"))


def jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise AssertionError("expected access token to be a JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def jwt_header(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise AssertionError("expected access token to be a JWT")
    header = parts[0] + "=" * (-len(parts[0]) % 4)
    return json.loads(base64.urlsafe_b64decode(header))


def sign_jwt(
    private_key: RSAPrivateKey,
    header: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> str:
    header_b64 = b64u(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    )
    payload_b64 = b64u(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{b64u(signature)}"


def time_now() -> int:
    return int(time.time())


@dataclass(frozen=True)
class DPoPKey:
    private_key: RSAPrivateKey
    public_jwk: dict[str, str]

    @classmethod
    def generate(cls) -> DPoPKey:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_numbers = private_key.public_key().public_numbers()
        return cls(
            private_key=private_key,
            public_jwk={
                "kty": "RSA",
                "n": b64u_int(public_numbers.n),
                "e": b64u_int(public_numbers.e),
            },
        )

    @property
    def thumbprint(self) -> str:
        # RFC 7638 canonical member set for RSA public keys.
        canonical = json.dumps(
            {
                "e": self.public_jwk["e"],
                "kty": self.public_jwk["kty"],
                "n": self.public_jwk["n"],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return b64u(hashlib.sha256(canonical).digest())

    @property
    def public_pem(self) -> str:
        return (
            self.private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

    def sign(self, payload: Mapping[str, Any], typ: str = "JWT") -> str:
        return sign_jwt(
            self.private_key,
            {"alg": "RS256", "typ": typ},
            payload,
        )

    def sign_dpop_proof(
        self,
        *,
        htm: str,
        htu: str,
        access_token: str | None = None,
        nonce: str | None = None,
        jti: str | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "htm": htm,
            "htu": htu,
            "iat": int(time_now()),
            "jti": jti or str(uuid.uuid4()),
        }
        if access_token is not None:
            payload["ath"] = b64u(hashlib.sha256(access_token.encode("ascii")).digest())
        if nonce is not None:
            payload["nonce"] = nonce
        return sign_jwt(
            self.private_key,
            {
                "alg": "RS256",
                "jwk": self.public_jwk,
                "typ": "dpop+jwt",
            },
            payload,
        )


@dataclass(frozen=True)
class DPoPAccessToken:
    token: str
    key: DPoPKey

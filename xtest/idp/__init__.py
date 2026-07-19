"""Provider-agnostic OIDC/IdP conformance helpers.

Contains the per-provider config schema (idp.provider), a minimal OIDC client
(idp.oidc), DPoP proof machinery (idp.dpop), and the platform config overlay
renderer (idp.platform_config). The checks live in test_idp_conformance.py;
provider configs live in idp/providers/.
"""

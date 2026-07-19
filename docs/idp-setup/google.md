# Google setup for IdP conformance

**Status: stub — the suite skips this provider.**

Google does not support the OAuth `client_credentials` grant for user-less
OIDC; service accounts authenticate with the **JWT-bearer** grant instead,
which `xtest/idp/oidc.py` does not implement yet. `xtest/idp/providers/google.yaml`
exists to track the gap and is skipped until either:

- a JWT-bearer extension to `idp/oidc.py` lands, or
- another supported grant mechanism is identified.

## If you are un-stubbing it

The reserved secret names (already wired into the workflow env block):

- `IDP_GOOGLE_AUDIENCE`
- `IDP_GOOGLE_CLIENT_ID`
- `IDP_GOOGLE_CLIENT_SECRET`

Flip the provider YAML from its stub state (real `audience`, honest
`capabilities`) and follow `docs/idp-conformance.md` — "Adding a new
provider" — for the rest of the checklist.

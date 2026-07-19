# Microsoft Entra ID setup for IdP conformance

One-time tenant setup for the `entra` provider (`xtest/idp/providers/entra.yaml`).

## Tenant objects

1. **"OpenTDF platform" app registration** — this is the audience. Set its
   **Application ID URI** (e.g. `api://opentdf-platform`) and expose an
   **app role** (application permission).
2. **Confidential client app registration** — the client the suite
   authenticates as. Grant it the app role from step 1 (API permissions →
   application permissions → admin consent) and create a **client secret**.
3. The client-credentials token request uses a `.default` scope on the target
   resource (`<App ID URI>/.default`) — already templated in the provider
   config via `IDP_ENTRA_AUDIENCE`.

The issuer is `https://login.microsoftonline.com/<tenant-id>/v2.0` (the v2
endpoint), interpolated from `IDP_ENTRA_TENANT_ID`.

## Secrets

- `IDP_ENTRA_TENANT_ID`
- `IDP_ENTRA_AUDIENCE` — App ID URI (or app client ID) of the platform app registration
- `IDP_ENTRA_CLIENT_ID`
- `IDP_ENTRA_CLIENT_SECRET`

For the wrong-audience negative test, create a second app registration and
request its `.default` scope instead (`custom_audience: true` in the provider
config). Then run per `docs/idp-conformance.md`.

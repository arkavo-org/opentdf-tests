# AWS Cognito setup for IdP conformance

One-time tenant setup for the `cognito` provider (`xtest/idp/providers/cognito.yaml`).

## Tenant objects

1. **User pool** — the issuer is
   `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>` (interpolated
   from the secrets below).
2. **Resource server** on the pool with identifier `opentdf` and a custom
   scope `platform` — the token request asks for scope `opentdf/platform`
   (client-credentials requires a resource server + custom scope).
3. **App client with a client secret** and the **client_credentials** grant
   enabled, authorized for the custom scope.

Cognito access tokens carry `aud` = the app client ID, so the provider config
sets `audience` to `IDP_COGNITO_CLIENT_ID`.

## Secrets

- `IDP_COGNITO_REGION`
- `IDP_COGNITO_USER_POOL_ID`
- `IDP_COGNITO_CLIENT_ID`
- `IDP_COGNITO_CLIENT_SECRET`

Then run per `docs/idp-conformance.md`. Note the pool needs a **Cognito
domain** configured for the token endpoint to be reachable.

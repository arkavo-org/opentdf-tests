# Okta setup for IdP conformance

One-time tenant setup for the `okta` provider (`xtest/idp/providers/okta.yaml`).
An Okta developer-edition tenant (free) is sufficient.

## Tenant objects

1. **Custom authorization server** — use the pre-created `default` custom AS
   (**Security → API → Authorization Servers**), not the org AS: the org AS
   only issues `aud=api://default`. The issuer is
   `https://YOUR_DOMAIN.okta.com/oauth2/default`.
2. On that AS, set the **audience** to `http://localhost:8080`
   (the AS's **Settings** tab) so tokens carry the audience the platform
   expects.
3. **Service app** — **Applications → Applications → Create App Integration**,
   sign-in method **API Services** (client_credentials grant). Copy the client
   ID and client secret.

## Secrets

- `IDP_OKTA_CLIENT_ID`
- `IDP_OKTA_CLIENT_SECRET`

Update the `issuer` placeholder in `okta.yaml` with the real domain, then run
per `docs/idp-conformance.md`. Access-token lifetime is configurable per
auth-server rule (`capabilities.configurable_token_lifetime: true`).

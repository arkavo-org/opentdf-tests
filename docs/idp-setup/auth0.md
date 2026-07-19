# Auth0 setup for IdP conformance

One-time tenant setup for the `auth0` provider (`xtest/idp/providers/auth0.yaml`).
A free-tier Auth0 tenant is sufficient. Budget ~15 minutes.

## 1. Create a tenant

Sign up at <https://auth0.com> and create a tenant. The examples below use
`YOUR_TENANT.us.auth0.com` as the tenant domain — substitute yours.

## 2. Create the platform API

**Applications → APIs → Create API:**

- Name: `OpenTDF platform`
- Identifier: `http://localhost:8080` — this is the `audience` the platform
  expects in the token's `aud` claim. It is an identifier, not a URL the
  platform serves; do not change it to match your deployment hostname.

Auth0 only mints JWT access tokens when an API audience is requested, which is
why the provider config passes `token_endpoint_params.audience`.

## 3. Create the wrong-audience API (negative test)

**Applications → APIs → Create API:**

- Name: `idp-conformance wrong audience`
- Identifier: `https://idp-conformance.invalid/` — deliberately not a real
  service. Tokens minted for this audience must be rejected by the platform
  (`wrong_audience_rejected` check).

## 4. Create the Machine-to-Machine application

**Applications → Applications → Create Application:**

- Type: **Machine to Machine**
- Authorize it on **both** APIs from steps 2 and 3 (the wizard prompts for
  one; add the second under the application's **APIs** tab afterward — toggle
  **Authorized** next to each API; no scopes/permissions are needed).
- Grant type: `client_credentials` (default for M2M apps).

Copy the **Client ID** and **Client Secret**.

## 5. Set the tenant Default Audience (required for SDKs)

Some SDKs request a token **without** an `audience` parameter, and Auth0
refuses those requests with
`access_denied: No audience parameter was provided, and no default audience has been configured`.
Set a tenant-wide default so those requests mint tokens for the platform API:

**Tenant Settings (gear icon) → General → API Authorization Settings →
Default Audience** → `http://localhost:8080` → Save.

## 6. Set the secrets

GitHub Actions (repo **Settings → Secrets and variables → Actions**):

- `IDP_AUTH0_CLIENT_ID`
- `IDP_AUTH0_CLIENT_SECRET`

For local runs, export the same variables in your shell.

## 7. Point the provider config at the tenant

In `xtest/idp/providers/auth0.yaml`, replace the issuer placeholder with the
real tenant domain:

```yaml
issuer: "https://YOUR_TENANT.us.auth0.com/"
```

**Keep the trailing slash.** Auth0 issuers end with `/` and the platform
compares issuer strings exactly — `https://tenant.us.auth0.com` (no slash)
will not match the discovered issuer.

Then flip the provider on:

```yaml
onboarded: true
```

`onboarded: false` keeps the provider out of the nightly matrix even when
secrets exist. No Auth0-side role setup is needed — the platform overlay
maps the M2M token's `gty` claim to the platform admin role automatically
(`platform_overlay.casbin_*` in the provider config).

## 8. Verify manually (optional)

```bash
curl -s https://YOUR_TENANT.us.auth0.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=client_credentials \
  -d client_id="$IDP_AUTH0_CLIENT_ID" \
  -d client_secret="$IDP_AUTH0_CLIENT_SECRET" \
  -d audience=http://localhost:8080 | jq -r .access_token
```

Decode the token (e.g. <https://jwt.io>) and confirm `iss` is
`https://YOUR_TENANT.us.auth0.com/` (trailing slash) and `aud` includes
`http://localhost:8080`.

Then run the suite per `docs/idp-conformance.md` (render the overlay, restart
the platform, `uv run pytest test_idp_conformance.py --idp-providers auth0 -v`).

## Known issues

- **`tdf_roundtrip` xfails with the go SDK** — the SDK attaches an RS256 DPoP
  proof to every token request (no opt-out), which Auth0 rejects
  (`invalid_dpop_proof`). Tracked as
  [arkavo-org/opentdf-platform#25](https://github.com/arkavo-org/opentdf-platform/issues/25);
  the check is marked `known_issues` in the provider config, so it reports as
  xfail (not a failure) and will XPASS once the SDK is fixed.

## Rotation

The M2M client secret does not expire on its own, but rotate it on suspicion
of leakage or when the owner changes:

1. **Applications → your M2M app → Settings → Client Secret → Rotate.**
2. Update the `IDP_AUTH0_CLIENT_SECRET` GitHub secret immediately — the old
   secret stops working at once.
3. The next nightly run validates the new secret; a token-acquisition failure
   there files the `idp-conformance` issue and routes to the provider `owner`.

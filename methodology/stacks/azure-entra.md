# Azure AD / Entra ID token validation

Load when the code uses `login.microsoftonline.com`, `@azure/msal-*`,
`passport-azure-ad`, `microsoft-identity-web`, or a JWKS at
`login.microsoftonline.com/<tenant>/discovery/v2.0/keys`.

Root cause: many apps and Microsoft Graph share the same JWKS, so signature
validity proves nothing. The claim checks below scope a token to your API.

## Claim checks

- **`tid` not validated** → cross-tenant token accepted. Issuer check as
  `sts.windows.net/{any}/` or a `common`/`organizations` authority without
  comparing `tid` to an allowlist → HIGH. `validateIssuer:false` is the classic bug.
- **`aud` not validated** → a Graph token (`aud=00000003-0000-0000-c000-000000000000`)
  or another app's token is accepted. Missing/loose audience on shared JWKS → HIGH.
- **`appid`/`azp` confusion** → public-client token on a confidential-client API,
  or a multi-tenant app accepting non-allowlisted tenants.
- **`scp` vs `roles` confusion** → app-only token (`roles`) hitting an endpoint
  that only checks `scp`, or vice versa. Often admin-level access.
- **v1.0 vs v2.0 token mix** → accepts both but validates only one claim shape.
- **`groups` overage ignored** → user in >150 groups gets `_claim_names.groups`;
  `groups.includes(...)` silently mis-grants.
- **guest (B2B) treated as member** → `userType` ignored.
- **implicit flow still enabled** → tokens in URL fragment (leak via Referer).
- **OBO misuse** → middle tier exchanges token without re-checking `aud`/`scp`.
- **MSAL cache in localStorage** → any XSS steals tokens.

## Confirm

Replay a token you legitimately hold (own free-tier tenant, or a Graph token from
your own browser session) against the API. A 200 where `tid`/`aud` should have
rejected it is the proof. Never use another person's token. Redact tokens.

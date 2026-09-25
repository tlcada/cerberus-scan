# Recon — fingerprint the app & map the attack surface

Do this first, in parallel with the running scanner. A scanner reports lines; a
professional first understands the application — what it is, what it protects,
where untrusted input enters. Everything downstream (which findings matter,
what to hand ZAP) depends on it.

## 1. Fingerprint

Read the entry point / server bootstrap and establish:

- **Framework & version** — Express / NestJS / Next.js / Django / Rails / Spring
  / Go net-http… Framework decides the quirks (Express prototype pollution,
  Next.js middleware bypass, NestJS guard order, Spring SpEL).
- **Auth model** — session cookie / JWT / API key / OAuth-OIDC / mTLS. *Where*
  is it enforced: global middleware, per-route guard, per-resolver?
- **Data stores** — SQL (which engine) / Mongo / DynamoDB / Redis / ORM.
- **External integrations** — S3, email, payment, webhooks, LLM APIs, queues,
  auth brokers. Each is a trust boundary.
- **Dangerous primitives** — `exec`/`spawn`/`eval`, template render with input,
  deserialization, user-path file I/O, raw SQL. Grep these early; they are the
  sinks your traces aim at.

Record the stack as a short list (e.g. `Db.PostgreSQL`, `Language.JavaScript`,
`WS.Nginx`) — this is the `tech` fingerprint you later hand `validate_target`.

**Mobile project?** An IPA/APK/AAB, Xcode project, `build.gradle` +
`AndroidManifest.xml`, or a React Native / Flutter / Expo / Capacitor root is a
separate surface — load `get_methodology("mobile")`. ZAP does not apply to a binary; only
a running backend API is a web target.

## 2. Enumerate every endpoint

Build the complete list before analysis.

    rg "router\.(get|post|put|delete|patch)\(|app\.(get|post|put|delete|patch|use)\("
    rg "@(Get|Post|Put|Delete|Patch)\("            # NestJS / decorators

- **GraphQL** (`graphql|apollo|typeDefs|resolvers|gql`) — one `/graphql` hides
  dozens of operations; read every resolver, check introspection + per-resolver
  authz.
- **WebSocket / SSE** (`ws\.on|socket\.io|EventSource|text/event-stream`) —
  these often skip the HTTP auth middleware entirely. Common blind spot.
- **Queue consumers & webhook receivers** — external input that isn't in the
  route table; find them via the integration grep.
- **Static file serving** (`express\.static|sendFile|res\.download|*-static`) —
  list the served dirs on disk; backups/exports/`.bak` files beside intended
  downloads are findings even though no route declares them.
- **Client-only routes** — SPA hash routes (`/#/score-board`) live in the
  frontend router (`RouterModule.forRoot`, `<Route path=…>`), never in a server
  grep, and often guard admin/debug views only in the UI.

## 3. Mark the high-value targets

Not all endpoints are equal. Flag what an attacker wants:

- anything under `/admin`, `/internal`, `/debug`, `/actuator`
- anything touching money, PII, health data, credentials, tokens
- anything that **writes** (state change) vs merely reads
- anything reachable **before auth** — the pre-auth surface holds the worst
  bugs (auth bypass, registration abuse, password reset)
- anything calling a dangerous primitive from step 1

## 4. Read the high-value files in full

The scanners and class greps steer you to matched lines — that misses any flaw
no pattern covers, and in high-value code that miss is expensive. So for the
files that own the targets above, read them **end to end**. Locate and fully
read every file in these categories (don't stop at the first few):

- **Auth & session:** login, register, verify, password reset, 2FA/OTP, JWT
  issuance & verification.
- **Money & entitlements:** payment, wallet, checkout, order, coupon/discount,
  membership, pricing, balance.
- **Ownership-scoped reads/writes (IDOR):** any handler filtering by an id —
  especially a query keyed on an id from the body/query, not the session.
- **Record creation with client-set fields (mass assignment):**
  `Model.create(req.body)`, any `role`/`isAdmin`/`author`/`price` from input.
- **File serving & upload:** download-by-name, upload parsers, path/extension/
  null-byte checks.
- **Data models:** the User model and anything with password hashing,
  sanitisation, or role defaults.

Keep everything else grep-scoped. The point is to spend the deep read only where
the blast radius is largest.

## 5. Note gaps, don't block

Record missing pieces (no app URL, no test creds, no OpenAPI spec) and proceed
with best-effort assumptions. Never block the scan waiting for information.

## Output — write this block, then carry it forward

Finish recon by producing a concrete threat model in this fixed shape. It is
your worklist for code review and the exact input for `validate_target`, so keep
it structured rather than prose:

    Stack:  <framework + version>, <db>, <auth model>  →  tech: [Db.X, Language.Y]
    Auth:   <where enforced: global mw / per-route guard / per-resolver>
    Endpoints (high-value first):
      METHOD  PATH                 auth?   params / body            why it matters
      POST    /api/login           none    {email,password}         pre-auth, creds
      GET     /api/users/:id       user    :id                      IDOR candidate
      POST    /api/orders          user    {total,items[]}          client-priced
      ...
    High-value files to read in full: <auth.ts, payments.ts, admin/*, ...>
    Gaps: <no runtime URL / no test creds / no OpenAPI>

The endpoint rows are what you hand ZAP in move 4 — method, path, and the
params/body that carry injectable input — so ZAP fuzzes real requests instead of
bare GETs. `tech` scopes ZAP to the right payload families. This structured
output is what makes runtime focused instead of blind.

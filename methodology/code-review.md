# Code review — the manual hunt

This is where you earn the report. Four classes in one guide: injection tracing,
auth & authz, IDOR/BOLA, and business logic. Work them against the high-value
files from recon. Record the `endpoint` and a source-to-sink trace for every
finding you confirm.

Examples below are Node/Express (`req.params`, `req.body`). The trace logic is
identical on every stack — only the idiom changes. Map entry points and sinks
with this table; grep the sink column to find where to start tracing:

    Stack     Untrusted input                    Dangerous sinks (grep these)
    Node/JS   req.params/body/query/headers,     child_process exec/spawn, eval,
              cookies, ctx.request                Function(), vm, `${}` in db.query,
                                                   res.sendFile, fs with req path
    Python    request.args/form/json/files,      os.system, subprocess(shell=True),
              request.headers, flask/django       eval/exec, pickle.loads, yaml.load,
              request.GET/POST                     cursor.execute(f"..."), jinja
                                                   Template(x).render, open(user_path)
    Java      @RequestParam/@RequestBody/         Runtime.exec, ProcessBuilder,
              @PathVariable, HttpServletRequest    Statement (not Prepared), OGNL/SpEL,
                                                   XMLDecoder, ObjectInputStream,
                                                   new File(userPath)
    Go        r.URL.Query(), r.FormValue,         exec.Command, os/exec, text/template
              mux.Vars(r), json.NewDecoder(body)   with input, fmt.Sprintf into db.Query,
                                                   filepath.Join(userPath)
    Ruby      params, request.body,               system/`backticks`/%x, eval,
              cookies, request.headers             Marshal.load, YAML.load, ERB,
                                                   send(userSym), where("...#{x}")
    PHP       $_GET/$_POST/$_REQUEST/$_COOKIE,    system/exec/passthru/shell_exec,
              php://input, $_SERVER headers        eval, unserialize, include $userPath,
                                                   $pdo->query("...$x")

---

## A. Injection & SAST tracing

For every scanner hit tagged with an injection class (SQLi, command, code,
path-traversal, SSRF, XSS, deserialization, SSTI) **and** every dangerous sink
you find by hand, trace input → sink before reporting:

1. Identify the entry point (params/body/query/headers, CLI arg, message, file).
2. Read every middleware/function between entry and handler — does any
   sanitise, validate, or parameterise the value?
3. Follow the calls to the sink (DB query, `res.send`, `exec`/`spawn`, template
   render, filesystem path) — or confirm sanitisation.
4. Document the chain `<expr>  file:line` per hop, mark the sink.
5. If the path crosses into an installed/compiled package, say so — caps
   confidence at "Likely vulnerable", not "Confirmed".

**Classes scanners underweight — sweep by hand:** SSRF; prototype pollution
(`__proto__`/`constructor`); NoSQL injection (`$where`/`$ne`/`$regex`); insecure
deserialization; SSTI; open redirect; mass assignment (`role`/`isAdmin`/`orgId`/
`tenantId`/`permissions` from body); path traversal & zip-slip; weak crypto
(`Math.random()` tokens, MD5/SHA1 passwords, non-constant-time compares); webhook
signature order; ReDoS; **frontend DOM XSS** (Angular `bypassSecurityTrust*`,
`[innerHTML]`, `document.write`, `eval` — route param → sink).

**Pattern hits are leads, not proof:** a `bypassSecurityTrustHtml` on a constant
is safe; a mass-assignment hit only bites if a privileged field exists on the
model. Confirm each by reading the code.

Confidence: static + runtime confirmed → HIGH. Static + traced reachable sink
with no sanitiser → HIGH. Reported but sanitised on the path → suppress, citing
the sanitiser's file:line.

---

## B. Auth & authorization

Auth code is always in scope. Read every JWT verify, login handler, session/cookie
issuer, OAuth/OIDC callback, and protected-route middleware end to end — including
in installed packages (cross the import boundary). An auth file that exists but
was not opened is a bug.

    rg "jwt\.verify|jsonwebtoken|jose|passport\.authenticate|express-jwt|next-auth|iron-session|express-session|bcrypt\.compare|argon2\.verify|/login|/auth/|/oauth/|/callback"

- **JWT verify — read the options literally.** `algorithms` a fixed list (no
  `none`, no wildcard, nothing from the token header); `audience` set and
  matching this API (missing on a shared-JWKS provider → any token from that
  issuer is accepted → HIGH); `issuer` set and specific, not a multi-tenant
  wildcard; expiration enforced.
- **Login.** Rate-limit + lockout; constant-time password compare (never `===`);
  no user-enumeration via response/timing/error text; high-entropy single-use
  reset tokens; lockout not bypassable via `X-Forwarded-For`.
- **Sessions & cookies.** Auth cookies need `httpOnly`, `secure`, `sameSite`,
  scoped domain, `__Host-`/`__Secure-` for sensitive ones. Missing `httpOnly` =
  HIGH. Server-side invalidation on logout/password-change. Session id rotates on
  login (fixation). **No** access/refresh token in `localStorage`/`sessionStorage`
  — grep client code; a token in web storage means any XSS = full token theft,
  report it even though it's client code.
- **OAuth / OIDC.** `state` validated and not reused; OIDC `nonce` bound to
  session; PKCE for public clients; `redirect_uri` matched against an exact
  allowlist (watch suffix-matching, wildcard schemes, trailing-slash
  normalization, `redirect_uri` built from request/DB at call time → token leak);
  refresh-token rotation + reuse detection; `response_type` switches rejected.
- **CORS.** `*` or `origin:true` with credentials, origin reflection without an
  allowlist, an unanchored regex (`/example\.com/` matches `evil.com.example.com.x`),
  or `null` origin allowed — any of these + credentialed requests is a finding.

A missing `audience`/`issuer`/`algorithms` check, a non-constant-time compare, or
a token in web storage is HIGH "Confirmed in code" without a running instance —
quote the file:line.

Provider deep-dives (load only if the stack matches): `get_methodology("azure-entra")`,
`get_methodology("aws")`.

---

## C. IDOR / BOLA (deterministic — don't sample)

This class is unreliable unless you follow the steps exactly.

1. **Enumerate every handler taking a resource id:**

       rg "req\.params\.\w*([iI]d|Uuid|Slug)\b" -l
       rg "req\.(body|query)\.\w*([iI]d|Uuid|userId|orgId|tenantId|accountId)\b" -l

2. **Three yes/no questions per handler (skipping any = bug):**
   - (a) *Ownership source:* is the owning id re-derived from `req.user`/session/
     token inside the handler, or taken from user-controlled input?
   - (b) *Downstream filter:* does the DB/ORM/resolver call include the
     session-derived ownership key in its WHERE/key, or only the user-controlled id?
   - (c) *Sibling diff:* in the same file, if a sibling handler re-derives
     ownership and this one doesn't, that deviation **is** the finding.

   A "no" to (a) or (b), or a deviation in (c), is HIGH "Confirmed in code".
   Quote both handlers with file:line — the deviating one and a correct sibling.

3. **Also check:** body-level IDOR (owning id trusted from body); soft-delete/
   filter bypass (`?includeDeleted=true`); header-forged tenancy (`x-tenant-id`
   overriding a claim); **vertical** IDOR — a low-priv role reaching an
   admin-scoped resource because the guard only checks "is authenticated".

Record the `endpoint` so `validate_target` can probe it. Never mark IDOR HIGH on
suspicion — show the missing check, the runtime proof, or both.

---

## D. Business logic (what no scanner finds)

Not bad syntax — correct code implementing a flawed rule. You find these by
understanding what the app is *supposed* to enforce, then asking "what if I don't
play along?" Work the high-value, state-changing endpoints:

- **Workflow / state-machine bypass.** Can I call step 3 without step 1? Does the
  handler trust a client-supplied `status`/`step`/`stage`, or derive it from
  server state? Try invoking the final action (place order, grant access, issue
  payout) directly, skipping the gates.
- **Value / quantity manipulation.** Negative amounts (refund of -100 credits the
  attacker), zero, huge, fractional cents, integer overflow; price/total sent by
  the client instead of computed server-side; quantity×price mismatch; discount
  stacking.
- **Replay & idempotency.** Can a one-time action (redeem coupon, cast vote, pay)
  be replayed? Is the idempotency key enforced server-side? **Race conditions:**
  concurrent requests at a "check balance then deduct" / "check-then-create" flow
  — TOCTOU between check and act is a double-spend. Reason about the pattern in
  the code.
- **Privilege / role self-escalation.** Can a user set their own `role`/`isAdmin`/
  `permissions`/`orgId` via a profile-update or registration body (mass
  assignment)? Can a low-priv role reach an action gated only in the UI? Invite/
  link flows: can I add myself to another org, or invite myself as admin?
- **Ownership across a workflow.** Create a draft under my account, then transfer/
  submit it referencing another user's parent object — each call passes its own
  check but the chain crosses a boundary.
- **Enumeration & disclosure by design.** Sequential ids leak volume; different
  responses/timing for "user exists" vs not; verbose errors, stack traces, debug
  endpoints.
- **Rate limiting & abuse.** Login, reset, OTP, signup, expensive queries — is
  there a per-account **and** per-IP limit? Can `X-Forwarded-For` rotation bypass
  it? Can lockout be weaponised to DoS a victim account?

**The heart of it — trust boundaries.** List every place the code trusts
something it shouldn't (a client-supplied id, header, price, role, tenant,
status, `x-internal: true`). Each is a candidate finding. Quote the line where
the trust happens and where the value *should* have come from (session, config,
recomputation). These are often the highest-impact findings in the report — a pro
weights them accordingly. Report them as: "handler X trusts client field Y; the
correct source is Z; therefore attacker sends Y=<value> and gets <impact>."

---

## E. Stack-specific classes (check the ones present)

Load these only when the app has the surface. Each is high-value and easy to
miss because it hides behind a single endpoint or a framework feature.

**GraphQL** (a schema, `/graphql`, Apollo/Yoga/graphql-js). One endpoint fronts
every operation, so per-resolver authz and cost control are the whole game.
- Authz **per resolver**, not just at `/graphql`: a mutation that skips the
  ownership check is IDOR even if the query above it is guarded (see §C).
- Introspection enabled in prod leaks the full schema (`__schema`).
- Batching / aliasing abuse: one request with 1000 aliased `login(...)` calls
  bypasses per-request rate limits — check for query cost/depth limits.
- Deeply nested queries (`a{b{a{b…}}}`) with no depth cap = DoS.
- Field-level leaks: a `User` type exposing `passwordHash`/`email` to peers.

**File upload** (`multer`, `FileField`, `MultipartFile`, S3 put from a handler).
- Type checked by `Content-Type`/extension only (both client-controlled), not by
  content sniffing — lets an attacker upload a `.php`/`.jsp`/`.svg`.
- Upload dir served executable, or path built from the client filename
  (`uploads/` + name → traversal / overwrite).
- SVG stored and served inline = stored XSS; polyglot files (valid image +
  script) bypass naive checks.
- Image/archive parsers: zip-slip on extract, decompression bombs, ImageMagick/
  ffmpeg on user files (`-` coder / SSRF).

**LLM / prompt injection** (app calls an LLM API — OpenAI/Anthropic/Bedrock/
local). Treat model output as untrusted, and any place user text joins the
prompt as an injection point.
- Untrusted content (a web page, a doc, an email the app summarises) can carry
  instructions that redirect the model — data reaching the prompt is a trust
  boundary.
- Model output flowing into a sink is the real bug: output → `eval`/`exec`,
  output → SQL, output → a tool/function call, output → `res.send` (XSS).
- Over-scoped tools: an agent with a shell/DB/email tool and no allowlist turns
  prompt injection into RCE/exfil. Check what the tools can do and who gates them.
- Secrets in the system prompt, or per-user data crossing into another user's
  context (shared memory/history).

**HTTP request smuggling / cache poisoning** (a proxy/CDN/load-balancer in front,
or a shared cache). Mostly a deployment-config finding, but flag it from code:
- Reverse proxy + backend that disagree on `Content-Length` vs
  `Transfer-Encoding` framing → smuggling.
- Unkeyed input reflected into a cacheable response (an `X-Forwarded-Host` used
  to build an absolute URL, then cached) → cache poisoning.
- User-controlled `Host`/`X-Forwarded-*` trusted for redirects, links, or
  password-reset URLs.

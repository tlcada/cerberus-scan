# Report template

Fill this in **once** and present it. This is a template, not a test. Match it as
closely as is reasonable, then deliver — do **not** regenerate the report over
and over to satisfy the exact shape, and do not run a validate-and-fix loop. Your
judgement about what belongs in the report is trusted. A clear, honest report
that mostly follows this layout is the goal; pixel-perfect conformance is not.

Plain terminal text — no markdown `**`, `#`, backticks, or tables. Unicode
box-drawing and indentation only.

## What goes in

Report **every** vulnerability you actually confirmed — from any scanner and from
your own review. Don't drop a finding because you judge it intentional, a
known/CTF challenge, "by design", or "not worth fixing" — that call is the
reader's. If a finding is intentional/known, report it and tag it; don't omit it.
Equally, don't keep anything you can't stand behind: every finding needs a real
source-to-sink trace or a runtime proof, or it's labelled "Theoretical /
unverified" or cut. A false positive erodes trust in the whole report.

## Layout

    Risk: <CRITICAL|HIGH|MEDIUM|LOW>  ·  <n> CRITICAL, <n> HIGH, <n> MEDIUM, <n> LOW
    App nature: <one line, only if notable — e.g. "intentionally-vulnerable
                training app; findings below are a validated attack map">
    Verdict: <2-3 lines, factual — what an attacker can actually do>

Then the findings, most severe first. One vulnerability class = one block (don't
bundle XXE + eval + YAML-bomb into one — that hides two of three).

    --- <n>. <short title>  ·  <emoji> <SEVERITY>  ·  <Confidence> ---
      Where:    path/file.ts:42  (endpoint: POST /api/x, if applicable)
      Impact:   <one sentence — scope-level impact>
      Trace:
        1. req.body.x                      routes/x.ts:12
        2. -> svc.handle(x)                services/x.ts:48
        3. -> db.query(`... ${x}`)         db/x.ts:74   <- sink
      Attack:
        1. POST /api/x  body {"x":"' OR 1=1--"}
        2. 200 with full users table (verified against http://localhost:3000)
      Basis:    Static + runtime confirmed.  (or: Static only; runtime needs X.)
      Intentional: <omit if real/unknown; else "known challenge (<name>)" — tag,
                   don't drop>
      Fix:      <one line — the exact change, field names, trusted source>

Emoji + word both required: `🔴 CRITICAL`, `🔴 HIGH`, `🟠 MEDIUM`, `🟡 LOW`.
`Impact:` is mandatory (most-often-dropped field). For an unexecuted proof use
`Attack: Not performed — <reason>`; for a non-code finding `Trace: Not applicable
— <reason>`. Never invent a trace or attack to fill the shape.

**Confidence values:** Confirmed exploitable / Confirmed in code / Likely
vulnerable / Theoretical.

**Severity by class** (starting points, not floors): SQL/NoSQL injection, auth
bypass, JWT forgery, XXE w/ file read, RCE/eval, SSRF, insecure deser → CRITICAL
or HIGH. IDOR/BOLA, stored XSS, path traversal / arbitrary file write → HIGH.
Don't reduce severity just because runtime was unavailable; don't assign CRITICAL
just because a keyword like "SSRF" appears. "Confirmed in code" needs the full
source-to-sink path + guard review; "Confirmed exploitable" needs observed
behaviour.

## Sections after the findings

- **Discovered endpoints** — the list (one line if >30).
- **Tool execution summary** (always) — one line per scanner: `ok <tool> —
  <result>` / `skipped <tool> — <reason>` / `failed <tool> — <reason>`. A
  timeout or partial scan is `failed`/incomplete, never "ok — 0 findings".
- **Runtime validation** (always, one line) — "ZAP active scan completed (N
  alerts)" if it ran, or "NOT PERFORMED (<reason + fix>)" if the image was
  missing / target unreachable / not requested. Never write a manual-only pass as
  though ZAP ran — and if runtime was requested, "ran manual probes instead of
  ZAP" is not a valid outcome: run ZAP (it's a seeded, authenticated background
  job, not a blind crawl) and add manual probes on top. Only a genuine tool
  failure excuses it, and then you state that failure here.
- **Infrastructure, CI & dependency findings** (whenever those scanners returned
  hits) — the code-tracing hunt naturally centres on the app, but the IaC
  (checkov/hadolint), CI (actionlint/zizmor), secret (gitleaks/trufflehog) and
  dependency-CVE (trivy/osv/npm-audit) scanners cover a real surface you must not
  silently drop. You don't have to trace each one, but you must **account for
  them**: at least one grouped finding per class that had hits, stating the count,
  the representative issues (with a file:line example), and a fix direction —
  e.g. "IaC (checkov): 113 findings — public-ingress security groups, unencrypted
  storage; see terraform/…:NN". Filter obvious noise per `secrets-deps-iac.md`,
  but "not reviewed in this pass" is a coverage gap to name here, not a reason to
  omit the class entirely.
- **Coverage** (always) — two honest levels:
    - *Scanners:* the source-file inventory in scope, excluded dirs, failed/
      partial tools.
    - *Deep review:* the files you read in full (auth, payments, admin, traced
      sinks); everything else covered at scanner/grep level. Don't inflate — if
      you read six files closely, say six, not "the whole codebase".
- **Suppressed / informational** (optional) — a scanner hit you dismissed, with
  the reason and file:line of the sanitiser/guard. Unreviewed work is **pending**,
  not suppressed — never file "not independently traced" here; say so under
  Coverage instead.

## Drop entirely

"No findings" sections; attack narratives unless a confirmed HIGH; restating the
threat model; generic OWASP definitions; vague advice; praise; a summary of what
you did. Breadth **and** depth — list every confirmed issue, then add the deep
ones others miss.

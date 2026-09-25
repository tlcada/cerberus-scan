# Secrets, dependency CVEs, IaC & CI/CD

Triage the scanner classes that aren't code-tracing. Read each file in
`.security-scan-output/` with a non-zero count; a missing file means nothing to
scan, not a failure. Keep this fast — the model-value here is reachability and
noise-filtering, not restating tool output.

## Secrets — gitleaks + trufflehog

- gitleaks finds by pattern/entropy. Dedupe working-tree vs git-history; a
  history-only secret is MEDIUM minimum, HIGH if it's a real external credential.
- trufflehog (`--only-verified`) actually tested whether the credential is live —
  a verified hit is HIGH "Confirmed" (it works). A verified secret that gitleaks
  also flagged is the strongest signal.
- **Redact every secret value in the report.**

## Dependency CVEs — trivy + osv-scanner

Two independent databases; the report marks `corroborated: true` when both flag
the same CVE. **Always check reachability before HIGH:** look up the vulnerable
function in the advisory, `rg` for its import + call site, cross package
boundaries, and classify Confirmed / Likely / Not / Unknown reachable.
devDependencies-only with no runtime path → drop.

Cloud deep-dive: `get_methodology("aws")` (only if the code uses the AWS SDK).

## IaC & containers — checkov + hadolint

Root user, `latest` tags, remote `ADD`, `ARG` secrets, unpinned installs,
world-open security groups, public storage. Skip pure style nits.

## CI/CD — actionlint + zizmor

`pull_request_target` checking out PR head, `${{ github.event.* }}` in `run:`,
actions pinned by tag not SHA, missing `permissions:`, prod creds in
`pull_request` builds, dependency confusion.

## Noise — do NOT report

Local dev `.env` placeholders; test/dev-only creds; unused config; devDep-only
CVEs with no reachable path; public-by-design tokens; missing-header findings on
JSON-only APIs.

## Account for every class — don't silently drop

These classes are quick, but they are not optional. For each scanner here that
returned hits, the report gets at least one grouped finding (count + a couple of
representative issues with a file:line + fix), per the report template's
"Infrastructure, CI & dependency findings" section. It's fine to spend little
time and to filter noise aggressively, but omitting a class that had real hits —
or writing "not reviewed in this pass" with nothing else — hides a surface the
reader asked about. Summarise it, even briefly.

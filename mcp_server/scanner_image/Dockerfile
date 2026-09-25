FROM node:20-slim

# opengrep ships a PyInstaller-bundled Python that reads its rule/config files
# with the locale's preferred encoding. Under the default C/POSIX locale that is
# ASCII, so any non-ASCII byte in a rule message (or, for some code paths, a
# scanned file) crashes it with UnicodeDecodeError and it produces NO output —
# which looks like "opengrep unavailable". Force a UTF-8 locale so the config
# reader decodes as UTF-8. (PYTHONUTF8/PYTHONIOENCODING are NOT honoured by the
# frozen interpreter; the locale is.) C.UTF-8 is built into Debian, no locale-gen.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

ARG GITLEAKS_VERSION=8.22.0
ARG TRIVY_VERSION=0.69.3
ARG OPENGREP_VERSION=1.19.0
ARG HADOLINT_VERSION=2.12.0
ARG ACTIONLINT_VERSION=1.7.7
ARG TRUFFLEHOG_VERSION=3.90.8
ARG OSV_VERSION=2.2.3
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates jq python3 python3-pip python3-charset-normalizer \
    && rm -rf /var/lib/apt/lists/*

# Checkov — IaC security scanner (Terraform, CloudFormation, etc.)
RUN pip3 install --no-cache-dir checkov --break-system-packages

# Zizmor — security-focused GitHub Actions auditor
RUN pip3 install --no-cache-dir zizmor --break-system-packages

# Opengrep — fully open source SAST (Semgrep-compatible, no token)
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86") && \
    curl -sSfL "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_${ARCH}" \
    -o /usr/local/bin/opengrep && chmod +x /usr/local/bin/opengrep

# Warm opengrep's bundled-Python cache at BUILD time (it extracts to
# /root/.cache/opengrep on first run) so scans don't pay the extraction cost
# and two parallel opengrep passes never race to extract into the same dir.
RUN opengrep --version >/dev/null 2>&1 || true

# Bundle a real SAST ruleset INTO the image so opengrep runs a broad, offline,
# deterministic pass with NO dependency on the semgrep.dev registry. `--config
# auto` needs network to that registry, which is exactly why the broad pass was
# silently skipping in some environments. run_scanners.py points opengrep at the
# language subdirs that match the target's files (see _bundled_configs()).
RUN git clone --depth 1 https://github.com/semgrep/semgrep-rules /opt/semgrep-rules \
    && rm -rf /opt/semgrep-rules/.git

# Trivy — vulnerability scanner
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "ARM64" || echo "64bit") && \
    curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz" \
    | tar xz -C /usr/local/bin trivy

# osv-scanner — Google OSV database (independent CVE source alongside Trivy)
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSfL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${ARCH}" \
    -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

# Gitleaks — secret detection (pattern/entropy)
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x64") && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz" \
    | tar xz -C /usr/local/bin gitleaks

# TruffleHog — verifies whether detected secrets are live
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSfL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz" \
    | tar xz -C /usr/local/bin trufflehog

# Hadolint — Dockerfile linter
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x86_64") && \
    curl -sSfL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${ARCH}" \
    -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint

# Actionlint — GitHub Actions workflow linter
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSfL "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${ARCH}.tar.gz" \
    | tar xz -C /usr/local/bin actionlint

# Custom Cerberus-Scan opengrep rules for classes the registry "auto" ruleset
# misses (Express mass assignment, JWT alg confusion / alg:none, Angular DOM XSS).
COPY rules/ /rules/
COPY fallback-rules/ /fallback-rules/

COPY run_scanners.py /run/run_scanners.py

# Fingerprint the actual bundled files, including cached images built before
# revision recording. Sorting makes the digest independent of traversal order.
RUN find /opt/semgrep-rules -type f -print0 | sort -z | xargs -0 sha256sum \
    | sha256sum > /opt/semgrep-rules-sha256

WORKDIR /workspace
ENTRYPOINT ["python3", "/run/run_scanners.py"]

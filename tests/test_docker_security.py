"""
Docker and Deployment Security Review
======================================
Target:  mumfordengineering/ — FastAPI + Jinja2 portfolio site on Fly.io
Reviewed: 2026-03-12
Reviewer: security-reviewer agent

SUMMARY
-------
Critical : 0
High     : 3  (uv unpinned, --forwarded-allow-ips *, missing Dockerfile HEALTHCHECK)
Medium   : 4  (base image not distroless, PYTHONDONTWRITEBYTECODE/PYTHONUNBUFFERED absent,
               no SIGTERM handler, pyproject uses >= constraints)
Low      : 2  (appuser has no home dir — acceptable, EXPOSE 8080 not a real risk)
Risk     : MEDIUM — no immediate exploit surface, but supply-chain and proxy-trust issues
            should be tightened before adding any sensitive data handling.

FINDINGS
--------

[HIGH-1] uv installed without version pin — supply-chain risk
  Evidence: Dockerfile line 5: `pip install --no-cache-dir uv`
  Risk:     Any future uv release (including a compromised one) is silently pulled into
            every build. A compromised PyPI uv package could exfiltrate secrets or alter
            the installed dependency tree.
  Fix:      `pip install --no-cache-dir "uv==0.6.x"` (pin exact version, verify hash)
            Alternative: use `astral-sh/setup-uv@v4` (already used in CI) to install uv
            and copy the resulting binary into the builder stage, or use a pre-built uv
            Docker image: `FROM ghcr.io/astral-sh/uv:0.6.x AS uv-bin`.

[HIGH-2] --forwarded-allow-ips * trusts ALL upstream proxy IPs
  Evidence: Dockerfile line 23 CMD: `--forwarded-allow-ips "*"`
  Risk:     Any request can forge X-Forwarded-For, X-Real-IP, and X-Forwarded-Proto
            headers to spoof the client IP or claim HTTPS when the connection is plain
            HTTP.  On Fly.io this is mitigated because the Fly proxy is the only entity
            that can inject these headers before your app receives the request, BUT this
            is undocumented and relies on Fly.io network topology never changing.
            If the app is ever run outside Fly.io (local dev, staging, another cloud),
            the wildcard becomes an open trust hole.
  Fix:      Prefer `--forwarded-allow-ips "10.0.0.0/8"` (Fly.io private network CIDR)
            or set the env var `FORWARDED_ALLOW_IPS` at deploy time so it is
            environment-specific, not baked into the image.

[HIGH-3] No HEALTHCHECK instruction in Dockerfile
  Evidence: Dockerfile has no HEALTHCHECK directive.
  Risk:     If the uvicorn process starts but hangs before accepting connections,
            Docker reports the container healthy and load balancers route traffic to
            it. This is a silent availability failure, not a security failure per se,
            but a hung container may also accumulate open file descriptors or sockets
            that are exploitable in resource-exhaustion scenarios.
  Note:     fly.toml DOES define an HTTP health check on /health. This covers the
            Fly.io deployment path, but the Docker image itself has no self-contained
            health check, so local `docker run` and any non-Fly deployment are blind.
  Fix:
            HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
              CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

[MEDIUM-1] Base image is python:3.12-slim, not distroless or chainguard
  Evidence: Dockerfile lines 1 and 7: `FROM python:3.12-slim`
  Risk:     python:3.12-slim includes a shell (/bin/sh), apt, and many system utilities.
            If an attacker achieves RCE via the application, they have a full shell
            environment and package manager. Distroless/chainguard images contain only
            the runtime and application — no shell, no package manager.
  Fix (upgrade path):
            Replace runtime stage with cgr.dev/chainguard/python:3.12 or
            gcr.io/distroless/python3. Both require copying the .venv as-is, which the
            current multi-stage build already supports. The CMD must use exec form (it
            already does). Note: distroless has no shell so `docker exec` for debugging
            is unavailable — use `docker run --entrypoint sh mumfordengineering:test` only
            against the slim builder stage.
  Priority: Low-medium for a public portfolio site. Raise to HIGH if the site ever
            handles authentication tokens, PII, or payment data.

[MEDIUM-2] PYTHONDONTWRITEBYTECODE and PYTHONUNBUFFERED not set
  Evidence: Dockerfile ENV block (lines 19-20) sets PYTHONPATH and PATH only.
  Risk:     Without PYTHONUNBUFFERED=1, stdout/stderr are buffered. If the process is
            killed (OOM, SIGKILL) before flush, the last log lines are lost — this
            hinders incident response. PYTHONDONTWRITEBYTECODE=1 is a minor concern
            (no .pyc files written to the read-only container FS by an unprivileged
            user), but it avoids unnecessary disk writes.
  Fix:      Add to Dockerfile before CMD:
              ENV PYTHONDONTWRITEBYTECODE=1
              ENV PYTHONUNBUFFERED=1

[MEDIUM-3] No SIGTERM handler — container may not shut down cleanly
  Evidence: CMD starts uvicorn directly; no signal-aware wrapper or --graceful-timeout.
  Risk:     Fly.io sends SIGTERM before stopping a machine. uvicorn handles SIGTERM by
            default (it calls lifespan shutdown hooks), but in-flight requests are not
            guaranteed to complete because the default timeout is platform-dependent.
            If a contact-form POST is mid-flight during deploy, the user sees a 502.
  Fix:      Add `--timeout-graceful-shutdown 10` to the uvicorn CMD args.
            Fly.io's default kill timeout is 5 s; setting 10 s and bumping fly.toml's
            kill_timeout to 15 s gives in-flight requests a clean drain window.

[MEDIUM-4] pyproject.toml uses >= version constraints — reproducibility relies on uv.lock
  Evidence: pyproject.toml lines 7-11: `fastapi>=0.115.0`, `uvicorn[standard]>=0.30.0`, etc.
  Risk:     uv.lock pins all transitive deps, so THIS build is reproducible. The risk is
            procedural: if uv.lock is deleted or regenerated without review, a newer
            version of fastapi or uvicorn with a breaking change or CVE is silently
            adopted. The Dockerfile uses `--frozen` which enforces uv.lock, so the
            runtime image is safe. The CI job `uv sync --all-groups` without `--frozen`
            WILL silently upgrade if uv.lock drifts.
  Fix:      In ci.yml, change `uv sync --all-groups` to `uv sync --all-groups --frozen`
            to fail fast if pyproject.toml diverges from uv.lock.

[LOW-1] appuser created without a home directory
  Evidence: Dockerfile line 16: `adduser --system --no-create-home appuser`
  Assessment: ACCEPTABLE. A portfolio site with no user sessions and no secrets written to
              disk has no need for a home directory. The absence of a home dir is actually
              slightly more secure: no ~/.config, ~/.local, or ~/.cache directories for
              a process to write state into. No remediation required.

[LOW-2] EXPOSE 8080 documents the port but does not enforce anything
  Evidence: Dockerfile line 21: `EXPOSE 8080`
  Assessment: ACCEPTABLE. EXPOSE is documentation only; it does not open the port on the
              host. fly.toml internal_port=8080 is the operative mapping. No remediation
              required. The port is not privileged (<1024) so running as appuser is fine.

CI FINDINGS
-----------

[CI-1] No hardcoded secrets detected
  Evidence: .github/workflows/ci.yml contains no token, key, password, or secret literals.
  Assessment: CLEAN. Fly.io deploy secrets (FLY_API_TOKEN) are not present in ci.yml,
              which means either deploy is manual or the deploy step has not been added yet.
              If a deploy step is added later, use `${{ secrets.FLY_API_TOKEN }}` and
              never log it (add `--quiet` to flyctl commands).

[CI-2] actions/checkout@v4 and astral-sh/setup-uv@v4 use floating major-version tags
  Evidence: ci.yml lines 13, 16: `@v4` (no SHA pin)
  Risk:     A compromised tag repoint on GitHub could execute arbitrary code in the CI
            runner. For a public portfolio this is a low-probability risk. For a repo
            with deploy secrets it is a supply-chain injection path.
  Fix:      Pin to SHA: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`
            This is a LOW priority for a personal portfolio site with no high-value CI
            secrets, but becomes HIGH if FLY_API_TOKEN is added.

.dockerignore ASSESSMENT
------------------------
  Complete for development artifacts: .git, .venv, .env, tests/, .github/, fly.toml,
  __pycache__, *.pyc, .DS_Store, .ruff_cache, .pytest_cache, *.egg-info.
  uv.lock is NOT excluded (line missing from .dockerignore), which is CORRECT — uv.lock
  is required by `uv sync --frozen` in the builder stage.
  No gap identified.

MULTI-STAGE BUILD LEAKAGE ASSESSMENT
-------------------------------------
  Builder stage: copies pyproject.toml, uv.lock, runs uv sync. Result: /app/.venv.
  Runtime stage: copies ONLY /app/.venv, src/, templates/, static/.
  pyproject.toml and uv.lock are NOT copied to the runtime stage (no COPY for them).
  Build tools (pip, uv binary, compile cache) stay in the builder layer.
  Assessment: CLEAN. No build artifacts leak to the runtime image.

SECURITY CHECKLIST
------------------
  [x] No hardcoded secrets in Dockerfile or CI
  [x] Multi-stage build (no build tools in runtime image)
  [x] Non-root user (appuser, UID from --system)
  [x] uv.lock pins all transitive dependencies (--frozen enforced in Dockerfile)
  [x] HTTPS enforced (force_https=true in fly.toml)
  [x] Health check defined in fly.toml
  [x] Minimal EXPOSE (single port, non-privileged)
  [x] .dockerignore excludes credentials, test artifacts, VCS metadata
  [ ] uv not version-pinned in Dockerfile (HIGH-1)
  [ ] --forwarded-allow-ips wildcard (HIGH-2)
  [ ] No HEALTHCHECK in Dockerfile itself (HIGH-3)
  [ ] PYTHONUNBUFFERED not set (MEDIUM-2)
  [ ] No graceful shutdown timeout (MEDIUM-3)
  [ ] CI sync not --frozen (MEDIUM-4)
  [ ] Base image not distroless (MEDIUM-1 — low urgency for portfolio)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
DOCKERFILE = REPO / "Dockerfile"
DOCKERIGNORE = REPO / ".dockerignore"
FLY_TOML = REPO / "fly.toml"
CI_WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
PYPROJECT = REPO / "pyproject.toml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def dockerfile_lines() -> list[str]:
    return DOCKERFILE.read_text().splitlines()


def ci_text() -> str:
    return CI_WORKFLOW.read_text()


def dockerignore_entries() -> set[str]:
    return {line.strip() for line in DOCKERIGNORE.read_text().splitlines() if line.strip()}


# ---------------------------------------------------------------------------
# [HIGH-1] uv version pin
# ---------------------------------------------------------------------------


def test_uv_installed_with_version_pin():
    """
    HIGH-1: uv must be pinned to a specific version to prevent silent supply-chain
    upgrades on every image rebuild.

    Current state: `pip install --no-cache-dir uv` (no pin) — FAILS this test.
    Required fix: `pip install --no-cache-dir "uv==<version>"` in the builder stage.
    """
    install_lines = [ln for ln in dockerfile_lines() if "pip install" in ln and "uv" in ln]
    assert install_lines, "No pip install uv line found in Dockerfile"
    for line in install_lines:
        # Accept "uv==X.Y.Z" (exact) or "uv>=X,<Y" (range) or quoted variants
        assert re.search(r"uv[=><!]+[\d.]", line), (
            f"[HIGH-1] uv not pinned in Dockerfile: {line!r}\n"
            'Fix: pip install --no-cache-dir "uv>=0.6.0,<0.7" or "uv==<version>"'
        )


# ---------------------------------------------------------------------------
# [HIGH-2] --forwarded-allow-ips wildcard
# ---------------------------------------------------------------------------


def test_forwarded_allow_ips_not_hardcoded_wildcard():
    """
    HIGH-2: --forwarded-allow-ips must not have a hardcoded wildcard baked into the
    image. The value should come from an environment variable so it is
    environment-specific (Fly.io can set "*", local dev defaults to empty).
    """
    cmd_lines = [ln for ln in dockerfile_lines() if "forwarded-allow-ips" in ln]
    assert cmd_lines, "No --forwarded-allow-ips found in Dockerfile CMD — verify argument is present"
    for line in cmd_lines:
        # The value should reference an env var (e.g. ${FORWARDED_ALLOW_IPS:-})
        # and NOT contain a literal "*" wildcard
        normalised = line.replace('"', " ").replace(",", " ")
        # Check that the wildcard is not hardcoded (env var reference is fine)
        has_env_ref = "FORWARDED_ALLOW_IPS" in line
        has_literal_wildcard = re.search(r'--forwarded-allow-ips\s+["\']?\*["\']?', normalised)
        if has_literal_wildcard and not has_env_ref:
            pytest.fail(
                "[HIGH-2] --forwarded-allow-ips has hardcoded wildcard '*' in Dockerfile.\n"
                'Fix: use env var: --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-}"'
            )


# ---------------------------------------------------------------------------
# [HIGH-3] HEALTHCHECK in Dockerfile
# ---------------------------------------------------------------------------


def test_dockerfile_has_healthcheck():
    """
    HIGH-3: A HEALTHCHECK instruction in the Dockerfile ensures the container
    self-reports liveness in any execution context, not just Fly.io.

    fly.toml defines an HTTP check on /health — that covers Fly.io only.
    Without a Dockerfile HEALTHCHECK, `docker ps` reports all containers as healthy
    regardless of application state.

    Fix:
        HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \\
          CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"
    """
    has_healthcheck = any("HEALTHCHECK" in ln for ln in dockerfile_lines())
    assert has_healthcheck, (
        "[HIGH-3] Dockerfile has no HEALTHCHECK instruction.\n"
        "fly.toml defines a check, but the image itself is health-check-blind outside Fly.io."
    )


# ---------------------------------------------------------------------------
# [MEDIUM-2] PYTHONUNBUFFERED and PYTHONDONTWRITEBYTECODE
# ---------------------------------------------------------------------------


def test_python_unbuffered_set():
    """
    MEDIUM-2a: PYTHONUNBUFFERED=1 ensures stdout/stderr are flushed immediately.
    Without it, log lines may be lost if the container is killed before buffer flush,
    hindering incident response.
    """
    env_lines = [ln for ln in dockerfile_lines() if ln.strip().startswith("ENV")]
    env_vars = " ".join(env_lines)
    assert "PYTHONUNBUFFERED" in env_vars, (
        "[MEDIUM-2a] PYTHONUNBUFFERED is not set in Dockerfile.\nFix: ENV PYTHONUNBUFFERED=1"
    )


def test_python_dont_write_bytecode_set():
    """
    MEDIUM-2b: PYTHONDONTWRITEBYTECODE=1 prevents writing .pyc files to the container
    filesystem, avoiding unnecessary disk writes in a read-only-ish container.
    """
    env_lines = [ln for ln in dockerfile_lines() if ln.strip().startswith("ENV")]
    env_vars = " ".join(env_lines)
    assert "PYTHONDONTWRITEBYTECODE" in env_vars, (
        "[MEDIUM-2b] PYTHONDONTWRITEBYTECODE is not set in Dockerfile.\nFix: ENV PYTHONDONTWRITEBYTECODE=1"
    )


# ---------------------------------------------------------------------------
# [MEDIUM-3] Graceful shutdown timeout
# ---------------------------------------------------------------------------


def test_uvicorn_has_graceful_shutdown_timeout():
    """
    MEDIUM-3: Fly.io sends SIGTERM before stopping machines. Without
    --timeout-graceful-shutdown, in-flight requests may be dropped mid-response
    during deploys or scaling events.

    Fix: add --timeout-graceful-shutdown 10 to the uvicorn CMD.
    """
    cmd_lines = [ln for ln in dockerfile_lines() if "uvicorn" in ln]
    assert cmd_lines, "No uvicorn CMD found in Dockerfile"
    for line in cmd_lines:
        assert "graceful-shutdown" in line or "timeout-graceful" in line, (
            f"[MEDIUM-3] uvicorn CMD missing --timeout-graceful-shutdown: {line!r}\n"
            "Fix: add --timeout-graceful-shutdown 10 to the CMD args"
        )


# ---------------------------------------------------------------------------
# [MEDIUM-4] CI uses --frozen on uv sync
# ---------------------------------------------------------------------------


def test_ci_uv_sync_uses_frozen():
    """
    MEDIUM-4: CI's `uv sync --all-groups` without --frozen will silently upgrade
    dependencies if uv.lock drifts from pyproject.toml. The Dockerfile correctly
    uses --frozen; CI should match.

    Fix: change `uv sync --all-groups` to `uv sync --all-groups --frozen` in ci.yml.
    """
    text = ci_text()
    # Find all uv sync invocations
    sync_calls = re.findall(r"uv sync[^\n]*", text)
    assert sync_calls, "No 'uv sync' found in ci.yml"
    for call in sync_calls:
        assert "--frozen" in call, (
            f"[MEDIUM-4] CI uv sync missing --frozen: {call!r}\nFix: uv sync --all-groups --frozen"
        )


# ---------------------------------------------------------------------------
# [LOW / PASSING] Checks that should already be green
# ---------------------------------------------------------------------------


def test_no_hardcoded_secrets_in_ci():
    """
    CI-1: No literal secret, token, password, or API key should appear in ci.yml.
    Secrets must be injected via ${{ secrets.NAME }}.
    """
    text = ci_text()
    # Patterns that suggest hardcoded credentials
    forbidden_patterns = [
        r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9+/]{16,}",
        r"(?i)password\s*[:=]\s*['\"][^'\"]{4,}",
        r"(?i)secret\s*[:=]\s*['\"][A-Za-z0-9+/]{16,}",
        r"(?i)token\s*[:=]\s*['\"][A-Za-z0-9._-]{16,}",
    ]
    for pattern in forbidden_patterns:
        matches = re.findall(pattern, text)
        assert not matches, f"[CI-1] Possible hardcoded secret in ci.yml matching {pattern!r}: {matches}"

    # Fly.io token check: literal fly- tokens not injected via ${{ secrets.* }}
    # Remove all ${{ secrets.* }} references first, then check for bare fly- tokens
    text_without_secret_refs = re.sub(r"\$\{\{\s*secrets\.[^}]+\}\}", "", text)
    fly_tokens = re.findall(r"fly-[A-Za-z0-9_-]{20,}", text_without_secret_refs)
    assert not fly_tokens, f"[CI-1] Possible hardcoded Fly.io token in ci.yml: {fly_tokens}"


def test_dockerignore_excludes_env_file():
    """CRITICAL invariant: .env must never be sent to Docker build context."""
    entries = dockerignore_entries()
    assert ".env" in entries, "[CRITICAL] .dockerignore does not exclude .env — credentials could enter build context"


def test_dockerignore_excludes_git():
    """VCS metadata must not be present in the image."""
    entries = dockerignore_entries()
    assert ".git" in entries, "[MEDIUM] .dockerignore does not exclude .git — repository history enters build context"


def test_dockerignore_excludes_venv():
    """Local .venv must not shadow the builder-stage venv."""
    entries = dockerignore_entries()
    assert ".venv" in entries, "[MEDIUM] .dockerignore does not exclude .venv — local venv may override builder venv"


def test_dockerignore_excludes_tests():
    """Test code must not ship in the production image."""
    entries = dockerignore_entries()
    assert "tests/" in entries, "[LOW] .dockerignore does not exclude tests/ — test code ships to production"


def test_uv_lock_not_excluded_from_dockerignore():
    """
    uv.lock must NOT be in .dockerignore. The builder stage uses `uv sync --frozen`
    which requires uv.lock to be present in the build context.
    Excluding it would break the build.
    """
    entries = dockerignore_entries()
    assert "uv.lock" not in entries, (
        "[BUILD-BREAK] uv.lock is in .dockerignore — the builder stage requires it for --frozen sync"
    )


def test_multi_stage_build_no_pyproject_in_runtime():
    """
    Build artifact leakage: pyproject.toml and uv.lock should not be COPY'd into
    the runtime stage. The builder stage needs them; the runtime stage does not.
    Only .venv, src/, templates/, and static/ should be copied to runtime.
    """
    lines = dockerfile_lines()
    # Find the second FROM (runtime stage start line index)
    from_indices = [i for i, ln in enumerate(lines) if ln.strip().startswith("FROM")]
    assert len(from_indices) >= 2, "Expected multi-stage build with at least 2 FROM statements"
    runtime_start = from_indices[1]
    runtime_lines = lines[runtime_start:]

    for line in runtime_lines:
        stripped = line.strip()
        if stripped.startswith("COPY") and "--from=builder" not in stripped:
            # Direct COPY in runtime stage must not include pyproject.toml or uv.lock
            assert "pyproject.toml" not in stripped, f"[MEDIUM] pyproject.toml copied into runtime stage: {line!r}"
            assert "uv.lock" not in stripped, f"[MEDIUM] uv.lock copied into runtime stage: {line!r}"


def test_runtime_runs_as_non_root():
    """
    Non-root user must be set before CMD. appuser is created and set via USER.
    Running as root in a container is a critical security misconfiguration.
    """
    lines = dockerfile_lines()
    from_indices = [i for i, ln in enumerate(lines) if ln.strip().startswith("FROM")]
    runtime_start = from_indices[1]
    runtime_lines = lines[runtime_start:]

    user_lines = [ln for ln in runtime_lines if ln.strip().startswith("USER")]
    assert user_lines, "[CRITICAL] No USER instruction in runtime stage — container runs as root"
    # Ensure USER is not root
    for line in user_lines:
        user_value = line.strip().replace("USER", "").strip()
        assert user_value not in ("root", "0"), f"[CRITICAL] Runtime stage sets USER to root: {line!r}"


def test_force_https_in_fly_toml():
    """Fly.io must enforce HTTPS. force_https=true ensures HTTP is redirected."""
    text = FLY_TOML.read_text()
    assert "force_https = true" in text, (
        "[HIGH] fly.toml missing force_https = true — HTTP traffic not redirected to HTTPS"
    )


def test_fly_toml_has_health_check():
    """fly.toml must define an HTTP health check so Fly.io can detect unhealthy machines."""
    text = FLY_TOML.read_text()
    assert "http_service.checks" in text or "[[http_service.checks]]" in text, (
        "[HIGH] fly.toml has no [[http_service.checks]] block — Fly.io cannot detect unhealthy machines"
    )


def test_no_shell_true_in_app_source():
    """
    Command injection guard: no subprocess.run/Popen/call with shell=True should
    exist in application source. Template-rendered or user-supplied data passed to
    a shell command is a critical RCE vector.
    """
    src_dir = REPO / "src"
    violations = []
    for py_file in src_dir.rglob("*.py"):
        source = py_file.read_text()
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                func_name = ""
                if isinstance(func, ast.Attribute):
                    func_name = func.attr
                elif isinstance(func, ast.Name):
                    func_name = func.id
                if func_name in ("run", "Popen", "call", "check_call", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            violations.append(f"{py_file}:{node.lineno}")
    assert not violations, "[CRITICAL] subprocess calls with shell=True found — command injection risk:\n" + "\n".join(
        violations
    )


def test_no_pickle_in_app_source():
    """
    Insecure deserialization: pickle.loads of any data in the application source
    is a critical RCE vector. JSON must be used instead.
    """
    src_dir = REPO / "src"
    violations = []
    for py_file in src_dir.rglob("*.py"):
        source = py_file.read_text()
        if re.search(r"\bpickle\.loads?\b", source):
            violations.append(str(py_file))
    assert not violations, (
        "[CRITICAL] pickle.loads found in app source — use json.loads for untrusted data:\n" + "\n".join(violations)
    )


def test_no_yaml_unsafe_load_in_app_source():
    """
    Insecure YAML loading: yaml.load() without Loader=yaml.SafeLoader is a critical
    arbitrary code execution vector. yaml.safe_load() must be used instead.
    """
    src_dir = REPO / "src"
    violations = []
    for py_file in src_dir.rglob("*.py"):
        source = py_file.read_text()
        # Match yaml.load( without safe_load
        if re.search(r"\byaml\.load\s*\(", source) and not re.search(r"\byaml\.safe_load\s*\(", source):
            violations.append(str(py_file))
    assert not violations, "[CRITICAL] yaml.load() (unsafe) found in app source — use yaml.safe_load():\n" + "\n".join(
        violations
    )

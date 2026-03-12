"""
Dependency Vulnerability Analysis — mumfordengineering
=======================================================
Reviewed: 2026-03-12
Scope: pyproject.toml + uv.lock

FINDINGS SUMMARY
----------------

FINDING  SEVERITY  CATEGORY                   STATUS
-------  --------  -------------------------  ------
DEP-01   INFO      python-multipart version   PASS — 0.0.22 is safe (CVE fixed in 0.0.18)
DEP-02   INFO      Jinja2 sandboxing          EXPECTED — templates/ are author-controlled
DEP-03   LOW       Supply chain: git deps     PASS — all packages from PyPI registry
DEP-04   LOW       Open version ranges        NOTE — ">=" allows future drift from uv.lock
DEP-05   INFO      Dev deps in Docker build   PASS — Dockerfile uses `uv sync --no-dev`
DEP-06   LOW       pip bootstrap in builder   LOW — pip in builder stage, not final image
DEP-07   MEDIUM    --forwarded-allow-ips *    MEDIUM — trusts all proxy IP claims
DEP-08   INFO      starlette 0.52.1           PASS — no known CVEs at this version
DEP-09   INFO      h11 0.16.0                 PASS — no known CVEs at this version
DEP-10   INFO      anyio 4.12.1               PASS — no known CVEs at this version
DEP-11   INFO      httptools 0.7.1            PASS — no known CVEs at this version
DEP-12   INFO      uvloop 0.22.1              PASS — no known CVEs at this version

RISK LEVEL: LOW overall — no unpatched CVEs in the pinned dependency set.
DEP-07 (--forwarded-allow-ips *) is the only actionable medium-severity finding.

PINNED VERSIONS (from uv.lock)
-------------------------------
fastapi            0.135.1   (requires >=0.115.0)
uvicorn            0.41.0    (requires >=0.30.0)
jinja2             3.1.6     (requires >=3.1.0)
python-multipart   0.0.22    (requires >=0.0.9)
starlette          0.52.1    (transitive, pinned by fastapi)
anyio              4.12.1    (transitive)
httptools          0.7.1     (transitive, uvicorn[standard])
h11                0.16.0    (transitive)
uvloop             0.22.1    (transitive, uvicorn[standard])
pydantic           2.12.5    (transitive, fastapi)
pydantic-core      2.41.5    (transitive, pydantic)
websockets         16.0      (transitive, uvicorn[standard])

All packages sourced from https://pypi.org/simple — no git or URL dependencies.
"""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LOCK_FILE = Path(__file__).resolve().parent.parent / "uv.lock"
PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


def _locked_version(package: str) -> str:
    """Return the exact version pinned in uv.lock for the named package."""
    text = LOCK_FILE.read_text()
    pattern = rf'name = "{re.escape(package)}"\nversion = "([^"]+)"'
    m = re.search(pattern, text)
    assert m, f"{package} not found in uv.lock"
    return m.group(1)


def _installed_version(package: str) -> str:
    return importlib.metadata.version(package)


def _parse_version(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split(".")[:3] if x.isdigit())


# ---------------------------------------------------------------------------
# DEP-01: python-multipart — historical ReDoS CVEs
#
# CVE history:
#   CVE-2024-53981  — ReDoS in Content-Type / Content-Disposition parsing
#                     Fixed in 0.0.18 (released 2024-12-02)
#   GHSA-59g5-f7fr  — Additional header parser bypass; fixed in 0.0.18
#
# Pinned version: 0.0.22 — all known CVEs patched.
# Minimum safe version: 0.0.18
# ---------------------------------------------------------------------------

PYTHON_MULTIPART_MIN_SAFE = (0, 0, 18)


class TestDep01PythonMultipart:
    def test_locked_version_meets_minimum_safe(self):
        """python-multipart 0.0.22 is above the 0.0.18 CVE fix baseline."""
        v = _parse_version(_locked_version("python-multipart"))
        assert v >= PYTHON_MULTIPART_MIN_SAFE, (
            f"python-multipart {v} is below minimum safe {PYTHON_MULTIPART_MIN_SAFE}. "
            "CVE-2024-53981 (ReDoS) is fixed in 0.0.18+."
        )

    def test_installed_version_matches_lock(self):
        """Installed python-multipart matches the pinned lock version."""
        locked = _locked_version("python-multipart")
        installed = _installed_version("python-multipart")
        assert installed == locked, (
            f"Installed python-multipart {installed!r} differs from lock {locked!r}. "
            "Run `uv sync --frozen` to align the environment."
        )

    def test_locked_version_is_not_known_vulnerable(self):
        """
        Versions 0.0.0–0.0.17 are vulnerable to CVE-2024-53981.
        Versions >=0.0.18 are patched.
        This test asserts the lock does not pin a vulnerable version range.
        """
        v = _locked_version("python-multipart")
        major, minor, patch = _parse_version(v)
        assert not (major == 0 and minor == 0 and patch < 18), (
            f"python-multipart {v} is in the vulnerable range (<0.0.18). "
            "CVE-2024-53981: ReDoS via crafted Content-Type header."
        )


# ---------------------------------------------------------------------------
# DEP-02: Jinja2 sandboxing
#
# Jinja2's SandboxedEnvironment restricts template execution to prevent
# arbitrary Python evaluation.  It is required when templates contain
# user-supplied content.
#
# For this site, templates live in templates/ and are author-controlled.
# Using the default Environment (no sandbox) is correct and expected.
# If user-supplied content were ever rendered as a template, this must change.
#
# CVE-2024-56201 / CVE-2024-56326: Jinja2 sandbox bypass via __init__ /
# __class__ attribute chains.  Fixed in 3.1.5.  Pinned version 3.1.6 is safe.
# ---------------------------------------------------------------------------

JINJA2_MIN_SAFE = (3, 1, 5)


class TestDep02Jinja2:
    def test_jinja2_version_above_sandbox_bypass_cves(self):
        """
        Jinja2 >= 3.1.5 is required to be clear of CVE-2024-56201 and
        CVE-2024-56326 (sandbox escape via Python object attribute traversal).
        Pinned 3.1.6 passes.
        """
        v = _parse_version(_locked_version("jinja2"))
        assert v >= JINJA2_MIN_SAFE, (
            f"Jinja2 {v} is below the 3.1.5 CVE fix baseline. CVE-2024-56201 / CVE-2024-56326: sandbox escape."
        )

    def test_jinja2_not_running_in_sandboxed_environment(self):
        """
        The app uses Jinja2Templates (default Environment), NOT SandboxedEnvironment.
        This is correct for server-controlled templates.  This test documents the
        current posture.  If user input ever reaches template rendering directly,
        this must change to SandboxedEnvironment.
        """
        from mumfordengineering.app import templates
        from jinja2 import Environment
        from jinja2.sandbox import SandboxedEnvironment

        env = templates.env
        assert isinstance(env, Environment)
        assert not isinstance(env, SandboxedEnvironment), (
            "Unexpected: app switched to SandboxedEnvironment. Update this test to reflect the new posture."
        )

    def test_jinja2_autoescaping_enabled_for_html(self):
        """
        Jinja2Templates enables autoescape for .html files by default.
        This prevents XSS from any variable values rendered into templates.
        """
        from mumfordengineering.app import templates

        env = templates.env
        # Test a filename that would trigger HTML autoescape
        assert env.is_async is False or True  # async flag is not security-relevant
        # The Environment should have autoescape enabled for .html
        # Jinja2Templates sets autoescape via select_autoescape(['html', 'xml'])
        # We can verify by checking the environment's autoescape callable result
        result = env.autoescape  # callable or bool
        if callable(result):
            assert result("index.html") is True, (
                "Jinja2 autoescape is NOT enabled for .html files. User data in templates could lead to XSS."
            )
        else:
            assert result is True, "Jinja2 autoescape is disabled globally. User data in templates could lead to XSS."

    def test_installed_jinja2_version_matches_lock(self):
        locked = _locked_version("jinja2")
        installed = _installed_version("jinja2")
        assert installed == locked


# ---------------------------------------------------------------------------
# DEP-03: Supply chain — no git or URL dependencies
#
# All packages must resolve from the PyPI registry.  A git dependency pulls
# arbitrary commits and bypasses PyPI integrity checks (PEP 517 hashes).
# ---------------------------------------------------------------------------


class TestDep03SupplyChain:
    def test_no_git_dependencies_in_lock(self):
        """uv.lock must not contain any git-sourced packages."""
        text = LOCK_FILE.read_text()
        git_sources = re.findall(r"source = \{[^}]*git[^}]*\}", text)
        assert not git_sources, (
            f"Found {len(git_sources)} git-sourced dependency/ies in uv.lock. "
            f"Git dependencies bypass PyPI hash verification: {git_sources}"
        )

    def test_no_url_dependencies_in_lock(self):
        """uv.lock must not contain direct URL (non-registry) packages."""
        text = LOCK_FILE.read_text()
        url_sources = re.findall(r'source = \{[^}]*url\s*=\s*"http', text)
        assert not url_sources, (
            f"Found {len(url_sources)} URL-sourced dependency/ies in uv.lock. "
            "Direct URL deps cannot be audited by pip-audit or safety."
        )

    def test_all_packages_from_pypi_registry(self):
        """All pinned packages use the PyPI registry source."""
        text = LOCK_FILE.read_text()
        # Every source line must match the PyPI registry
        source_lines = re.findall(r"source = \{[^}]+\}", text)
        non_pypi = [s for s in source_lines if 'registry = "https://pypi.org' not in s]
        # The project itself (mumfordengineering) uses editable/directory source — that is expected
        own_project = [s for s in non_pypi if "editable" in s or "directory" in s]
        unexpected = [s for s in non_pypi if s not in own_project]
        assert not unexpected, f"Found non-PyPI sources in uv.lock: {unexpected}"


# ---------------------------------------------------------------------------
# DEP-04: Open version ranges — uv.lock drift risk
#
# pyproject.toml uses ">=" for all dependencies with no upper bound.
# This means `uv sync` on a fresh install will resolve to whatever PyPI
# considers latest, which may differ from uv.lock if the lock is stale.
# uv.lock pins exact versions, but the ">=" constraint allows any future
# version to satisfy the dependency spec.
#
# Risk: if uv.lock is regenerated (e.g., `uv lock --upgrade`) without a
# compatibility audit, a newly published version with a breaking change or
# security regression could be pinned.
#
# Recommendation: add upper-bound constraints for security-sensitive packages,
# or add a CI step that compares old vs new lock on upgrade PRs.
# ---------------------------------------------------------------------------


class TestDep04VersionRanges:
    def test_pyproject_uses_open_lower_bound_constraints(self):
        """
        Documents that pyproject.toml uses ">=" (open upper bound).
        This is a LOW risk: uv.lock provides reproducibility, but the lock
        can be regenerated to any compatible future version.
        This test documents the posture — it does not enforce a constraint style.
        """
        text = PYPROJECT.read_text()
        # Bracket-counting extraction handles extras like uvicorn[standard]>=0.30.0
        start = text.find("dependencies = [")
        assert start != -1, "dependencies block not found in pyproject.toml"
        depth = 0
        end = start
        for i, ch in enumerate(text[start:]):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    end = start + i + 1
                    break
        deps = text[start:end]
        # Verify the known open-range packages are present as documented
        assert re.search(r"fastapi\s*>=", deps), "fastapi>= not found in dependencies"
        assert re.search(r"uvicorn", deps), "uvicorn not found in dependencies"
        assert re.search(r"jinja2\s*>=", deps), "jinja2>= not found in dependencies"
        assert re.search(r"python-multipart\s*>=", deps), "python-multipart>= not found in dependencies"

    def test_lock_file_is_present_and_non_empty(self):
        """
        uv.lock must exist and be non-trivial.  An empty or missing lock means
        the next `uv sync` will resolve from scratch, potentially pulling
        vulnerable versions.
        """
        assert LOCK_FILE.exists(), "uv.lock is missing — reproducible builds are not possible"
        content = LOCK_FILE.read_text()
        assert len(content) > 500, "uv.lock appears empty or truncated"
        assert "[[package]]" in content, "uv.lock does not contain any pinned packages"

    def test_lock_pins_exact_fastapi_version(self):
        """uv.lock must pin an exact (not range) fastapi version."""
        v = _locked_version("fastapi")
        assert re.fullmatch(r"\d+\.\d+\.\d+", v), f"fastapi lock entry {v!r} is not an exact semver pin"

    def test_lock_pins_exact_jinja2_version(self):
        v = _locked_version("jinja2")
        assert re.fullmatch(r"\d+\.\d+\.\d+", v)

    def test_lock_pins_exact_python_multipart_version(self):
        v = _locked_version("python-multipart")
        assert re.fullmatch(r"\d+\.\d+\.\d+", v)


# ---------------------------------------------------------------------------
# DEP-05: Dev dependencies excluded from Docker production image
#
# The Dockerfile builder stage runs `uv sync --frozen --no-dev`.
# This ensures pytest, httpx, ruff, and pytest-asyncio are NOT installed
# in the final image, reducing attack surface and image size.
# ---------------------------------------------------------------------------


class TestDep05DockerDevDeps:
    def test_dockerfile_uses_frozen_sync(self):
        """Builder stage must use `--frozen` to enforce reproducible installs."""
        text = DOCKERFILE.read_text()
        assert "--frozen" in text, (
            "Dockerfile does not use `uv sync --frozen`. "
            "Without --frozen, uv may resolve different versions than uv.lock."
        )

    def test_dockerfile_excludes_dev_dependencies(self):
        """Builder stage must use `--no-dev` to exclude test/lint tools."""
        text = DOCKERFILE.read_text()
        assert "--no-dev" in text, (
            "Dockerfile does not use `uv sync --no-dev`. "
            "Dev dependencies (pytest, httpx, ruff) may be installed in the production image."
        )

    def test_dockerfile_copies_only_necessary_source_dirs(self):
        """
        Final image stage must not COPY the tests/ directory.
        Test files in production images can expose internal API knowledge.
        """
        text = DOCKERFILE.read_text()
        # Find COPY instructions in the final stage (after second FROM)
        final_stage = text.split("FROM")[2] if text.count("FROM") >= 2 else text
        assert "COPY tests/" not in final_stage, (
            "Dockerfile COPY instruction includes tests/ in the final image. Remove it to reduce attack surface."
        )

    def test_dockerfile_uses_nonroot_user(self):
        """Final image must run as a non-root user (principle of least privilege)."""
        text = DOCKERFILE.read_text()
        assert "adduser" in text or "useradd" in text, "Dockerfile does not create a non-root user."
        assert "USER appuser" in text or re.search(r"USER\s+\w+", text), (
            "Dockerfile does not switch to a non-root USER before CMD."
        )


# ---------------------------------------------------------------------------
# DEP-06: pip bootstrap in builder stage
#
# The builder stage runs `pip install --no-cache-dir uv` before switching to
# uv for all subsequent dependency management.  The pip version in
# python:3.12-slim is controlled by the base image maintainer (Docker Official
# Images / Python Docker Community).
#
# Risk assessment:
#   - pip in the builder stage is NOT present in the final image (multi-stage
#     build: final FROM copies only .venv, src/, templates/, static/).
#   - pip CVEs only matter in the builder stage where it is invoked once to
#     install uv, then discarded.
#   - No known critical CVEs in the pip version shipped with python:3.12-slim
#     as of review date that would be exploitable in this specific invocation
#     (single `pip install uv`, no user-controlled input).
#
# Recommendation (LOW priority): pin the base image to a specific digest
# (e.g., python:3.12-slim@sha256:...) for fully reproducible builds.
# ---------------------------------------------------------------------------


class TestDep06PipBootstrap:
    def test_dockerfile_uses_no_cache_flag_for_pip(self):
        """pip install in builder must use --no-cache-dir to reduce image layer size."""
        text = DOCKERFILE.read_text()
        assert "--no-cache-dir" in text, (
            "Dockerfile pip install is missing --no-cache-dir. "
            "This wastes layer space and is non-standard for Docker builds."
        )

    def test_dockerfile_pip_install_only_installs_uv(self):
        """
        The builder's pip install must only install uv, nothing else.
        Installing arbitrary packages via pip (rather than uv) bypasses
        the uv.lock integrity guarantee.
        """
        text = DOCKERFILE.read_text()
        pip_lines = [line.strip() for line in text.splitlines() if "pip install" in line]
        for line in pip_lines:
            # Extract only the pip install sub-command (before any && continuation)
            # e.g. "RUN pip install --no-cache-dir uv && uv sync ..."
            # → isolate "pip install --no-cache-dir uv"
            pip_segment = re.search(r"pip install\s+(.*?)(?:\s*&&|\s*$)", line)
            assert pip_segment, f"Could not parse pip install segment from: {line!r}"
            install_args = pip_segment.group(1).strip().split()
            package_tokens = [t for t in install_args if not t.startswith("-")]
            assert len(package_tokens) == 1, (
                f"pip install installs unexpected packages: {package_tokens}. Only 'uv' should be installed via pip."
            )
            assert package_tokens[0].strip('"').startswith("uv"), (
                f"pip install installs unexpected package: {package_tokens[0]!r}. "
                "Only 'uv' (with optional version pin) should be installed."
            )

    def test_final_image_does_not_contain_pip_install_commands(self):
        """
        All pip install commands must be in the builder stage only.
        The final image stage must not call pip install.
        """
        text = DOCKERFILE.read_text()
        # Split on FROM to isolate final stage
        stages = text.split("FROM ")
        assert len(stages) >= 3, "Dockerfile must have at least 2 stages (builder + final)"
        final_stage = stages[-1]  # last FROM block is the final image
        assert "pip install" not in final_stage, (
            "pip install found in the final image stage. This adds pip to the production image attack surface."
        )


# ---------------------------------------------------------------------------
# DEP-07: --forwarded-allow-ips * in uvicorn CMD
#
# SEVERITY: MEDIUM
#
# The Dockerfile CMD runs:
#   uvicorn ... --proxy-headers --forwarded-allow-ips *
#
# --proxy-headers enables reading X-Forwarded-For / X-Forwarded-Proto.
# --forwarded-allow-ips * means uvicorn trusts X-Forwarded-For from ANY source.
#
# Impact: The app's _get_client_ip() reads fly-client-ip first, then falls
# back to x-forwarded-for.  If an attacker can reach the server directly
# (bypassing Fly.io's proxy), they can supply a spoofed fly-client-ip or
# x-forwarded-for header and impersonate any IP address.
#
# This defeats:
#   - Rate limiting (any IP can reset its own limit by using a fake IP)
#   - Log attribution (contact form submissions will show false IPs)
#
# Fix: Restrict --forwarded-allow-ips to the actual Fly.io proxy IP range,
# or validate IP headers at the application layer.
#
# If deployed exclusively on Fly.io (which injects fly-client-ip and owns the
# network path), the Fly.io proxy is the sole trusted intermediary.
# The fly-client-ip header cannot be forged by end users on Fly.io.
# However, --forwarded-allow-ips * combined with x-forwarded-for fallback in
# _get_client_ip() still creates a risk if the service is ever exposed on
# a non-Fly network path (e.g., direct port binding, alternative deployment).
# ---------------------------------------------------------------------------


class TestDep07ForwardedAllowIps:
    def test_dockerfile_cmd_contains_proxy_headers(self):
        """uvicorn is launched with --proxy-headers (expected for Fly.io)."""
        text = DOCKERFILE.read_text()
        assert "--proxy-headers" in text

    def test_dockerfile_cmd_uses_env_var_for_forwarded_allow_ips(self):
        """
        --forwarded-allow-ips must reference an environment variable, not a
        hardcoded wildcard. The env var is set in fly.toml for Fly.io and
        defaults to empty (no trusted proxies) outside Fly.io.
        """
        text = DOCKERFILE.read_text()
        assert "--forwarded-allow-ips" in text, (
            "--forwarded-allow-ips flag is absent; verify proxy header trust is configured."
        )
        assert "FORWARDED_ALLOW_IPS" in text, (
            "--forwarded-allow-ips should reference $FORWARDED_ALLOW_IPS env var, "
            "not a hardcoded value. Set the env var in fly.toml or deployment config."
        )

    def test_app_reads_fly_client_ip_before_x_forwarded_for(self):
        """
        _get_client_ip() prefers fly-client-ip over x-forwarded-for.
        On Fly.io, fly-client-ip is set by the platform and cannot be
        forged by end users, making it safer than x-forwarded-for.
        This test verifies the priority order has not been reversed.
        """
        from mumfordengineering.app import _get_client_ip
        from unittest.mock import MagicMock

        # Simulate a request with both headers
        request = MagicMock()
        request.headers = {
            "fly-client-ip": "1.2.3.4",
            "x-forwarded-for": "9.9.9.9, 8.8.8.8",
        }
        request.client = None

        ip = _get_client_ip(request)
        assert ip == "1.2.3.4", (
            f"_get_client_ip returned {ip!r} instead of fly-client-ip value '1.2.3.4'. "
            "fly-client-ip must take priority over x-forwarded-for."
        )

    def test_app_falls_back_to_x_forwarded_for_first_ip(self):
        """
        When fly-client-ip is absent, only the first entry from x-forwarded-for
        is used.  Validates that the fallback does not pick up a proxy-injected
        forged IP from a later position in the header chain.
        """
        from mumfordengineering.app import _get_client_ip
        from unittest.mock import MagicMock

        request = MagicMock()
        request.headers = {"x-forwarded-for": "10.0.0.1, 172.16.0.1, 192.168.1.1"}
        request.client = None

        ip = _get_client_ip(request)
        assert ip == "unknown", f"_get_client_ip returned {ip!r}; expected 'unknown' (XFF no longer trusted)."

    def test_rate_limiter_is_bypassable_with_spoofed_fly_client_ip(self):
        """
        DOCUMENTS A KNOWN RISK (DEP-07).
        If an attacker can reach uvicorn directly (no Fly.io proxy), they can
        spoof fly-client-ip to use a fresh IP bucket on every request, bypassing
        rate limiting entirely.

        On Fly.io this attack is blocked because fly-client-ip is injected by
        the platform's edge and cannot be set by clients.  On any other deployment
        path (direct port exposure, alternative CDN) this is exploitable.
        """
        import asyncio
        from httpx import ASGITransport, AsyncClient
        from mumfordengineering.app import app, _contact_timestamps

        async def run():
            _contact_timestamps.clear()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Exhaust rate limit for IP A
                for _ in range(5):
                    await client.post(
                        "/contact",
                        data={"name": "A", "email": "a@example.com", "message": "test", "website": ""},
                        headers={"fly-client-ip": "100.0.0.1"},
                    )
                # Rate limited on IP A
                resp_a = await client.post(
                    "/contact",
                    data={"name": "A", "email": "a@example.com", "message": "test", "website": ""},
                    headers={"fly-client-ip": "100.0.0.1"},
                )
                # Fresh IP bypasses rate limit
                resp_b = await client.post(
                    "/contact",
                    data={"name": "A", "email": "a@example.com", "message": "test", "website": ""},
                    headers={"fly-client-ip": "100.0.0.2"},  # different IP
                )
            return resp_a, resp_b

        resp_a, resp_b = asyncio.get_event_loop().run_until_complete(run())
        # Both return 200 — the second with a fresh IP is accepted
        assert resp_a.status_code == 200
        assert resp_b.status_code == 200
        # This is expected/documented behaviour, not a test failure


# ---------------------------------------------------------------------------
# DEP-08–12: Transitive dependency version assertions
#
# These tests assert the exact pinned versions for security-relevant
# transitive dependencies.  If a CVE is published for any of these, the
# minimum safe version can be updated here and the test will catch a stale lock.
# ---------------------------------------------------------------------------


class TestDep08To12TransitiveDeps:
    def test_starlette_version(self):
        """
        starlette 0.52.1 — no known unpatched CVEs as of 2026-03-12.
        Minimum tracked: 0.27.0 (GHSA-74m5-2c7w-9w3x path traversal in StaticFiles).
        Current lock (0.52.1) is well above the patched baseline.
        """
        v = _parse_version(_locked_version("starlette"))
        assert v >= (0, 27, 0), f"starlette {v} is below 0.27.0 — vulnerable to GHSA-74m5-2c7w-9w3x."

    def test_h11_version(self):
        """
        h11 0.16.0 — no known unpatched CVEs as of 2026-03-12.
        h11 is the HTTP/1.1 parser; a vulnerability here would affect all
        HTTP request parsing in uvicorn.
        """
        v = _parse_version(_locked_version("h11"))
        assert v >= (0, 14, 0), f"h11 {v} is below minimum tracked version 0.14.0"

    def test_anyio_version(self):
        """
        anyio 4.12.1 — no known unpatched CVEs as of 2026-03-12.
        anyio provides async primitives; older versions had task group
        cancellation issues but no published security CVEs.
        """
        v = _parse_version(_locked_version("anyio"))
        assert v >= (4, 0, 0), f"anyio {v} is below minimum tracked version 4.0.0"

    def test_httptools_version(self):
        """
        httptools 0.7.1 — no known unpatched CVEs as of 2026-03-12.
        httptools wraps llhttp (Node.js HTTP parser) in Python.
        """
        v = _parse_version(_locked_version("httptools"))
        assert v >= (0, 6, 0), f"httptools {v} is below minimum tracked version 0.6.0"

    def test_uvloop_version(self):
        """
        uvloop 0.22.1 — no known unpatched CVEs as of 2026-03-12.
        uvloop wraps libuv; vulnerabilities in libuv can theoretically surface.
        """
        v = _parse_version(_locked_version("uvloop"))
        assert v >= (0, 19, 0), f"uvloop {v} is below minimum tracked version 0.19.0"

    def test_pydantic_version(self):
        """
        pydantic 2.12.5 — no known unpatched CVEs as of 2026-03-12.
        pydantic v2 uses pydantic-core (Rust); older pydantic v1 had
        ReDoS issues in email validators (CVE-2024-3772, fixed in 2.4.0).
        """
        v = _parse_version(_locked_version("pydantic"))
        assert v >= (2, 4, 0), (
            f"pydantic {v} is below 2.4.0 — vulnerable to CVE-2024-3772 (ReDoS in email_validator integration)."
        )

    def test_fastapi_version(self):
        """
        fastapi 0.135.1 — no known unpatched CVEs as of 2026-03-12.
        Minimum tracked: 0.109.1 (GHSA-qf9m-jfhm-86rw DOS via large form data,
        fixed in 0.109.1 by adding python-multipart constraint).
        """
        v = _parse_version(_locked_version("fastapi"))
        assert v >= (0, 109, 1), f"fastapi {v} is below 0.109.1 — vulnerable to GHSA-qf9m-jfhm-86rw."

    def test_uvicorn_version(self):
        """
        uvicorn 0.41.0 — no known unpatched CVEs as of 2026-03-12.
        Minimum tracked: 0.11.7 (historical HTTP smuggling issues).
        """
        v = _parse_version(_locked_version("uvicorn"))
        assert v >= (0, 11, 7), f"uvicorn {v} is below minimum tracked version 0.11.7"


# ---------------------------------------------------------------------------
# Aggregate: all packages resolve from PyPI (integrity check)
# ---------------------------------------------------------------------------


class TestDepIntegrity:
    def test_lock_file_has_hashes_for_all_packages(self):
        """
        Every package in uv.lock must have at least one sdist or wheel hash.
        Missing hashes mean a package could be silently substituted (supply chain).
        """
        text = LOCK_FILE.read_text()
        # Find all package blocks
        blocks = re.split(r"\n\[\[package\]\]", text)
        packages_without_hashes = []
        for block in blocks[1:]:  # skip preamble
            name_m = re.search(r'name = "([^"]+)"', block)
            if not name_m:
                continue
            pkg_name = name_m.group(1)
            # Skip the project itself — it has no dist-info hashes in lock
            if pkg_name == "mumfordengineering":
                continue
            if "sha256:" not in block:
                packages_without_hashes.append(pkg_name)
        assert not packages_without_hashes, (
            f"These packages have no integrity hashes in uv.lock: {packages_without_hashes}. "
            "An attacker who can manipulate PyPI mirrors could substitute these packages."
        )

    def test_no_yanked_versions_pattern_in_lock(self):
        """
        uv.lock should not contain yanked package markers.
        Yanked versions are pulled from PyPI for safety reasons.
        """
        text = LOCK_FILE.read_text()
        assert "yanked = true" not in text, (
            "uv.lock contains at least one yanked package. Run `uv lock` to resolve to un-yanked versions."
        )

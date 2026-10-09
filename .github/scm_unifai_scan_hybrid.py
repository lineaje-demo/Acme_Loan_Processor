#!/usr/bin/env python3
"""Lineaje UnifAI Policy Scanner — GitHub Actions edition.

Scans already-checked-out source code against Lineaje AI security policies and
optionally opens a remediation PR built from the LLM remediation ``fix_code`` patches
the policy engine returns (guardrail stubs, ``gr_stub_client.py`` and
``.env`` files are never inserted; each patched Python file must still compile and
define every name it uses, or its fix is dropped); the PR commits the
patched files. The step summary also prints the exact ``entities.aientity.json`` and
``findings.aifinding.json`` the server uploaded to Lineaje — in hybrid mode those are
the only scan artifacts that leave the MCP host. Designed to run on a GitHub-managed
(or self-hosted) runner where the repository is already checked out.

Self-contained: the only SCM code here is a minimal GitHub REST client
(:class:`GitHubClient`, defined below) covering the branch/commit/PR calls the
remediation step makes, so this script is the only file a workflow needs to
copy. Nothing outside the Python stdlib is required beyond the ``mcp`` SDK.

Every file under ``--source-path`` is scanned. There is no exclusion list and no
special handling for dependency manifests: the walk collects everything it
finds, splits it into batches of ``UNIFAI_FILE_BATCH_SIZE`` files, and uploads
each batch archive as-is. Trimming the scan input (e.g. dropping ``.git``) is
the caller's job — the workflow does it before invoking this script.

Usage::

    python scm_unifai_scan_hybrid.py --source-path . --create-fix-pr

Output:

* **stdout** — the markdown policy report. The workflow redirects this into
  ``$GITHUB_STEP_SUMMARY`` so it renders on the run summary page rather than
  filling the step log.
* **stderr** — progress logs, ending with a one-line result such as
  ``Result: ❌ Not Compliant — 2 violation(s)``.

Required environment variable::

    LINEAJE_PAT_TOKEN  — Lineaje refresh token (exchanged for short-lived access tokens)

Optional environment variables::

    GITHUB_TOKEN / GH_TOKEN  — needed by --create-fix-pr to push the branch and open the PR
    UNIFAI_FILE_BATCH_SIZE   — files per batch (default 100; 0 puts everything in one batch)
    MCP_SERVER_URL           — override the Lineaje MCP endpoint

Exit codes::

    0 — scan completed (see the report for compliance status)
    1 — runtime error (every batch failed, or an unhandled exception)
    2 — configuration error (auth failure, missing repo/branch)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import builtins
import importlib
import fnmatch
import json
import ast
import logging
import os
import pathlib
import re
import shutil
import subprocess
import symtable
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("gha_repo_scan")

# ===========================================================================
# Constants
# ===========================================================================

MCP_SERVER_URL = "https://172.206.26.109/mcp"#"https://172.206.26.109/mcp"  # Put in your VM IP Address here


def _mcp_http_client_with_extra_ca(headers=None, timeout=None, auth=None):
    """Same defaults as mcp's create_mcp_http_client, plus (if configured) one
    extra CA added to — not replacing — the normal system/certifi trust store.

    The Wipro VM's Caddy `tls internal` cert is self-signed, and httpx (which
    the mcp SDK's streamablehttp_client uses) defaults to certifi's public CA
    bundle only — unlike stdlib ssl/requests, it does NOT read
    SSL_CERT_FILE/REQUESTS_CA_BUNDLE on its own. A fresh CI runner with no
    extra trust config therefore fails the TLS handshake before any request is
    even sent, surfacing to a caller only as a generic "unhandled errors in a
    TaskGroup (1 sub-exception)", with nothing logged server-side because the
    connection never completes.

    No certificate content lives in this script: point MCP_CA_BUNDLE (or the
    same REQUESTS_CA_BUNDLE / SSL_CERT_FILE convention scripts/run_demo_scan.sh
    already uses) at a CA file supplied separately by the workflow — e.g. a
    repo/org secret written to a temp file in an earlier step. Unset, this is
    a no-op: behavior is identical to the SDK's own create_mcp_http_client.
    """
    import ssl

    import httpx

    # Defaults to "1" (insecure) when unset — set MCP_TLS_INSECURE_SKIP_VERIFY=0/false/no
    # explicitly to turn verification back on. Only leave this default on against a
    # known, private endpoint reachable solely by this workflow.
    insecure = (os.environ.get("MCP_TLS_INSECURE_SKIP_VERIFY", "1") or "1").strip().lower() in ("1", "true", "yes")
    verify: Any
    if insecure:
        logger.warning(
            "MCP_TLS_INSECURE_SKIP_VERIFY is set — TLS certificate and hostname "
            "verification are DISABLED for the MCP connection. Do not use this "
            "against anything but a known, private endpoint."
        )
        verify = False
    else:
        ctx = ssl.create_default_context()
        ca_bundle_path = (
            os.environ.get("MCP_CA_BUNDLE")
            or os.environ.get("REQUESTS_CA_BUNDLE")
            or os.environ.get("SSL_CERT_FILE")
            or ""
        ).strip()
        if ca_bundle_path:
            ctx.load_verify_locations(cafile=ca_bundle_path)
        verify = ctx

    kwargs: Dict[str, Any] = {"follow_redirects": True, "verify": verify}
    kwargs["timeout"] = timeout if timeout is not None else httpx.Timeout(30, read=300)
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)



from contextlib import asynccontextmanager as _asynccontextmanager
from datetime import timedelta as _timedelta


@_asynccontextmanager
async def _streamablehttp_client_compat(
    url,
    headers=None,
    timeout=30,
    sse_read_timeout=60 * 5,
    terminate_on_close=True,
    httpx_client_factory=None,
    auth=None,
):
    import httpx
    from mcp.client.streamable_http import streamable_http_client

    factory = httpx_client_factory or _mcp_http_client_with_extra_ca
    timeout_seconds = timeout.total_seconds() if isinstance(timeout, _timedelta) else timeout
    sse_read_timeout_seconds = (
        sse_read_timeout.total_seconds() if isinstance(sse_read_timeout, _timedelta) else sse_read_timeout
    )
    client = factory(
        headers=headers,
        timeout=httpx.Timeout(timeout_seconds, read=sse_read_timeout_seconds),
        auth=auth,
    )
    async with client:
        async with streamable_http_client(
            url, http_client=client, terminate_on_close=terminate_on_close,
        ) as streams:
            if len(streams) == 2:
                streams = (*streams, None)
            yield streams


MAX_SCAN_WORKERS = 4
REMEDIATION_BRANCH_PREFIX = "remediation/unifai-gha"

# Azure DevOps REST limits for the remediation PR (used by AzureDevOpsClient).
AZURE_DEVOPS_API_VERSION = "7.1"
AZURE_PR_TITLE_LIMIT = 400
DEFAULT_UNIFAI_FILE_BATCH_SIZE = 100
GITHUB_PR_BODY_SAFE_LIMIT = 60000
# Azure DevOps rejects PR descriptions longer than 4000 characters.
AZURE_PR_DESCRIPTION_LIMIT = 4000

# Kept inline because this script is copied to customer CI runners and must
# remain standalone. These values mirror scripts/gha_repo_scan.py.
EVIDENCE_TYPE_SCM_SCAN = "scm_scan"
MANIFEST_FILE_PATTERNS = frozenset({
    "requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg",
    "*.toml", "environment.yml", "environment.yaml", "poetry.lock", "Pipfile.lock",
    "package.json", "yarn.lock", "pom.xml", "project.xml", "build.gradle",
    "build.gradle.kts", "build.gradle.mustache", "build.sbt", "Gemfile", "go.mod",
    "Cargo.toml", "packages.config", "*.csproj", "*.fsproj", "*.vbproj",
    "nuget.config", "Directory.Packages.props", "*.sln", "*.slnx", "vcpkg.json",
    ".vcpkg-root", "composer.json", "Package.swift", "pubspec.yaml", "mix.exs",
    "*.gemspec", "config.json",
})
LOCKFILE_BASENAMES = frozenset({
    "bun.lockb", "flake.lock", "package-lock.json", "pnpm-lock.yaml", "bun.lock",
    "gradle.lockfile", "Gemfile.lock", "go.sum", "Cargo.lock", "composer.lock",
    "Package.resolved", "pubspec.lock", "mix.lock", "packages.lock.json",
})
_MANIFEST_LOCKFILE_EXCEPTIONS = frozenset({"yarn.lock", "poetry.lock", "Pipfile.lock"})
ARCHIVE_EXCLUDE_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", "venv", ".venv",
    "env", ".tox", "htmlcov", ".mypy_cache", ".ruff_cache", "node_modules",
    ".yarn", ".pnp", "dist", "build", ".next", ".nuxt", "out", "coverage",
    ".cache", "target", ".gradle", ".m2", "Pods", ".expo", ".idea", ".vscode",
    ".lineaje-aiepo-security", ".lineaje", "migrations", "alembic",
})
ARCHIVE_EXCLUDE_GLOBS = frozenset({
    "*.secret", "*.key", "*.pem", "*.env.*", "*.zip", "*.tar", "*.tar.gz",
    "*.jar", "*.war", "*.swp", "*.swo", "*.lock", "package-lock.json",
    "Gemfile.lock", "Cargo.lock", "composer.lock", "*.min.js", "*.min.css", "*.map",
    "*_pb2.py", "*.pb.go", "*.pb.cc", "*.pb.h", "*.snap", "*README*",
    "*readme*", "*Dockerfile*", "*dockerfile*", "*.dockerfile", "*.dockerignore",
})
BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg", ".woff",
    ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".exe",
    ".dll", ".so", ".dylib", ".class", ".jar", ".war", ".pyc", ".pyo", ".o",
    ".a", ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".db", ".sqlite",
    ".sqlite3",
    # The server prefilter skips these too (Tier 3); sending them only costs
    # request body (4 MiB cap, 413).
    ".epub", ".mobi", ".azw3", ".odt", ".ods", ".odp", ".odg", ".tif", ".tiff",
    ".heic", ".avif", ".psd", ".mkv", ".webm", ".ogg", ".m4a", ".aac", ".xz",
    ".tgz", ".zst", ".whl", ".egg", ".wasm", ".parquet", ".arrow", ".feather",
    ".npy", ".npz", ".h5", ".hdf5", ".tfrecord", ".pkl", ".pickle", ".bin",
    ".onnx", ".pt", ".pth", ".safetensors", ".gguf",
})
_ARCHIVE_EXCLUDE_DIR_GLOBS = (".venv-*", "venv-*")


def _looks_binary(path: str) -> bool:
    """True when the file's first 8 KiB contain a NUL byte (not source text)."""
    try:
        with open(path, "rb") as handle:
            return b"\0" in handle.read(8192)
    except OSError:
        return False


def is_lockfile_basename(name: str) -> bool:
    base = os.path.basename(str(name or ""))
    lower = base.lower()
    exceptions = {n.lower() for n in _MANIFEST_LOCKFILE_EXCEPTIONS}
    lockfiles = {n.lower() for n in LOCKFILE_BASENAMES}
    if lower in exceptions:
        return False
    return (
        lower in lockfiles or lower.endswith(".lock") or lower.endswith(".lockfile")
        or lower.endswith("-lock.json") or lower.endswith("-lock.yaml")
    )


def _is_manifest_basename(name: str) -> bool:
    if is_lockfile_basename(name):
        return False
    return name in MANIFEST_FILE_PATTERNS or any(
        fnmatch.fnmatch(name, pattern)
        for pattern in MANIFEST_FILE_PATTERNS if "*" in pattern or "?" in pattern
    )


def archive_exclude_globs_keeping_manifests() -> Tuple[str, ...]:
    return tuple(sorted(pattern for pattern in ARCHIVE_EXCLUDE_GLOBS if pattern not in MANIFEST_FILE_PATTERNS))


def pin_manifests_to_first_batch(
    file_list: List[str], batch_size: int,
) -> Tuple[List[List[str]], List[str], List[str]]:
    if batch_size <= 0:
        batch_size = max(1, len(file_list) or 1)
    filtered = [path for path in file_list if not is_lockfile_basename(os.path.basename(path))]
    manifests = [path for path in filtered if _is_manifest_basename(os.path.basename(path))]
    code = [path for path in filtered if not _is_manifest_basename(os.path.basename(path))]
    code_batches = [code[i:i + batch_size] for i in range(0, len(code), batch_size)]
    if not code_batches:
        return ([manifests] if manifests else []), code, manifests
    return [manifests + code_batches[0], *code_batches[1:]], code, manifests


def split_batch_keeping_manifests_whole(
    batch_files: List[str],
) -> Optional[Tuple[List[str], List[str]]]:
    if len(batch_files) < 2:
        return None
    manifests = [path for path in batch_files if _is_manifest_basename(os.path.basename(path))]
    code = [path for path in batch_files if not _is_manifest_basename(os.path.basename(path))]
    if not code:
        return None
    if len(code) == 1:
        return (manifests, code) if manifests else None
    midpoint = len(code) // 2
    return manifests + code[:midpoint], code[midpoint:]

_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC = 120
_LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD = (
    "https://lineaje-identity-service.v2.prod.veedna.com"
    "/lineajeidentity/api/v1/auth/native/renew-access-token"
)


# ===========================================================================
# Azure DevOps client — remediation branch, commit, pull request
#
# Only the calls _create_fix_pr makes, over urllib.request from the stdlib.
# ===========================================================================

_NULL_OBJECT_ID = "0" * 40


class AzureDevOpsClient:
    """Minimal Azure DevOps Git REST client for opening remediation PRs.

    Every URL is built from the collection URI the agent already exposes as
    ``$(System.TeamFoundationCollectionUri)``, so the same client works against
    Azure DevOps Services (``https://dev.azure.com/{org}/``) and against an
    on-premises Azure DevOps Server collection.

    Both token flavours a pipeline can supply are accepted and auto-detected:
    ``$(System.AccessToken)`` is a JWT and goes out as ``Authorization: Bearer``,
    while a personal access token goes out as HTTP Basic with an empty username,
    which is the only form Azure DevOps accepts for PATs.
    """

    def __init__(self, token: str, org_url: str, project: str, repository: str) -> None:
        self.token = token
        self.org_url = org_url.rstrip("/")
        self.project = project
        self.repository = repository

    # -- request plumbing --------------------------------------------------

    @property
    def _repo_base(self) -> str:
        return (
            f"{self.org_url}/{urllib.parse.quote(self.project, safe='')}"
            f"/_apis/git/repositories/{urllib.parse.quote(self.repository, safe='')}"
        )

    def _auth_header(self) -> str:
        if self.token.count(".") == 2 and self.token.startswith("ey"):
            return f"Bearer {self.token}"
        return "Basic " + base64.b64encode(f":{self.token}".encode()).decode()

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": self._auth_header(),
            "Accept": "application/json",
            "User-Agent": "UniFAI-PR-Scanner/1.0",
        }

    def _url(self, endpoint: str, **params: str) -> str:
        query: Dict[str, str] = {"api-version": AZURE_DEVOPS_API_VERSION}
        query.update({k: v for k, v in params.items() if v})
        return f"{self._repo_base}{endpoint}?{urllib.parse.urlencode(query)}"

    def _request(
        self,
        method: str,
        url: str,
        body: Any = None,
        *,
        expected_errors: Optional[set] = None,
    ) -> Any:
        """Issue an HTTP request and return the decoded JSON.

        *expected_errors* is an optional set of HTTP status codes (e.g. ``{404}``)
        that the caller expects and will handle — these are logged at DEBUG instead
        of ERROR so they don't pollute output during normal operation.
        """
        headers = self._headers()

        data = json.dumps(body).encode() if body is not None else None
        if data:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        logger.debug("%s %s", method, url)

        try:
            with urllib.request.urlopen(req) as resp:
                resp_bytes = resp.read()
                if not resp_bytes:
                    return None
                content_type = resp.headers.get("Content-Type", "")
                if "json" not in content_type.lower():
                    # Azure DevOps answers an unauthenticated API call with the
                    # HTML sign-in page and HTTP 200 rather than a 401, so a
                    # non-JSON body here almost always means a rejected token.
                    raise RuntimeError(
                        f"Azure DevOps returned {content_type or 'a non-JSON body'} for {method} {url} — "
                        "the token was most likely rejected. Check that the step maps "
                        "SYSTEM_ACCESSTOKEN, or that the PAT has the Code (Read & Write) scope."
                    )
                return json.loads(resp_bytes)
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")[:500]
            if expected_errors and exc.code in expected_errors:
                logger.debug("Azure DevOps API %s %s → %s (expected): %s", method, url, exc.code, error_body)
            else:
                logger.error("Azure DevOps API %s %s → %s: %s", method, url, exc.code, error_body)
            raise

    # -- refs --------------------------------------------------------------

    def get_branch_sha(self, branch: str) -> Optional[str]:
        """Tip commit id of *branch*, or None when the branch does not exist."""
        data = self._request("GET", self._url("/refs", filter=f"heads/{branch}"))
        for ref in (data or {}).get("value", []):
            if ref.get("name") == f"refs/heads/{branch}" and ref.get("objectId"):
                return str(ref["objectId"])
        return None

    def create_branch(self, branch_name: str, from_sha: str) -> None:
        """Create ``refs/heads/<branch_name>`` pointing at *from_sha*."""
        resp = self._request("POST", self._url("/refs"), [{
            "name": f"refs/heads/{branch_name}",
            "oldObjectId": _NULL_OBJECT_ID,
            "newObjectId": from_sha,
        }])
        # This endpoint reports per-ref failures inside a 200 response body.
        for result in (resp or {}).get("value", []):
            if not result.get("success", True):
                detail = (
                    result.get("customMessage")
                    or result.get("updateStatus")
                    or "unknown error"
                )
                raise RuntimeError(f"Could not create refs/heads/{branch_name}: {detail}")

    # -- items -------------------------------------------------------------

    def file_exists(self, path: str, ref_sha: str) -> bool:
        """Whether *path* exists at *ref_sha*, which picks ``edit`` vs ``add``."""
        url = self._url(
            "/items",
            **{
                "path": f"/{path.lstrip('/')}",
                "versionDescriptor.version": ref_sha,
                "versionDescriptor.versionType": "commit",
                "includeContent": "false",
                "$format": "json",
            },
        )
        try:
            self._request("GET", url, expected_errors={404})
            return True
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False
            raise

    # -- pushes ------------------------------------------------------------

    def push_commit(
        self,
        branch: str,
        base_sha: str,
        files: Dict[str, bytes],
        message: str,
        *,
        existing: Optional[Dict[str, bool]] = None,
    ) -> str:
        """Push every entry of *files* to *branch* as a single commit on *base_sha*.

        Azure DevOps commits through the Pushes API rather than one call per file
        the way GitHub's Contents API does, so the whole remediation lands as one
        commit and there is no partially-committed branch to clean up on failure.
        """
        existing = existing or {}
        changes: List[Dict[str, Any]] = []
        for path, content in sorted(files.items()):
            rel = path.lstrip("/")
            changes.append({
                "changeType": "edit" if existing.get(rel, True) else "add",
                "item": {"path": f"/{rel}"},
                "newContent": {
                    "content": base64.b64encode(content).decode(),
                    "contentType": "base64encoded",
                },
            })
        resp = self._request("POST", self._url("/pushes"), {
            "refUpdates": [{"name": f"refs/heads/{branch}", "oldObjectId": base_sha}],
            "commits": [{"comment": message, "changes": changes}],
        })
        commits = (resp or {}).get("commits") or [{}]
        return str(commits[0].get("commitId", ""))

    # -- pull requests -----------------------------------------------------

    def create_pull_request(
        self, title: str, source_branch: str, target_branch: str, description: str
    ) -> int:
        resp = self._request("POST", self._url("/pullrequests"), {
            "sourceRefName": f"refs/heads/{source_branch}",
            "targetRefName": f"refs/heads/{target_branch}",
            "title": title[:AZURE_PR_TITLE_LIMIT],
            "description": description[:AZURE_PR_DESCRIPTION_LIMIT],
        })
        return int(resp["pullRequestId"])

    def pull_request_url(self, pr_id: int) -> str:
        return (
            f"{self.org_url}/{urllib.parse.quote(self.project, safe='')}"
            f"/_git/{urllib.parse.quote(self.repository, safe='')}/pullrequest/{pr_id}"
        )

# ===========================================================================
# Token helpers
# ===========================================================================

def _normalize_token(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip().lstrip("﻿").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _normalize_url(url: Optional[str]) -> str:
    if url is None:
        return ""
    u = str(url).strip()
    if len(u) >= 2 and u[0] == u[-1] and u[0] in "\"'":
        u = u[1:-1].strip()
    return u


def _identity_token_response_dict(raw_text: str, *, context: str) -> dict:
    text = raw_text.strip() if raw_text else ""
    try:
        parsed: Any = json.loads(raw_text)
    except json.JSONDecodeError:
        # Some endpoints return a bare JWT string
        parts = text.split(".")
        if context == "renew-access-token" and len(parts) == 3:
            return {"access_token": text}
        raise RuntimeError(f"{context}: response is not valid JSON") from None
    for _ in range(8):
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, str):
            s = parsed.strip()
            if not s:
                raise RuntimeError(f"{context}: empty JSON string where object expected")
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                parts = s.split(".")
                if context == "renew-access-token" and len(parts) == 3:
                    return {"access_token": s}
                raise RuntimeError(f"{context}: server returned error string: {s[:800]}") from None
            continue
        break
    raise RuntimeError(f"{context}: unexpected JSON type after unwrap: {type(parsed).__name__}")


class RefreshTokenTokenManager:
    """Exchange LINEAJE_PAT_TOKEN at the production identity endpoint.

    The hybrid scanner intentionally does not honor endpoint overrides for
    refresh-token exchange. Customer CI configuration may change the MCP
    endpoint, but credentials must always be renewed by the production Lineaje
    identity service.
    """

    def __init__(self, refresh_token: str, renew_access_token_url: Optional[str] = None) -> None:
        self._refresh_token = _normalize_token(refresh_token)
        if not self._refresh_token:
            raise ValueError("LINEAJE_PAT_TOKEN must be non-empty")
        # Keep the optional argument for call-site compatibility, but never let
        # it or LINEAJE_RENEW_ACCESS_TOKEN_URL redirect credentials elsewhere.
        self._renew_url = _LINEAJE_NATIVE_RENEW_ACCESS_TOKEN_URL_PROD
        self._lock = threading.Lock()
        self._access_token = ""
        self._access_deadline = 0.0
        try:
            self._skew_sec = int(os.environ.get(
                "LINEAJE_TOKEN_REFRESH_SKEW_SEC", str(_DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC)
            ))
        except ValueError:
            self._skew_sec = _DEFAULT_LINEAJE_TOKEN_REFRESH_SKEW_SEC

    def get_access_token(self) -> str:
        with self._lock:
            return self._get_unlocked()

    def _get_unlocked(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_deadline - self._skew_sec:
            return self._access_token
        self._renew()
        if not self._access_token:
            raise RuntimeError("renew-access-token did not return access_token")
        return self._access_token

    def _renew(self) -> None:
        q = urllib.parse.urlencode({"refreshToken": self._refresh_token})
        url = f"{self._renew_url}?{q}"
        req = urllib.request.Request(
            url, data=b"null",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = _identity_token_response_dict(resp.read().decode(), context="renew-access-token")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"renew-access-token HTTP {exc.code}: {body[:800]}") from exc
        at = (data.get("access_token") or "").strip()
        if not at:
            raise RuntimeError(f"Token response missing access_token: {data!r}")
        self._access_token = at
        rt = (data.get("refresh_token") or "").strip()
        if rt:
            self._refresh_token = rt
        exp = data.get("expires_in")
        try:
            exp_sec = int(exp) if exp is not None else 3600
        except (TypeError, ValueError):
            exp_sec = 3600
        self._access_deadline = time.time() + max(60, exp_sec)
        logger.debug("Access token renewed; expires in %ds", exp_sec)


def build_bearer_getter() -> Callable[[], str]:
    pat = _normalize_token(os.environ.get("LINEAJE_PAT_TOKEN", ""))
    if not pat:
        raise RuntimeError("LINEAJE_PAT_TOKEN is not set")
    mgr = RefreshTokenTokenManager(pat)
    return mgr.get_access_token

# ===========================================================================
# File collection
# ===========================================================================

def collect_repo_files(
    local_path: str,
    exclude: Optional[List[str]] = None,
    skipped: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Collect the same useful source set as the standalone GHA scanner.

    Explicit ``--exclude`` paths remain supported for Azure Pipelines. Common
    VCS/vendor/build directories, generated files, secrets, binaries, and
    dependency lockfiles are filtered without deleting anything in the checkout.
    When *skipped* is given it gets ``{path: reason}`` for every file left out; a
    pruned directory is one ``dir/`` entry (its files are not walked).
    """
    def skip(path: str, reason: str) -> None:
        if skipped is not None:
            skipped[path] = reason

    excluded = {_norm_rel_path(e) for e in (exclude or []) if e and e.strip()}
    exclude_globs = archive_exclude_globs_keeping_manifests()

    def explicitly_excluded(path: str) -> bool:
        normalized = _norm_rel_path(path)
        return any(normalized == item or normalized.startswith(item + "/") for item in excluded)

    def excluded_dir(name: str, rel_path: str) -> bool:
        return (
            explicitly_excluded(rel_path)
            or name in ARCHIVE_EXCLUDE_DIRS
            or any(fnmatch.fnmatch(name, pattern) for pattern in _ARCHIVE_EXCLUDE_DIR_GLOBS)
        )

    file_list: List[str] = []
    for root, dirs, filenames in os.walk(local_path):
        rel_root = _norm_rel_path(os.path.relpath(root, local_path))
        if rel_root == ".":
            rel_root = ""
        kept_dirs = []
        for directory in dirs:
            rel_dir = f"{rel_root}/{directory}" if rel_root else directory
            if not excluded_dir(directory, rel_dir):
                kept_dirs.append(directory)
            elif explicitly_excluded(rel_dir):
                skip(rel_dir + "/", "directory: --exclude")
            else:
                skip(rel_dir + "/", "directory: VCS / vendored / build / virtualenv")
        dirs[:] = kept_dirs
        for fname in filenames:
            rel_path = os.path.relpath(os.path.join(root, fname), local_path).replace("\\", "/")
            if explicitly_excluded(rel_path):
                skip(rel_path, "--exclude")
                continue
            if is_lockfile_basename(fname):
                skip(rel_path, "lockfile")
                continue
            if pathlib.Path(fname).suffix.lower() in BINARY_EXTENSIONS:
                skip(rel_path, f"binary extension ({pathlib.Path(fname).suffix.lower()})")
                continue
            matched = next((pattern for pattern in exclude_globs
                            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(fname, pattern)), None)
            if matched:
                skip(rel_path, f"excluded pattern ({matched})")
                continue
            if _looks_binary(os.path.join(root, fname)):
                skip(rel_path, "binary content")
                continue
            file_list.append(rel_path)
    return sorted(file_list)

def _text_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> List[str]:
    """Plain-text table (``|``-separated, padded columns), one string per line."""
    body = [["" if c is None else str(c) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in body:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))

    def line(cells: Sequence[str]) -> str:
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"

    return [line(list(headers)), "|-" + "-|-".join("-" * w for w in widths) + "-|", *(line(r) for r in body)]


def log_file_selection(batches: Sequence[Sequence[str]], manifest_files: Sequence[str],
                       skipped: Dict[str, str]) -> None:
    """Log which files are sent to the MCP server (with their batch) and which are left out, why."""
    manifests = set(manifest_files)
    sent = [(b, f) for b, files in enumerate(batches, 1) for f in files]
    lines = [f"[FILES] sent to the MCP server: {len(sent)} file(s) in {len(batches)} batch(es)"]
    lines += ["[FILES] " + ln for ln in _text_table(
        ("#", "File", "Batch", "Kind"),
        [(i, f, b, "manifest" if f in manifests else "source") for i, (b, f) in enumerate(sent, 1)])]
    if skipped:
        lines.append(f"[FILES] not sent: {len(skipped)} file(s) / folder(s)")
        lines += ["[FILES] " + ln for ln in _text_table(
            ("#", "File", "Reason"), [(i, p, why) for i, (p, why) in enumerate(sorted(skipped.items()), 1)])]
    logger.info("\n".join(lines))


# ===========================================================================
# Archive creation
# ===========================================================================

def retain_batch_archive(archive_path: str) -> Optional[str]:
    """Copy a batch archive into ``UNIFAI_SCAN_ARCHIVE_DIR`` when it is set.

    The archive itself is kept under ``<source>/.lineaje/scan-archives/`` (or
    ``UNIFAI_SCAN_ARCHIVE_ROOT``); the workflow sets this to also put a copy in the
    per-run folder on the runner host (the VM).
    """
    dest_dir = (os.environ.get("UNIFAI_SCAN_ARCHIVE_DIR") or "").strip()
    if not dest_dir or not os.path.isfile(archive_path):
        return None
    try:
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, os.path.basename(archive_path))
        shutil.copy2(archive_path, dest)
    except OSError as exc:
        logger.warning("Could not keep batch archive in %s: %s", dest_dir, exc)
        return None
    logger.info("Kept batch archive: %s", dest)
    return dest


def _norm_archive_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def create_batch_archive(
    source_dir: str,
    archive_dir: str,
    file_subset: List[str],
    source_code_repo: str,
    branch: str,
    head_sha: str,
    batch_index: Any = 0,
    run_id: str = "",
    manifest_files: Optional[List[str]] = None,
) -> str:
    extra_manifests = [path for path in (manifest_files or []) if path not in file_subset]
    archive_files = list(file_subset) + extra_manifests
    manifest_count = sum(1 for path in archive_files if _is_manifest_basename(os.path.basename(path)))
    archive_path = os.path.join(archive_dir, f"repo_scan_batch_{batch_index}.zip")
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in archive_files:
            full_path = os.path.join(source_dir, rel_path)
            if os.path.isfile(full_path):
                zf.write(full_path, rel_path)
        metadata = {
            "scan_source": "ado_repo_scan",
            "repo": source_code_repo,
            "branch": branch,
            "head_sha": head_sha,
            "scan_type": "full_repository",
            "batch_index": batch_index,
            "batch_file_count": len(file_subset),
            # Manifests are pinned into batch 1's file list, so count them in the archive,
            # not only the ones appended here (was always 0).
            "manifest_file_count": manifest_count,
        }
        zf.writestr("user_metadata.json", json.dumps(metadata, indent=2))
    size_kb = os.path.getsize(archive_path) // 1024
    logger.info(
        "Batch archive #%s: %d files (%d manifests), %d KB",
        batch_index, len(archive_files), manifest_count, size_kb,
    )
    return archive_path


def _batch_size(total_files: int) -> int:
    raw = (os.environ.get("UNIFAI_FILE_BATCH_SIZE") or "").strip()
    if not raw:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    try:
        size = int(raw)
    except ValueError:
        return DEFAULT_UNIFAI_FILE_BATCH_SIZE
    if size <= 0:
        return max(1, total_files)
    return size

# ===========================================================================
# MCP scan (SDK path only)
# ===========================================================================

from contextlib import asynccontextmanager as _asynccontextmanager
from datetime import timedelta as _timedelta


@_asynccontextmanager
async def streamablehttp_client(
    url,
    headers=None,
    timeout=30,
    sse_read_timeout=60 * 5,
    terminate_on_close=True,
    httpx_client_factory=None,
    auth=None,
):
    import httpx
    from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

    timeout_seconds = timeout.total_seconds() if isinstance(timeout, _timedelta) else timeout
    sse_read_timeout_seconds = (
        sse_read_timeout.total_seconds() if isinstance(sse_read_timeout, _timedelta) else sse_read_timeout
    )
    httpx_timeout = httpx.Timeout(timeout_seconds, read=sse_read_timeout_seconds)

    # MCP_CA_BUNDLE / REQUESTS_CA_BUNDLE / SSL_CERT_FILE: extra trust anchor for a
    # self-signed MCP endpoint (e.g. a self-hosted hybrid VM's Caddy `tls internal`
    # cert). `create_mcp_http_client` below builds a plain httpx.AsyncClient with
    # no `verify=` kwarg, so httpx falls back to its OWN default (certifi's bundle)
    # for `verify=True` and — unlike stdlib ssl or `requests` — does NOT read
    # SSL_CERT_FILE/REQUESTS_CA_BUNDLE from the environment on its own. A fresh
    # agent with no manually-trusted CA therefore fails TLS verification before any
    # request is even sent (confirmed live elsewhere: a plain httpx.AsyncClient()
    # against a self-signed endpoint raises SSLCertVerificationError: unable to get
    # local issuer certificate — the generic "unhandled errors in a TaskGroup"
    # callers see is just that SSL error re-wrapped by anyio's TaskGroup, with no
    # request ever reaching the server). Passing verify=<path> explicitly is the
    # only way to make httpx honor this trust anchor; unset (the default — MCP_SERVER_URL
    # here is the real prod SaaS endpoint with a publicly-trusted cert), this is a
    # no-op and behavior is identical to before.
    ca_bundle = (
        os.environ.get("MCP_CA_BUNDLE")
        or os.environ.get("REQUESTS_CA_BUNDLE")
        or os.environ.get("SSL_CERT_FILE")
        or ""
    ).strip()
    # Opt-in only (unlike some other scripts that default this to insecure) —
    # this file is also used for real customer runs against the actual SaaS
    # endpoint, so TLS verification must stay on unless explicitly disabled
    # for a known, private endpoint (e.g. a self-signed demo VM).
    insecure = (os.environ.get("MCP_TLS_INSECURE_SKIP_VERIFY", "") or "").strip().lower() in ("1", "true", "yes")

    if httpx_client_factory is not None:
        client = httpx_client_factory(headers=headers, timeout=httpx_timeout, auth=auth)
    elif ca_bundle:
        client = httpx.AsyncClient(
            follow_redirects=True, headers=headers, timeout=httpx_timeout, auth=auth, verify=ca_bundle,
        )
    elif insecure:
        logger.warning(
            "MCP_TLS_INSECURE_SKIP_VERIFY is set — TLS certificate and hostname "
            "verification are DISABLED for the MCP connection. Do not use this "
            "against anything but a known, private endpoint."
        )
        client = httpx.AsyncClient(
            follow_redirects=True, headers=headers, timeout=httpx_timeout, auth=auth, verify=False,
        )
    else:
        client = create_mcp_http_client(headers=headers, timeout=httpx_timeout, auth=auth)

    async with client:
        async with streamable_http_client(
            url, http_client=client, terminate_on_close=terminate_on_close,
        ) as streams:
            if len(streams) == 2:
                streams = (*streams, None)
            yield streams


def _upload_to_s3(presigned_url: str, archive_path: str) -> None:
    size = os.path.getsize(archive_path)
    logger.debug("Uploading %d KB to S3 ...", size // 1024)
    with open(archive_path, "rb") as f:
        req = urllib.request.Request(
            presigned_url, data=f.read(), method="PUT",
            headers={"Content-Type": "application/zip"},
        )
        with urllib.request.urlopen(req) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"S3 upload failed: HTTP {resp.status}")
    logger.debug("S3 upload complete")


def _is_payload_too_large(exc: BaseException) -> bool:
    """True when exc is (or wraps) an HTTP 413 from the MCP endpoint.

    The ``mcp`` SDK's StreamableHTTPSessionManager hard-caps request bodies at
    4 MiB and 413s anything bigger before it ever reaches application code —
    archive_content_base64 (used in hybrid mode, where source never touches
    S3) routes the whole archive through that same request body, so a batch
    whose files happen to be large enough hits this cap. Retrying the
    identical payload would just 413 again; the caller should split the batch
    in half instead.
    """
    cause = exc
    while hasattr(cause, "exceptions") and cause.exceptions:
        cause = cause.exceptions[0]
    try:
        import httpx
        if isinstance(cause, httpx.HTTPStatusError) and cause.response is not None:
            return cause.response.status_code == 413
    except Exception:
        pass
    text = str(cause)
    return "413" in text and ("Request Entity Too Large" in text or "Request body too large" in text)


def _loads_scan_payload(raw: str) -> dict:
    """Parse plain JSON or report-first MCP scan text (stdlib only).
    """
    text = (raw or "").strip()
    if not text:
        return {"raw": "empty response"}
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    marker = "<!-- LINEAJE_MCP_JSON -->"
    if marker in text:
        json_part = text.split(marker, 1)[1].strip()
        try:
            parsed = json.loads(json_part)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    brace = text.rfind("\n{")
    if brace >= 0:
        try:
            parsed = json.loads(text[brace + 1:])
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
    return {"raw": text, "report": text}


def _parse_tool_result(result: Any) -> dict:
    for attr in ("structuredContent", "structured_content"):
        structured = getattr(result, attr, None)
        if isinstance(structured, dict) and (
            "report" in structured or "status" in structured or "error" in structured
        ):
            return structured
    if hasattr(result, "content") and result.content:
        raw = result.content[0].text if hasattr(result.content[0], "text") else str(result.content[0])
        return _loads_scan_payload(raw)
    return {"raw": "empty response"}


def _describe_exception(exc: BaseException) -> str:
    """Unwrap ExceptionGroup/BaseExceptionGroup (e.g. from asyncio.TaskGroup, which
    anyio's streamablehttp_client uses internally) down to the real underlying
    message(s). Without this, a caller only ever sees the generic
    "unhandled errors in a TaskGroup (N sub-exception)" wrapper text — which
    hides exactly the RuntimeError this script raises on purpose (auth
    failures, get_upload_url errors, etc.) or the SSL error a bad/missing
    MCP_CA_BUNDLE produces. BaseExceptionGroup is a builtin since Python 3.11,
    the same version that introduced asyncio.TaskGroup, so no import/version
    guard is needed here."""
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_describe_exception(e) for e in exc.exceptions)
    return f"{type(exc).__name__}: {exc}"


# Guardrail stub insertion
_GR_CHECK_MARKERS: Dict[str, str] = {
    ".py": "def gr_check(",
    ".js": "function gr_check(",
    ".jsx": "function gr_check(",
    ".ts": "function gr_check(",
    ".tsx": "function gr_check(",
    ".go": "func grCheck(",
    ".java": "class GrClient {",
}

_GUARDRAIL_MANIFEST_REL = ".env.example"


def _module_prefix_insert_index(lines: List[str]) -> int:
    """0-indexed position to insert a new top-level block at — after any
    shebang/encoding comment AND after a leading module docstring, if
    present. Only the first statement in a Python file is its module
    docstring; inserting above it silently demotes it to a dead string-
    literal expression. Falls back to shebang/encoding-only detection for
    non-Python sources — never raises."""
    idx = 0
    for i, ln in enumerate(lines[:5]):
        if ln.startswith("#!") or ln.strip().startswith("# -*-"):
            idx = i + 1
        if ln.startswith("package "):
            idx = max(idx, i + 1)
    try:
        tree = ast.parse("".join(lines))
        first = tree.body[0] if tree.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(getattr(first, "value", None), ast.Constant)
            and isinstance(first.value.value, str)
        ):
            idx = max(idx, first.end_lineno)
    except SyntaxError:
        pass
    return idx


def safe_prefix_insert_index(lines: List[str]) -> int:
    """Like _module_prefix_insert_index(), but also walks past any leading
    `from __future__ import` line(s) — those must be the first statement(s)
    in a Python file; inserting anything above one is a real SyntaxError."""
    insert_at = _module_prefix_insert_index(lines)
    while insert_at < len(lines) and lines[insert_at].lstrip().startswith("from __future__ import"):
        insert_at += 1
    return insert_at


def validate_python_source(new_content: str, abs_path: str) -> Optional[str]:
    """Whole-file compile() check after a stub insertion. Returns None if
    still valid, else the SyntaxError message. compile(), not ast.parse() —
    ast.parse() does not enforce future-import placement."""
    try:
        compile(new_content, abs_path, "exec")
        return None
    except SyntaxError as exc:
        return str(exc)


_COMPILE_GATED_EXTS = (".py", ".pyi")


def _drop_uncompilable_fixes(validated_fixes: Dict[str, str]) -> List[str]:
    """Final compile gate before the remediation PR (C-37 / LIN-35923).

    Covers every file this script is about to commit (LLM ``fix_code``
    patches and any server-provided whole-file content), so a corrupted file
    is never committed. Runs validate_python_source on every .py / .pyi entry, removes
    failures from ``validated_fixes`` in place and returns one
    "<path> dropped: does not compile (<err>)" line per removed file.
    Non-Python entries are left untouched. Compile-only by design: this
    script runs standalone, so the pyflakes gate lives server-side."""
    dropped: List[str] = []
    for rel_path in list(validated_fixes):
        if not rel_path.lower().endswith(_COMPILE_GATED_EXTS):
            continue
        err = validate_python_source(validated_fixes[rel_path], rel_path)
        if err:
            del validated_fixes[rel_path]
            msg = f"{rel_path} dropped: does not compile ({err})"
            logger.warning("Remediation gate: %s", msg)
            dropped.append(msg)
    return dropped


# C-38 S37: fixes call one shared guard module instead of writing their own
# sanitizers. The server tells each fix how to import it; this script writes the
# module into the directory of every committed Python file that imports it.
_GUARD_FILENAME = "unifai_guard.py"
_GUARD_HEADER = "Prompt-injection and PII guard added by Lineaje UnifAI remediation."
_GUARD_IMPORT_RE = re.compile(
    r"^[ \t]*(?:from[ \t]+(?:\.|[\w.]+\.)?unifai_guard[ \t]+import\b|import[ \t]+(?:[\w.]+\.)?unifai_guard\b)",
    re.M)


def _add_shared_guard_files(
    validated_fixes: Dict[str, str], source_dir: str, fix_table: List[Dict[str, str]],
) -> List[str]:
    """Add ``unifai_guard.py`` next to each patched Python file that imports it.

    Returns "<path> dropped: …" lines for fixes that cannot get the guard (a file of
    the customer's own already has that name); those fixes are removed."""
    dropped: List[str] = []
    for rel in sorted(validated_fixes):
        content = validated_fixes.get(rel)
        if content is None or not rel.endswith(".py") or os.path.basename(rel) == _GUARD_FILENAME:
            continue
        if not _GUARD_IMPORT_RE.search(content):
            continue
        guard_rel = "/".join(p for p in (os.path.dirname(rel).replace("\\", "/"), _GUARD_FILENAME) if p)
        if validated_fixes.get(guard_rel) == _UNIFAI_GUARD_SOURCE:
            continue
        existing = os.path.join(source_dir, *guard_rel.split("/"))
        if os.path.isfile(existing):
            with open(existing, encoding="utf-8", errors="replace") as fh:
                current = fh.read()
            if current == _UNIFAI_GUARD_SOURCE:
                continue
            if _GUARD_HEADER not in current:
                del validated_fixes[rel]
                msg = f"{rel} dropped: {guard_rel} already exists and is not the UnifAI guard"
                logger.warning("Remediation gate: %s", msg)
                dropped.append(msg)
                continue
        validated_fixes[guard_rel] = _UNIFAI_GUARD_SOURCE
        fix_table.append({
            "policy": "Shared guard",
            "description": "Adds the prompt-injection and PII guard that the fixes in this directory "
                           "call (one vetted copy, standard library only).",
            "file": guard_rel,
        })
        logger.info("Remediation: added shared guard %s", guard_rel)
    dropped.extend(_add_js_shared_guard_files(validated_fixes, source_dir, fix_table))
    return dropped


# The JavaScript/TypeScript twin (unifaiGuard.js; CommonJS and .mjs variants; .d.ts for
# TypeScript), written next to each committed JS/TS file that imports it.
_JS_GUARD_MODULE = "unifaiGuard"
_JS_GUARD_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
_JS_GUARD_OWNER = 'UNIFAI-GUARD owner="Lineaje UnifAI"'
_JS_GUARD_SPEC_RE = re.compile(
    r"""(?P<how>\bfrom\s*|\brequire\s*\(\s*)['"]\./unifaiGuard(?P<ext>\.[cm]?js)?['"]""")
_JS_GUARD_EXPORTS = ("UNIFAI_GUARD_MANIFEST", "VERSION", "findPromptAttacks", "sanitizePrompt",
                     "sanitizeMessages", "unsupportedPiiCategories", "redactPii", "maskPii", "findCodeExecution",
                     "removeSuspiciousContent", "findShellCommands")


def _js_guard_commonjs(source: str) -> str:
    body = re.sub(r"^export (const|function) ", r"\1 ", source, flags=re.M)
    return body.rstrip("\n") + "\n\nmodule.exports = { " + ", ".join(_JS_GUARD_EXPORTS) + " };\n"


def _js_guard_files_for(rel: str, content: str) -> Dict[str, str]:
    """Guard file(s) a committed JS/TS file needs, by the way it imports the guard."""
    m = _JS_GUARD_SPEC_RE.search(content)
    if not m:
        return {}
    cjs = m.group("how").lstrip().startswith("require")
    ext = m.group("ext") or ".js"
    directory = os.path.dirname(rel).replace("\\", "/")
    join = lambda name: "/".join(p for p in (directory, name) if p)
    files = {join(_JS_GUARD_MODULE + ext):
             _js_guard_commonjs(_UNIFAI_GUARD_JS_SOURCE) if cjs else _UNIFAI_GUARD_JS_SOURCE}
    if rel.lower().endswith((".ts", ".tsx", ".mts", ".cts")) and not cjs:
        files[join(_JS_GUARD_MODULE + ".d.ts")] = _UNIFAI_GUARD_DTS_SOURCE
    return files


def _add_js_shared_guard_files(
    validated_fixes: Dict[str, str], source_dir: str, fix_table: List[Dict[str, str]],
) -> List[str]:
    dropped: List[str] = []
    for rel in sorted(validated_fixes):
        content = validated_fixes.get(rel)
        if content is None or not rel.lower().endswith(_JS_GUARD_EXTS) or _is_guard_file(rel):
            continue
        needed = _js_guard_files_for(rel, content)
        conflict = None
        for guard_rel in needed:
            existing = os.path.join(source_dir, *guard_rel.split("/"))
            if os.path.isfile(existing):
                with open(existing, encoding="utf-8", errors="replace") as fh:
                    if _JS_GUARD_OWNER not in fh.read():
                        conflict = guard_rel
                        break
        if conflict:
            del validated_fixes[rel]
            msg = f"{rel} dropped: {conflict} already exists and is not the UnifAI guard"
            logger.warning("Remediation gate: %s", msg)
            dropped.append(msg)
            continue
        for guard_rel, guard_source in needed.items():
            if validated_fixes.get(guard_rel) == guard_source:
                continue
            existing = os.path.join(source_dir, *guard_rel.split("/"))
            if os.path.isfile(existing):
                with open(existing, encoding="utf-8", errors="replace") as fh:
                    if fh.read() == guard_source:
                        continue
            validated_fixes[guard_rel] = guard_source
            fix_table.append({
                "policy": "Shared guard",
                "description": "Adds the prompt-injection and PII guard that the fixes in this directory "
                               "call (one vetted copy, no dependencies; JavaScript/TypeScript twin of "
                               "unifai_guard.py).",
                "file": guard_rel,
            })
            logger.info("Remediation: added shared guard %s", guard_rel)
    return dropped


# --- BEGIN UNIFAI_GUARD_SOURCE (generated by scripts/hybrid/embed_guard.py; do not edit) ---
_UNIFAI_GUARD_SOURCE = r'''"""Prompt-injection and PII guard added by Lineaje UnifAI remediation.

One shared module per service: remediation fixes import it instead of adding
their own sanitizers, so every route applies the same rules. Standard library
only; Python 3.8+.

* ``sanitize_prompt(text)``: removes prompt-injection spans from untrusted text
  (user input, uploaded or retrieved content) before it reaches a model. Only
  the matched span is replaced; the rest of the text, its newlines and layout
  are kept.
* ``find_prompt_attacks(text)``: the attack categories found, for code that
  refuses input instead of cleaning it.
* ``redact_pii(text, categories)``: masks the personal data a policy defines
  (its ``runtime.routine.params.categories``, per region) in text sent to a
  model, a log, a user or an external service.
* ``mask_pii(text, categories)``: the same detection as ``redact_pii``, shown in
  masked form for text displayed to a user: an identifier (SSN, card, account)
  keeps its last 4 digits (``***-**-6789``), any other value becomes
  ``<masked:label>`` (``<masked:phone>``).
* ``sanitize_messages(messages)``: ``sanitize_prompt`` on the user/tool turns of
  a chat message list (string content and text parts).
* ``remove_suspicious_content(text)``: uploaded or fetched file content with shell
  commands (alias, rg/ripgrep, curl, wget, rm, echo > file, dd, git, tar, chmod, chown,
  fsck, mkfs, shred, eval, source, export), also when base64-encoded or written in
  leetspeak, replaced by ``<suspicious_content_removed>``; ``find_shell_commands(text)``
  lists them.
* ``find_code_execution(text)``: the dynamic code-execution primitives found in
  model output (eval, exec, os.system, subprocess with shell=True, JS eval /
  Function / child_process, shell eval, piping a download into a shell), for code
  that validates an answer before it is executed or shown.

Never apply these to identifiers or lookup keys (user ids, file names, document
ids): those must reach their service unchanged.
"""
import base64
import binascii
import re

__all__ = ["sanitize_prompt", "find_prompt_attacks", "redact_pii", "mask_pii", "sanitize_messages",
           "unsupported_pii_categories", "find_code_execution", "remove_suspicious_content",
           "find_shell_commands"]
__version__ = "2.4.0"

# UNIFAI-GUARD owner="Lineaje UnifAI": generated by UnifAI remediation scans; do not edit.
# Scans read UNIFAI_GUARD_MANIFEST (without running this file) to reuse this module instead
# of adding another guardrail, and ship a newer version that only adds routines when a
# policy needs one listed nowhere below. Keys are the policies' runtime.routine.id values.
UNIFAI_GUARD_MANIFEST = {
    "owner": "Lineaje UnifAI",
    "version": "2.4.0",
    "routines": {
        "sanitize_prompt_injection": ["sanitize_prompt", "find_prompt_attacks", "sanitize_messages",
                                      "remove_suspicious_content", "find_shell_commands"],
        "mask_pii": ["redact_pii", "mask_pii"],
        "mask_pii_and_secrets": ["redact_pii", "mask_pii"],
        "validate_llm_output": ["find_code_execution"],
    },
}

# --- prompt injection -------------------------------------------------------

_Q = r"(?:all|any|every|the|your|my|of\s+the)?\s*"
_PHRASES = (
    ("instruction_override", re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass|skip)\s+" + _Q
        + r"(?:(?:previous|prior|above|earlier|preceding|original|existing|safety|system)\s+)+"
        r"(?:instructions?|rules|guidelines|prompts?|directions|directives|constraints)\b"
        r"|\bforget\s+everything\s+(?:above|before|you\s+were\s+told)\b"
        r"|\bsystem\s+override\b", re.I)),
    ("role_hijack", re.compile(
        r"\byou\s+are\s+now\s+(?:in\s+)?(?:an?\s+)?"
        r"(?:dan|unrestricted|unfiltered|jailbroken|evil|developer\s+mode|admin(?:istrator)?\s+mode|god\s+mode)\b"
        r"|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|uncensored)\s+(?:ai|model|assistant|chatbot)\b"
        r"|\b(?:developer|jailbreak|god)\s+mode\s+(?:enabled|activated|on)\b", re.I)),
    ("prompt_exfiltration", re.compile(
        r"\b(?:reveal|show|print|display|output|repeat|leak|dump|tell\s+me)\s+(?:me\s+)?"
        r"(?:all\s+|your\s+|the\s+)*(?:full\s+|entire\s+|hidden\s+|initial\s+|original\s+|secret\s+)?"
        r"(?:system\s+(?:prompts?|instructions|messages?)|initial\s+prompts?|hidden\s+instructions)\b", re.I)),
    ("data_exfiltration", re.compile(
        r"\b(?:reveal|list|dump|show|give\s+me)\s+(?:me\s+)?all\s+(?:the\s+)?"
        r"(?:confidential|secret|private|sensitive)\s+(?:information|data)\b"
        r"|\b(?:user\s+passwords|api\s+keys|access\s+tokens|private\s+keys)\b"
        r"|\bprovide\s+unrestricted\s+access\b", re.I)),
)
_EXFIL_VERB = re.compile(r"\b(?:list|reveal|dump|show|give|send|print|output|leak)\b", re.I)

_HIDDEN_HTML = re.compile(
    r"<(?P<tag>[a-z][a-z0-9]*)\b[^>]*?(?:\shidden\b|style\s*=\s*[\"'][^\"']*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^\"']*[\"']"
    r"|class\s*=\s*[\"'][^\"']*\b(?:hidden|invisible|sr-only)\b[^\"']*[\"'])[^>]*>"
    r".*?</(?P=tag)\s*>", re.I | re.S)
_MARKDOWN_IMAGE_EXFIL = re.compile(r"!\[[^\]\n]*\]\(\s*https?://[^)\s]*\?[^)\s]*\)", re.I)
_SHELL = re.compile(
    r"\b(?:bash|sh|zsh|ksh|powershell|pwsh|cmd(?:\.exe)?)\s+(?:-c|/c|-command)\s+\S[^\n]*"
    r"|\b(?:curl|wget)\s+[^\n|]*\|\s*(?:ba|z)?sh\b"
    r"|\brm\s+-rf\s+/\S*", re.I)
_CHAT_TOKENS = re.compile(r"<\|[a-z_]{2,20}\|>|\[/?INST\]|<</?SYS>>", re.I)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED = re.compile(r"(?<!\S)(?:[A-Za-z0-9@$]\s){3,}[A-Za-z0-9@$](?!\S)")


def _normalized(text):
    """(normalized text, index map): leetspeak folded, single-letter spacing removed.

    Every character of the normalized text maps back to its index in *text*, so
    a match removes exactly the original span."""
    drop = set()
    for m in _SPACED.finditer(text):
        drop.update(i for i in range(m.start(), m.end()) if text[i].isspace())
    chars, index = [], []
    for i, ch in enumerate(text):
        if i not in drop:
            chars.append(ch)
            index.append(i)
    return "".join(chars).translate(_LEET), index


def _phrase_spans(text):
    spans = []
    norm, index = _normalized(text)
    for category, pattern in _PHRASES:
        for m in pattern.finditer(norm):
            if m.end() <= m.start():
                continue
            if category == "data_exfiltration" and m.group(0).lower().startswith(
                    ("user passwords", "api keys", "access tokens", "private keys")):
                # "user passwords" alone is ordinary text ("list all passwords policies");
                # it is an attack only as the object of a request verb in the same sentence.
                sentence_start = max(norm.rfind(".", 0, m.start()), norm.rfind("\n", 0, m.start())) + 1
                if not _EXFIL_VERB.search(norm[sentence_start:m.start()]):
                    continue
            spans.append((index[m.start()], index[m.end() - 1] + 1, category))
    return spans


def _encoded_spans(text):
    spans = []
    for m in _BASE64.finditer(text):
        token = m.group(0)
        if len(token) % 4:
            continue
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(ch.isprintable() or ch.isspace() for ch in decoded) < 0.95 * len(decoded):
            continue
        if _phrase_spans(decoded) or _SHELL.search(decoded):
            spans.append((m.start(), m.end(), "encoded_payload"))
    return spans


def _attack_spans(text):
    spans = _phrase_spans(text) + _encoded_spans(text)
    for category, pattern in (("hidden_content", _HIDDEN_HTML),
                              ("markdown_image_exfiltration", _MARKDOWN_IMAGE_EXFIL),
                              ("command_injection", _SHELL),
                              ("chat_template_tokens", _CHAT_TOKENS)):
        spans.extend((m.start(), m.end(), category) for m in pattern.finditer(text))
    spans.sort()
    merged = []
    for start, end, category in spans:
        if merged and start < merged[-1][1]:
            prev = merged[-1]
            merged[-1] = (prev[0], max(prev[1], end), prev[2])
        else:
            merged.append((start, end, category))
    return merged


def find_prompt_attacks(text):
    """Attack categories found in *text* (empty list: none)."""
    if not isinstance(text, str) or not text:
        return []
    return sorted({category for _s, _e, category in _attack_spans(text)})


def sanitize_prompt(text):
    """*text* with prompt-injection spans replaced by a marker; anything else unchanged."""
    if not isinstance(text, str) or not text:
        return text
    out = text
    for start, end, category in reversed(_attack_spans(text)):
        out = out[:start] + "<prompt_injection_removed: " + category + ">" + out[end:]
    return out


def sanitize_messages(messages, roles=("user", "tool", "function")):
    """A copy of a chat message list with ``sanitize_prompt`` applied to the given roles.

    Handles string content and lists of content parts (``{"type": "text", "text": ...}``).
    System and assistant turns are the application's own text and are left as they are."""
    if not isinstance(messages, list):
        return messages
    result = []
    for message in messages:
        if isinstance(message, dict) and message.get("role") in roles:
            message = dict(message)
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = sanitize_prompt(content)
            elif isinstance(content, list):
                parts = []
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part = dict(part, text=sanitize_prompt(part["text"]))
                    parts.append(part)
                message["content"] = parts
        result.append(message)
    return result


# --- PII --------------------------------------------------------------------
# What is personal data is defined by the policy: callers pass the violated
# policy's ``runtime.routine.params.categories`` (the scanner writes them into
# each call). There is no default set. The category names are the policy
# vocabulary of the tenant's enabled PII policies (AI_DAT_SEC_011, 012, 023). A
# category with no text detector here (ethnicity, biometrics, the secret types
# of 011) is not redacted; ``unsupported_pii_categories`` lists them so the
# scanner can say so in the PR.

def _luhn(digits):
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_card(value):
    digits = re.sub(r"\D", "", value)
    return 13 <= len(digits) <= 19 and digits[0] in "23456" and len(set(digits)) > 1 and _luhn(digits)


_STREET = (r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl"
           r"|Terrace|Parkway|Pkwy|Highway|Hwy)\.?")
_DATE = r"(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})"
_NUM = r"(?:\s*(?:no\.?|number|num|#|id))?\s*[:#=]?\s*"
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_CODE = r"(?=[A-Z0-9-]*\d)[A-Z0-9-]{%d,%d}\b"


def _labelled(label, value, flags=re.I):
    """Pattern that keeps *label* and masks the value after it."""
    # The label is always case-insensitive; *flags* apply to the value (names keep their capitals).
    return re.compile(r"(?P<label>\b(?i:" + label + r")(?i:" + _NUM + r"))" + value, flags)


# policy category -> patterns; a pattern with a "label" group keeps the label.
_DETECTORS = {
    "email": (re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])"),),
    "credit_card": (re.compile(r"(?<![\w-])\d{4}(?:[ -]?\d{4}){2}[ -]?\d{1,7}(?![\w-])"),),
    "financial_account_number": (
        re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b"),
        _labelled(r"(?:bank\s+|checking\s+|savings\s+)?(?:account|acct|a/c)|routing|IBAN", _CODE % (6, 34))),
    "ssn": (re.compile(r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])"),
            _labelled(r"SSN|social\s+security", r"\d{3}\s\d{2}\s\d{4}\b")),
    "taxpayer_id": (_labelled(r"tax(?:payer)?\s*id(?:entification)?|EIN|TIN", _CODE % (8, 15)),),
    "passport_number": (_labelled(r"passport", r"(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b"),),
    "drivers_license_number": (_labelled(r"driver'?s?\s+licen[cs]e|DL", _CODE % (5, 20)),),
    "medical_records": (_labelled(r"MRN|medical\s+record|patient\s+id", _CODE % (4, 20)),),
    "employee_id": (_labelled(r"employee|emp|staff", _CODE % (3, 20)),),
    "school_id": (_labelled(r"student|school", _CODE % (3, 20)),),
    "vehicle_identification_number": (_labelled(r"VIN|vehicle\s+identification", r"[A-HJ-NPR-Z0-9]{17}\b"),),
    "mac_address": (re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])"),),
    "ip_address": (re.compile(r"(?<![\w.])(?<!v)(?:" + _OCTET + r"\.){3}" + _OCTET + r"(?![\w.])"),
                   re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![\w:])")),
    "fine_location": (_labelled(r"lat(?:itude)?|gps|location|coord(?:inate)?s?",
                                r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b"),),
    "year_of_birth": (_labelled(r"DOB|D\.O\.B\.?|date\s+of\s+birth|born\s+on|birth\s*date", _DATE),
                      _labelled(r"born\s+in|year\s+of\s+birth|birth\s+year", r"(?:19|20)\d{2}\b")),
    "birthplace": (_labelled(r"place\s+of\s+birth|birth\s*place", r"[A-Z][A-Za-z'.-]+(?:[ ,]+[A-Z][A-Za-z'.-]+){0,3}", 0),),
    "mothers_maiden_name": (_labelled(r"mother'?s\s+maiden\s+name(?:\s+is)?", r"[A-Z][A-Za-z'-]+(?:\s[A-Z][A-Za-z'-]+)?", 0),),
    "phone": (re.compile(r"(?<![\w+(])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\w-])"),
              re.compile(r"(?<![\w+])\+\d{1,3}[\s.-]?\d{2,5}(?:[\s.-]?\d{2,5}){1,3}(?![\w-])"),
              _labelled(r"phone|mobile|cell|tel|telephone|fax", r"\+?\d[\d\s().-]{6,}\d\b")),
    "home_address": (re.compile(r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s){1,3}" + _STREET
                                + r"(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}(?:\s+\d{5}(?:-\d{4})?)?)?"),),
}
# Applied in this order (dict order): longer, more specific shapes first (a card before a phone).


def _normalized_categories(categories):
    if isinstance(categories, str):
        categories = (categories,)
    if not categories:
        return ()
    return tuple(str(c).strip().lower() for c in categories if str(c).strip())


def unsupported_pii_categories(categories):
    """The policy categories this guard has no text detector for (they are not redacted)."""
    return [c for c in _normalized_categories(categories) if c not in _DETECTORS]


def _masker(category):
    def mask(match):
        if category == "credit_card" and not _is_card(match.group(0)):
            return match.group(0)
        label = match.groupdict().get("label") or ""
        return label + "<redacted:" + category + ">"
    return mask


# mask_pii: one fixed label per category (the policy's display vocabulary); identifiers
# keep their last 4 digits.
_MASK_LABEL = {
    "phone": "phone", "email": "email", "home_address": "address", "year_of_birth": "dob",
    "passport_number": "passport", "drivers_license_number": "drivers_license", "taxpayer_id": "tax_id",
    "employee_id": "employee_id", "school_id": "school_id", "vehicle_identification_number": "vin",
    "ip_address": "ip_address", "mac_address": "mac_address", "birthplace": "birthplace",
    "mothers_maiden_name": "maiden_name", "medical_records": "medical", "fine_location": "location",
}
_KEEP_LAST4 = frozenset({"ssn", "credit_card", "financial_account_number"})


def _last4(value):
    digits = [i for i, ch in enumerate(value) if ch.isdigit()]
    keep = set(digits[-4:])
    return "".join(ch if (not ch.isalnum() or i in keep) else "*" for i, ch in enumerate(value))


def _display_masker(category):
    def mask(match):
        if category == "credit_card" and not _is_card(match.group(0)):
            return match.group(0)
        label = match.groupdict().get("label") or ""
        value = match.group(0)[len(label):]
        if category in _KEEP_LAST4:
            return label + _last4(value)
        return label + "<masked:" + _MASK_LABEL.get(category, category) + ">"
    return mask


def _structured(value, fn, depth=0):
    """*fn* applied to every string inside *value*, keeping its type: lists, tuples, sets,
    dicts, pydantic models (v1 and v2) and dataclasses come back as the same type with
    their text fields masked; anything else is returned unchanged."""
    if isinstance(value, str):
        return fn(value)
    if depth > 8 or value is None or isinstance(value, (bytes, bytearray, int, float, bool)):
        return value
    if isinstance(value, dict):
        return type(value)((k, _structured(v, fn, depth + 1)) for k, v in value.items()) \
            if type(value) is not dict else {k: _structured(v, fn, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_structured(v, fn, depth + 1) for v in value]
        if isinstance(value, tuple) and hasattr(value, "_fields"):  # namedtuple
            return type(value)(*items)
        return type(value)(items)
    fields = getattr(type(value), "model_fields", None)  # pydantic v2
    if isinstance(fields, dict) and hasattr(value, "model_copy"):
        return value.model_copy(update={f: _structured(getattr(value, f, None), fn, depth + 1) for f in fields})
    fields = getattr(type(value), "__fields__", None)  # pydantic v1
    if isinstance(fields, dict) and hasattr(value, "copy"):
        return value.copy(update={f: _structured(getattr(value, f, None), fn, depth + 1) for f in fields})
    import dataclasses
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.replace(value, **{f.name: _structured(getattr(value, f.name), fn, depth + 1)
                                             for f in dataclasses.fields(value) if f.init})
    return value


def mask_pii(text, categories):
    """*text* with the personal data of the given policy *categories* masked for display:
    identifiers keep their last 4 digits, other values become ``<masked:label>``. *text*
    may also be a list, dict, pydantic model or dataclass (e.g. response sources): the same
    type comes back with every text field masked."""
    if not isinstance(text, str):
        return _structured(text, lambda t: mask_pii(t, categories)) if text is not None else text
    if not text:
        return text
    wanted = set(_normalized_categories(categories))
    out = text
    for category, patterns in _DETECTORS.items():
        if category in wanted:
            for pattern in patterns:
                out = pattern.sub(_display_masker(category), out)
    return out


def redact_pii(text, categories):
    """*text* with the personal data of the given policy *categories* replaced by
    ``<redacted:category>``; anything else unchanged.

    *categories* is the violated policy's ``runtime.routine.params.categories``
    (e.g. ``("ssn", "email", "phone", ...)``); only those are redacted. *text* may also be
    a list, dict, pydantic model or dataclass: the same type comes back redacted."""
    if not isinstance(text, str):
        return _structured(text, lambda t: redact_pii(t, categories)) if text is not None else text
    if not text:
        return text
    wanted = set(_normalized_categories(categories))
    out = text
    for category, patterns in _DETECTORS.items():
        if category in wanted:
            for pattern in patterns:
                out = pattern.sub(_masker(category), out)
    return out


# --- model output: dynamic code execution -------------------------------------

_CODE_EXECUTION = (
    ("python_eval_exec", re.compile(r"(?<![\w.])(?:eval|exec|compile|__import__)\s*\(")),
    ("os_command", re.compile(r"\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?)\s*\(")),
    ("subprocess_shell", re.compile(r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True", re.S)),
    ("js_eval", re.compile(r"(?<![\w.])(?:eval|new\s+Function|Function)\s*\(")),
    ("js_child_process", re.compile(r"\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(\s*['\"`]")),
    ("shell_eval", re.compile(r"(?:^|[;&|\s])(?:eval|source)\s+['\"$]|\b(?:bash|sh|zsh)\s+-c\s+\S", re.M)),
    ("pipe_to_shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")),
    ("destructive_command", re.compile(r"\brm\s+-rf\s+/|\bmkfs(?:\.\w+)?\s|\bdd\s+if=|:\(\)\s*\{\s*:\|:&\s*\};:")),
)


def find_code_execution(text):
    """The dynamic code-execution primitives found in *text* (empty list: none).

    For model output that is executed, written to disk or shown as runnable code:
    the caller decides what to do with a finding (refuse, flag, or require review);
    this function never changes the text."""
    if not isinstance(text, str) or not text:
        return []
    return sorted({name for name, pattern in _CODE_EXECUTION if pattern.search(text)})


# --- uploaded file content: shell commands ---------------------------------------

_CMD = (
    r"(?:sudo\s+)?(?:"
    r"alias\s+[\w.-]+=\S*"
    r"|(?:rg|ripgrep)\s+[-\w'\"./*]+"
    r"|curl\s+(?:-\S+\s+)*\S+"
    r"|wget\s+(?:-\S+\s+)*\S+"
    r"|rm\s+(?:-[a-z]+\s+)*[\w./~*$-]+"
    r"|echo\s+[^\n>]*>>?\s*\S+"
    r"|dd\s+(?:if|of)=\S+"
    r"|git\s+(?:clone|push|pull|fetch|reset|checkout|remote|config|rm|apply|am)\b[^\n]*"
    r"|tar\s+-?[a-z]*[xcz][a-z]*f?\s+\S+"
    r"|chmod\s+(?:-[a-z]+\s+)*[0-7ugoa+=,rwxst-]+\s+\S+"
    r"|chown\s+(?:-[a-z]+\s+)*[\w.:-]+\s+\S+"
    r"|fsck(?:\.\w+)?(?:\s+-\S+)*\s+\S+"
    r"|mkfs(?:\.\w+)?\s+\S+"
    r"|shred\s+(?:-\S+\s+)*\S+"
    r"|(?:eval|source)\s+\S+"
    r"|export\s+[A-Z_][A-Z0-9_]*=\S*"
    r")"
)
# A command at the start of a line, after a prompt, or after a shell separator.
_SHELL_LINE = re.compile(r"(?:(?<=^)|(?<=\n)|(?<=[;&|`]))[ \t]*(?:[$#>]\s*)?" + _CMD + r"[^\n;&|]*", re.I)
_BASE64_SHORT = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])")
_LEET_MULTI = (("|-|", "h"), ("|_|", "u"), ("|<", "k"), ("|\\|", "n"), ("/\\", "a"), ("()", "o"))


def _fold_leet(line):
    for seq, ch in _LEET_MULTI:
        line = line.replace(seq, ch)
    return line.translate(_LEET)


def _shell_spans(text):
    """(start, end) of shell-command lines in *text*: plain, leetspeak-folded per line, or
    inside a base64 token."""
    spans = [(m.start(), m.end()) for m in _SHELL_LINE.finditer(text)]
    offset = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        folded = _fold_leet(body)
        if folded != body and _SHELL_LINE.search(folded) and not _SHELL_LINE.search(body):
            lead = len(body) - len(body.lstrip())
            spans.append((offset + lead, offset + len(body)))
        offset += len(line)
    for m in _BASE64_SHORT.finditer(text):
        token = m.group(0)
        if len(token) % 4:
            continue
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _SHELL_LINE.search(decoded):
            spans.append((m.start(), m.end()))
    spans.sort()
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def find_shell_commands(text):
    """The shell-command lines found in uploaded or fetched content (empty list: none)."""
    if not isinstance(text, str) or not text:
        return []
    return [text[s:e].strip() for s, e in _shell_spans(text)]


def remove_suspicious_content(text):
    """*text* (uploaded or fetched file content) with each shell command replaced by
    ``<suspicious_content_removed>``; the rest of the content is kept."""
    if not isinstance(text, str):
        return _structured(text, remove_suspicious_content) if text is not None else text
    out = text
    for start, end in reversed(_shell_spans(text)):
        out = out[:start] + "<suspicious_content_removed>" + out[end:]
    return out
'''
_UNIFAI_GUARD_JS_SOURCE = r'''/*
 * Prompt-injection and PII guard added by Lineaje UnifAI remediation.
 *
 * JavaScript/TypeScript twin of unifai_guard.py: same rules, same markers. One
 * shared module per directory: remediation fixes import it instead of adding
 * their own sanitizers, so every route applies the same rules. No dependencies;
 * runs in browsers (ES2018+) and Node 12+. Types: unifaiGuard.d.ts.
 *
 * - sanitizePrompt(text): removes prompt-injection spans from untrusted text
 *   (user input, uploaded or retrieved content) before it reaches a model. Only
 *   the matched span is replaced; the rest of the text, its newlines and layout
 *   are kept.
 * - findPromptAttacks(text): the attack categories found, for code that refuses
 *   input instead of cleaning it.
 * - redactPii(text, categories): masks the personal data a policy defines (its
 *   runtime.routine.params.categories, per region) in text sent to a model, a
 *   log, a user or an external service.
 * - maskPii(text, categories): the same detection as redactPii, in masked form for
 *   text shown to a user: identifiers (SSN, card, account) keep their last 4 digits
 *   ("***-**-6789"), other values become "<masked:label>".
 * - sanitizeMessages(messages): sanitizePrompt on the user/tool turns of a chat
 *   message list (string content and text parts).
 * - findCodeExecution(text): the dynamic code-execution primitives found in model
 *   output (eval, exec, os.system, subprocess with shell=True, JS eval / Function /
 *   child_process, shell eval, piping a download into a shell).
 *
 * Never apply these to identifiers or lookup keys (user ids, file names,
 * document ids): those must reach their service unchanged.
 */

// UNIFAI-GUARD owner="Lineaje UnifAI": generated by UnifAI remediation scans; do not edit.
// Scans read UNIFAI_GUARD_MANIFEST (without running this file) to reuse this module instead
// of adding another guardrail, and ship a newer version that only adds routines when a
// policy needs one listed nowhere below. Keys are the policies' runtime.routine.id values.
export const UNIFAI_GUARD_MANIFEST = {
  "owner": "Lineaje UnifAI",
  "version": "2.4.0",
  "routines": {
    "sanitize_prompt_injection": ["sanitizePrompt", "findPromptAttacks", "sanitizeMessages",
                                  "removeSuspiciousContent", "findShellCommands"],
    "mask_pii": ["redactPii", "maskPii"],
    "mask_pii_and_secrets": ["redactPii", "maskPii"],
    "validate_llm_output": ["findCodeExecution"]
  }
};

export const VERSION = "2.4.0";

// --- prompt injection -------------------------------------------------------

const Q = "(?:all|any|every|the|your|my|of\\s+the)?\\s*";
const PHRASES = [
  ["instruction_override", new RegExp(
    "\\b(?:ignore|disregard|forget|override|bypass|skip)\\s+" + Q
    + "(?:(?:previous|prior|above|earlier|preceding|original|existing|safety|system)\\s+)+"
    + "(?:instructions?|rules|guidelines|prompts?|directions|directives|constraints)\\b"
    + "|\\bforget\\s+everything\\s+(?:above|before|you\\s+were\\s+told)\\b"
    + "|\\bsystem\\s+override\\b", "gi")],
  ["role_hijack", new RegExp(
    "\\byou\\s+are\\s+now\\s+(?:in\\s+)?(?:an?\\s+)?"
    + "(?:dan|unrestricted|unfiltered|jailbroken|evil|developer\\s+mode|admin(?:istrator)?\\s+mode|god\\s+mode)\\b"
    + "|\\bact\\s+as\\s+(?:an?\\s+)?(?:unrestricted|unfiltered|jailbroken|uncensored)\\s+(?:ai|model|assistant|chatbot)\\b"
    + "|\\b(?:developer|jailbreak|god)\\s+mode\\s+(?:enabled|activated|on)\\b", "gi")],
  ["prompt_exfiltration", new RegExp(
    "\\b(?:reveal|show|print|display|output|repeat|leak|dump|tell\\s+me)\\s+(?:me\\s+)?"
    + "(?:all\\s+|your\\s+|the\\s+)*(?:full\\s+|entire\\s+|hidden\\s+|initial\\s+|original\\s+|secret\\s+)?"
    + "(?:system\\s+(?:prompts?|instructions|messages?)|initial\\s+prompts?|hidden\\s+instructions)\\b", "gi")],
  ["data_exfiltration", new RegExp(
    "\\b(?:reveal|list|dump|show|give\\s+me)\\s+(?:me\\s+)?all\\s+(?:the\\s+)?"
    + "(?:confidential|secret|private|sensitive)\\s+(?:information|data)\\b"
    + "|\\b(?:user\\s+passwords|api\\s+keys|access\\s+tokens|private\\s+keys)\\b"
    + "|\\bprovide\\s+unrestricted\\s+access\\b", "gi")]
];
const EXFIL_VERB = /\b(?:list|reveal|dump|show|give|send|print|output|leak)\b/i;
const EXFIL_OBJECTS = ["user passwords", "api keys", "access tokens", "private keys"];

const HIDDEN_HTML = new RegExp(
  "<(?<tag>[a-z][a-z0-9]*)\\b[^>]*?(?:\\shidden\\b|style\\s*=\\s*[\"'][^\"']*"
  + "(?:display\\s*:\\s*none|visibility\\s*:\\s*hidden|font-size\\s*:\\s*0)[^\"']*[\"']"
  + "|class\\s*=\\s*[\"'][^\"']*\\b(?:hidden|invisible|sr-only)\\b[^\"']*[\"'])[^>]*>"
  + "[\\s\\S]*?</\\k<tag>\\s*>", "gi");
const MARKDOWN_IMAGE_EXFIL = /!\[[^\]\n]*\]\(\s*https?:\/\/[^)\s]*\?[^)\s]*\)/gi;
const SHELL = new RegExp(
  "\\b(?:bash|sh|zsh|ksh|powershell|pwsh|cmd(?:\\.exe)?)\\s+(?:-c|/c|-command)\\s+\\S[^\\n]*"
  + "|\\b(?:curl|wget)\\s+[^\\n|]*\\|\\s*(?:ba|z)?sh\\b"
  + "|\\brm\\s+-rf\\s+/\\S*", "gi");
const CHAT_TOKENS = /<\|[a-z_]{2,20}\|>|\[\/?INST\]|<<\/?SYS>>/gi;
const BASE64 = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])/g;

const LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };
const SPACED = /(?<!\S)(?:[A-Za-z0-9@$]\s){3,}[A-Za-z0-9@$](?!\S)/g;

function matches(pattern, text) {
  pattern.lastIndex = 0;
  const out = [];
  let m;
  while ((m = pattern.exec(text)) !== null) {
    if (m[0] === "") {
      pattern.lastIndex += 1;
      continue;
    }
    out.push(m);
  }
  return out;
}

// [normalized text, index map]: leetspeak folded, single-letter spacing removed.
// Every character of the normalized text maps back to its index in text, so a
// match removes exactly the original span.
function normalized(text) {
  const drop = new Set();
  for (const m of matches(SPACED, text)) {
    for (let i = m.index; i < m.index + m[0].length; i++) {
      if (/\s/.test(text[i])) drop.add(i);
    }
  }
  const chars = [];
  const index = [];
  for (let i = 0; i < text.length; i++) {
    if (!drop.has(i)) {
      const ch = text[i];
      chars.push(Object.prototype.hasOwnProperty.call(LEET, ch) ? LEET[ch] : ch);
      index.push(i);
    }
  }
  return [chars.join(""), index];
}

function phraseSpans(text) {
  const spans = [];
  const [norm, index] = normalized(text);
  for (const [category, pattern] of PHRASES) {
    for (const m of matches(pattern, norm)) {
      const start = m.index;
      const end = m.index + m[0].length;
      if (category === "data_exfiltration"
          && EXFIL_OBJECTS.some((o) => m[0].toLowerCase().startsWith(o))) {
        // "user passwords" alone is ordinary text ("list all passwords policies");
        // it is an attack only as the object of a request verb in the same sentence.
        const sentenceStart = Math.max(norm.lastIndexOf(".", start - 1), norm.lastIndexOf("\n", start - 1)) + 1;
        if (!EXFIL_VERB.test(norm.slice(sentenceStart, start))) continue;
      }
      spans.push([index[start], index[end - 1] + 1, category]);
    }
  }
  return spans;
}

function decodeBase64(token) {
  try {
    let bytes;
    if (typeof atob === "function") {
      const bin = atob(token);
      bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    } else if (typeof Buffer !== "undefined") {
      bytes = Buffer.from(token, "base64");
    } else {
      return null;
    }
    if (typeof TextDecoder === "undefined") return null;
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (e) {
    return null;
  }
}

function isPrintableOrSpace(ch) {
  const c = ch.codePointAt(0);
  return /\s/.test(ch) || (c >= 0x20 && c !== 0x7f && !(c >= 0x80 && c < 0xa0));
}

function encodedSpans(text) {
  const spans = [];
  for (const m of matches(BASE64, text)) {
    const token = m[0];
    if (token.length % 4) continue;
    const decoded = decodeBase64(token);
    if (decoded === null) continue;
    const chars = Array.from(decoded);
    if (chars.filter(isPrintableOrSpace).length < 0.95 * chars.length) continue;
    if (phraseSpans(decoded).length || matches(SHELL, decoded).length) {
      spans.push([m.index, m.index + token.length, "encoded_payload"]);
    }
  }
  return spans;
}

function attackSpans(text) {
  const spans = phraseSpans(text).concat(encodedSpans(text));
  for (const [category, pattern] of [["hidden_content", HIDDEN_HTML],
                                     ["markdown_image_exfiltration", MARKDOWN_IMAGE_EXFIL],
                                     ["command_injection", SHELL],
                                     ["chat_template_tokens", CHAT_TOKENS]]) {
    for (const m of matches(pattern, text)) spans.push([m.index, m.index + m[0].length, category]);
  }
  spans.sort((a, b) => a[0] - b[0] || a[1] - b[1] || (a[2] < b[2] ? -1 : a[2] > b[2] ? 1 : 0));
  const merged = [];
  for (const [start, end, category] of spans) {
    const prev = merged[merged.length - 1];
    if (prev && start < prev[1]) {
      merged[merged.length - 1] = [prev[0], Math.max(prev[1], end), prev[2]];
    } else {
      merged.push([start, end, category]);
    }
  }
  return merged;
}

/** Attack categories found in text (empty array: none). */
export function findPromptAttacks(text) {
  if (typeof text !== "string" || !text) return [];
  return Array.from(new Set(attackSpans(text).map((s) => s[2]))).sort();
}

/** text with prompt-injection spans replaced by a marker; anything else unchanged. */
export function sanitizePrompt(text) {
  if (typeof text !== "string" || !text) return text;
  let out = text;
  const spans = attackSpans(text);
  for (let i = spans.length - 1; i >= 0; i--) {
    const [start, end, category] = spans[i];
    out = out.slice(0, start) + "<prompt_injection_removed: " + category + ">" + out.slice(end);
  }
  return out;
}

/**
 * A copy of a chat message list with sanitizePrompt applied to the given roles.
 * Handles string content and lists of content parts ({type: "text", text: ...}).
 * System and assistant turns are the application's own text and are left as they are.
 */
export function sanitizeMessages(messages, roles = ["user", "tool", "function"]) {
  if (!Array.isArray(messages)) return messages;
  return messages.map((message) => {
    if (!message || typeof message !== "object" || roles.indexOf(message.role) === -1) return message;
    const copy = Object.assign({}, message);
    const content = copy.content;
    if (typeof content === "string") {
      copy.content = sanitizePrompt(content);
    } else if (Array.isArray(content)) {
      copy.content = content.map((part) => (part && typeof part === "object" && typeof part.text === "string"
        ? Object.assign({}, part, { text: sanitizePrompt(part.text) })
        : part));
    }
    return copy;
  });
}

// --- PII --------------------------------------------------------------------
// What is personal data is defined by the policy: callers pass the violated
// policy's runtime.routine.params.categories (the scanner writes them into each
// call). There is no default set. A category with no text detector here
// (ethnicity, biometrics, the secret types of 011) is not redacted;
// unsupportedPiiCategories lists them so the scanner can say so in the PR.

function luhn(digits) {
  let total = 0;
  const parity = digits.length % 2;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[i]);
    if (i % 2 === parity) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  }
  return total % 10 === 0;
}

function isCard(value) {
  const digits = value.replace(/\D/g, "");
  return digits.length >= 13 && digits.length <= 19 && "23456".indexOf(digits[0]) !== -1
    && new Set(digits).size > 1 && luhn(digits);
}

// A label pattern matched case-insensitively while the value keeps its own case
// (JavaScript has no inline (?i:...) group in every browser): letters outside
// escapes and character classes become [xX].
function caseless(pattern) {
  let out = "";
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "\\") {
      out += ch + (pattern[i + 1] || "");
      i += 1;
    } else if (ch === "[" && !inClass) {
      inClass = true;
      out += ch;
    } else if (ch === "]" && inClass) {
      inClass = false;
      out += ch;
    } else if (!inClass && /[a-z]/i.test(ch)) {
      out += "[" + ch.toLowerCase() + ch.toUpperCase() + "]";
    } else {
      out += ch;
    }
  }
  return out;
}

const STREET = "(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl"
  + "|Terrace|Parkway|Pkwy|Highway|Hwy)\\.?";
const DATE = "(?:\\d{4}-\\d{2}-\\d{2}|\\d{1,2}/\\d{1,2}/\\d{2,4})";
const NUM = "(?:\\s*(?:no\\.?|number|num|#|id))?\\s*[:#=]?\\s*";
const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const code = (min, max) => "(?=[A-Z0-9-]*\\d)[A-Z0-9-]{" + min + "," + max + "}\\b";

// Pattern that keeps the label and masks the value after it. The label is always
// case-insensitive; caseSensitiveValue keeps a value's capitals (names).
function labelled(label, value, caseSensitiveValue) {
  return new RegExp("(?<label>\\b" + caseless("(?:" + label + ")") + caseless("(?:" + NUM + ")") + ")" + value,
    caseSensitiveValue ? "g" : "gi");
}

// policy category -> patterns, applied in this order (longer, more specific shapes
// first: a card before a phone); a pattern with a "label" group keeps the label.
const DETECTORS = [
  ["email", [/(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])/g]],
  ["credit_card", [/(?<![\w-])\d{4}(?:[ -]?\d{4}){2}[ -]?\d{1,7}(?![\w-])/g]],
  ["financial_account_number", [
    /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b/g,
    labelled("(?:bank\\s+|checking\\s+|savings\\s+)?(?:account|acct|a/c)|routing|IBAN", code(6, 34))]],
  ["ssn", [/(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])/g,
           labelled("SSN|social\\s+security", "\\d{3}\\s\\d{2}\\s\\d{4}\\b")]],
  ["taxpayer_id", [labelled("tax(?:payer)?\\s*id(?:entification)?|EIN|TIN", code(8, 15))]],
  ["passport_number", [labelled("passport", "(?=[A-Z0-9]*\\d)[A-Z0-9]{6,9}\\b")]],
  ["drivers_license_number", [labelled("driver'?s?\\s+licen[cs]e|DL", code(5, 20))]],
  ["medical_records", [labelled("MRN|medical\\s+record|patient\\s+id", code(4, 20))]],
  ["employee_id", [labelled("employee|emp|staff", code(3, 20))]],
  ["school_id", [labelled("student|school", code(3, 20))]],
  ["vehicle_identification_number", [labelled("VIN|vehicle\\s+identification", "[A-HJ-NPR-Z0-9]{17}\\b")]],
  ["mac_address", [/(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])/g]],
  ["ip_address", [new RegExp("(?<![\\w.])(?<!v)(?:" + OCTET + "\\.){3}" + OCTET + "(?![\\w.])", "g"),
                  /(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![\w:])/g]],
  ["fine_location", [labelled("lat(?:itude)?|gps|location|coord(?:inate)?s?",
                              "-?\\d{1,3}\\.\\d{4,},\\s*-?\\d{1,3}\\.\\d{4,}\\b")]],
  ["year_of_birth", [labelled("DOB|D\\.O\\.B\\.?|date\\s+of\\s+birth|born\\s+on|birth\\s*date", DATE),
                     labelled("born\\s+in|year\\s+of\\s+birth|birth\\s+year", "(?:19|20)\\d{2}\\b")]],
  ["birthplace", [labelled("place\\s+of\\s+birth|birth\\s*place",
                           "[A-Z][A-Za-z'.-]+(?:[ ,]+[A-Z][A-Za-z'.-]+){0,3}", true)]],
  ["mothers_maiden_name", [labelled("mother'?s\\s+maiden\\s+name(?:\\s+is)?",
                                    "[A-Z][A-Za-z'-]+(?:\\s[A-Z][A-Za-z'-]+)?", true)]],
  ["phone", [/(?<![\w+(])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\w-])/g,
             /(?<![\w+])\+\d{1,3}[\s.-]?\d{2,5}(?:[\s.-]?\d{2,5}){1,3}(?![\w-])/g,
             labelled("phone|mobile|cell|tel|telephone|fax", "\\+?\\d[\\d\\s().-]{6,}\\d\\b")]],
  ["home_address", [new RegExp("\\b\\d{1,6}\\s+(?:[A-Z][a-z]+\\s){1,3}" + STREET
    + "(?:,\\s*[A-Z][a-z]+(?:\\s[A-Z][a-z]+)*)?(?:,\\s*[A-Z]{2}(?:\\s+\\d{5}(?:-\\d{4})?)?)?", "g")]]
];
const DETECTOR_NAMES = DETECTORS.map((d) => d[0]);

function normalizedCategories(categories) {
  if (typeof categories === "string") categories = [categories];
  if (!categories || !categories.length) return [];
  return Array.from(categories).map((c) => String(c).trim().toLowerCase()).filter((c) => c);
}

/** The policy categories this guard has no text detector for (they are not redacted). */
export function unsupportedPiiCategories(categories) {
  return normalizedCategories(categories).filter((c) => DETECTOR_NAMES.indexOf(c) === -1);
}

// maskPii: one fixed label per category; identifiers keep their last 4 digits.
const MASK_LABEL = {
  phone: "phone", email: "email", home_address: "address", year_of_birth: "dob",
  passport_number: "passport", drivers_license_number: "drivers_license", taxpayer_id: "tax_id",
  employee_id: "employee_id", school_id: "school_id", vehicle_identification_number: "vin",
  ip_address: "ip_address", mac_address: "mac_address", birthplace: "birthplace",
  mothers_maiden_name: "maiden_name", medical_records: "medical", fine_location: "location"
};
const KEEP_LAST4 = new Set(["ssn", "credit_card", "financial_account_number"]);

function last4(value) {
  const digits = [];
  for (let i = 0; i < value.length; i++) if (/\d/.test(value[i])) digits.push(i);
  const keep = new Set(digits.slice(-4));
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    out += (!/[A-Za-z0-9]/.test(ch) || keep.has(i)) ? ch : "*";
  }
  return out;
}

/**
 * text with the personal data of the given policy categories masked for display:
 * identifiers keep their last 4 digits, other values become <masked:label>.
 */
// fn applied to every string inside value, keeping its shape: arrays and plain or class
// objects come back with their text fields masked (a copy; the input is not changed).
function structured(value, fn, depth) {
  depth = depth || 0;
  if (typeof value === "string") return fn(value);
  if (value === null || value === undefined || depth > 8 || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => structured(v, fn, depth + 1));
  if (value instanceof Date || (typeof Buffer !== "undefined" && Buffer.isBuffer(value)) ||
      ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return value;
  const out = Object.create(Object.getPrototypeOf(value));
  for (const key of Object.keys(value)) out[key] = structured(value[key], fn, depth + 1);
  return out;
}

export function maskPii(text, categories) {
  if (typeof text !== "string") return structured(text, (t) => maskPii(t, categories));
  if (!text) return text;
  const wanted = new Set(normalizedCategories(categories));
  let out = text;
  for (const [category, patterns] of DETECTORS) {
    if (!wanted.has(category)) continue;
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      out = out.replace(pattern, function () {
        const args = Array.prototype.slice.call(arguments);
        const match = args[0];
        const groups = typeof args[args.length - 1] === "object" ? args[args.length - 1] : null;
        if (category === "credit_card" && !isCard(match)) return match;
        const label = (groups && groups.label) || "";
        const value = match.slice(label.length);
        if (KEEP_LAST4.has(category)) return label + last4(value);
        return label + "<masked:" + (MASK_LABEL[category] || category) + ">";
      });
    }
  }
  return out;
}

/**
 * text with the personal data of the given policy categories replaced by
 * <redacted:category>; anything else unchanged. categories is the violated
 * policy's runtime.routine.params.categories (e.g. ["ssn", "email", "phone"]);
 * only those are redacted.
 */
export function redactPii(text, categories) {
  if (typeof text !== "string") return structured(text, (t) => redactPii(t, categories));
  if (!text) return text;
  const wanted = new Set(normalizedCategories(categories));
  let out = text;
  for (const [category, patterns] of DETECTORS) {
    if (!wanted.has(category)) continue;
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      out = out.replace(pattern, function () {
        const args = Array.prototype.slice.call(arguments);
        const match = args[0];
        const groups = typeof args[args.length - 1] === "object" ? args[args.length - 1] : null;
        if (category === "credit_card" && !isCard(match)) return match;
        const label = (groups && groups.label) || "";
        return label + "<redacted:" + category + ">";
      });
    }
  }
  return out;
}

// --- model output: dynamic code execution -------------------------------------

const CODE_EXECUTION = [
  ["python_eval_exec", /(?<![\w.])(?:eval|exec|compile|__import__)\s*\(/],
  ["os_command", /\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?)\s*\(/],
  ["subprocess_shell", /\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True/s],
  ["js_eval", /(?<![\w.])(?:eval|new\s+Function|Function)\s*\(/],
  ["js_child_process", /\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"`]/],
  ["shell_eval", /(?:^|[;&|\s])(?:eval|source)\s+['"$]|\b(?:bash|sh|zsh)\s+-c\s+\S/m],
  ["pipe_to_shell", /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/],
  ["destructive_command", /\brm\s+-rf\s+\/|\bmkfs(?:\.\w+)?\s|\bdd\s+if=|:\(\)\s*\{\s*:\|:&\s*\};:/]
];

/**
 * The dynamic code-execution primitives found in text (empty array: none). For model
 * output that is executed, written to disk or shown as runnable code; the caller
 * decides what to do with a finding. Never changes the text.
 */
export function findCodeExecution(text) {
  if (typeof text !== "string" || !text) return [];
  return Array.from(new Set(CODE_EXECUTION.filter(([, p]) => p.test(text)).map(([n]) => n))).sort();
}

// --- uploaded file content: shell commands ---------------------------------------

const CMD = "(?:sudo\\s+)?(?:"
  + "alias\\s+[\\w.-]+=\\S*"
  + "|(?:rg|ripgrep)\\s+[-\\w'\"./*]+"
  + "|curl\\s+(?:-\\S+\\s+)*\\S+"
  + "|wget\\s+(?:-\\S+\\s+)*\\S+"
  + "|rm\\s+(?:-[a-z]+\\s+)*[\\w./~*$-]+"
  + "|echo\\s+[^\\n>]*>>?\\s*\\S+"
  + "|dd\\s+(?:if|of)=\\S+"
  + "|git\\s+(?:clone|push|pull|fetch|reset|checkout|remote|config|rm|apply|am)\\b[^\\n]*"
  + "|tar\\s+-?[a-z]*[xcz][a-z]*f?\\s+\\S+"
  + "|chmod\\s+(?:-[a-z]+\\s+)*[0-7ugoa+=,rwxst-]+\\s+\\S+"
  + "|chown\\s+(?:-[a-z]+\\s+)*[\\w.:-]+\\s+\\S+"
  + "|fsck(?:\\.\\w+)?(?:\\s+-\\S+)*\\s+\\S+"
  + "|mkfs(?:\\.\\w+)?\\s+\\S+"
  + "|shred\\s+(?:-\\S+\\s+)*\\S+"
  + "|(?:eval|source)\\s+\\S+"
  + "|export\\s+[A-Z_][A-Z0-9_]*=\\S*"
  + ")";
const SHELL_LINE = new RegExp("(?:(?<=^)|(?<=\\n)|(?<=[;&|`]))[ \\t]*(?:[$#>]\\s*)?" + CMD + "[^\\n;&|]*", "gi");
const BASE64_SHORT = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])/g;
const LEET_MULTI = [["|-|", "h"], ["|_|", "u"], ["|<", "k"], ["|\\|", "n"], ["/\\", "a"], ["()", "o"]];

function foldLeet(line) {
  for (const [seq, ch] of LEET_MULTI) line = line.split(seq).join(ch);
  let out = "";
  for (const ch of line) out += Object.prototype.hasOwnProperty.call(LEET, ch) ? LEET[ch] : ch;
  return out;
}

function hasShell(text) {
  SHELL_LINE.lastIndex = 0;
  return SHELL_LINE.test(text);
}

function shellSpans(text) {
  const spans = matches(SHELL_LINE, text).map((m) => [m.index, m.index + m[0].length]);
  let offset = 0;
  for (const line of text.split(/(?<=\n)/)) {
    const body = line.replace(/[\r\n]+$/, "");
    const folded = foldLeet(body);
    if (folded !== body && hasShell(folded) && !hasShell(body)) {
      const lead = body.length - body.replace(/^\s+/, "").length;
      spans.push([offset + lead, offset + body.length]);
    }
    offset += line.length;
  }
  for (const m of matches(BASE64_SHORT, text)) {
    const token = m[0];
    if (token.length % 4) continue;
    const decoded = decodeBase64(token);
    if (decoded !== null && hasShell(decoded)) spans.push([m.index, m.index + token.length]);
  }
  spans.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const merged = [];
  for (const [start, end] of spans) {
    const prev = merged[merged.length - 1];
    if (prev && start <= prev[1]) prev[1] = Math.max(prev[1], end);
    else merged.push([start, end]);
  }
  return merged;
}

/** The shell-command lines found in uploaded or fetched content (empty array: none). */
export function findShellCommands(text) {
  if (typeof text !== "string" || !text) return [];
  return shellSpans(text).map(([s, e]) => text.slice(s, e).trim());
}

/** Uploaded or fetched content with each shell command replaced by <suspicious_content_removed>. */
export function removeSuspiciousContent(text) {
  if (typeof text !== "string") return structured(text, removeSuspiciousContent);
  let out = text;
  const spans = shellSpans(text);
  for (let i = spans.length - 1; i >= 0; i--) {
    out = out.slice(0, spans[i][0]) + "<suspicious_content_removed>" + out.slice(spans[i][1]);
  }
  return out;
}
'''
_UNIFAI_GUARD_DTS_SOURCE = r'''// Types for unifaiGuard.js, the prompt-injection and PII guard added by Lineaje UnifAI remediation.
// UNIFAI-GUARD owner="Lineaje UnifAI": generated by UnifAI remediation scans; do not edit.

export declare const UNIFAI_GUARD_MANIFEST: {
  owner: string;
  version: string;
  routines: Record<string, string[]>;
};
export declare const VERSION: string;

/** Attack categories found in text (empty array: none). */
export declare function findPromptAttacks(text: unknown): string[];

/** text with prompt-injection spans replaced by a marker; anything else unchanged. */
export declare function sanitizePrompt<T>(text: T): T;

/** A copy of a chat message list with sanitizePrompt applied to the given roles. */
export declare function sanitizeMessages<T>(messages: T, roles?: readonly string[]): T;

/** The policy categories this guard has no text detector for (they are not redacted). */
export declare function unsupportedPiiCategories(categories: string | readonly string[]): string[];

/** text with the personal data of the given policy categories replaced by <redacted:category>. */
export declare function redactPii<T>(text: T, categories: string | readonly string[]): T;

/** The dynamic code-execution primitives found in model output (empty array: none). */
export declare function findCodeExecution(text: unknown): string[];

/** text with PII masked for display: identifiers keep their last 4 digits, others become <masked:label>. */
export declare function maskPii<T>(text: T, categories: string | readonly string[]): T;

/** The shell-command lines found in uploaded or fetched content (empty array: none). */
export declare function findShellCommands(text: unknown): string[];

/** Uploaded or fetched content with each shell command replaced by <suspicious_content_removed>. */
export declare function removeSuspiciousContent<T>(text: T): T;
'''
# --- END UNIFAI_GUARD_SOURCE ---


def _norm_stub_relpath(path: str) -> str:
    """Repo-relative path used only for stub-identity comparison."""
    p = (path or "").replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    if os.path.basename(p) == "gr_stub_client.py":
        return "gr_stub_client.py"
    return p


def _stub_identity_keys(row: Dict[str, Any]) -> list:
    rel = _norm_stub_relpath(str(row.get("file") or ""))
    try:
        line = int(row.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    ip = str(row.get("insertion_point") or "")
    site = str(row.get("site_id") or "")
    keys: list = []
    if site:
        keys.append(("site", site))
    if rel:
        keys.append(("loc", rel, line, ip))
        if line == 0 and not ip:
            keys.append(("file", rel))
    return keys


def _dedupe_stub_insertions(stubs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse overlapping batches / path aliases into one row per site."""
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for s in stubs:
        if not isinstance(s, dict):
            out.append(s)
            continue
        entry = dict(s)
        rel = _norm_stub_relpath(str(s.get("file") or ""))
        if rel:
            entry["file"] = rel
        keys = _stub_identity_keys(entry)
        if keys and any(k in seen for k in keys):
            if entry.get("new_content"):
                for i, kept in enumerate(out):
                    if not isinstance(kept, dict):
                        continue
                    kept_keys = _stub_identity_keys(kept)
                    if any(k in kept_keys for k in keys):
                        merged = dict(kept)
                        merged["new_content"] = entry["new_content"]
                        merged["status"] = "detected"
                        merged["safe_to_insert"] = True
                        merged["file"] = rel or merged.get("file") or ""
                        out[i] = merged
                        break
            continue
        for k in keys:
            seen.add(k)
        out.append(entry)
    return out


def _collapse_stub_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen_sites: set = set()
    seen_loc: set = set()
    out: List[Dict[str, Any]] = []
    for hit in sorted(hits, key=lambda h: int(h.get("line") or 0)):
        site = str(hit.get("site_id") or "")
        try:
            line = int(hit.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        loc = (line, str(hit.get("insertion_point") or ""))
        if site and site in seen_sites:
            continue
        if loc in seen_loc:
            continue
        if site:
            seen_sites.add(site)
        seen_loc.add(loc)
        out.append(hit)
    return out


def _stub_insertions_from_mcp_result(mcp_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Merge stub_insertions with patched_files / companion_files from the MCP response."""
    stubs = [dict(s) for s in (mcp_result.get("stub_insertions") or [])]
    by_file: Dict[str, str] = {}
    for extra in list(mcp_result.get("patched_files") or []) + list(mcp_result.get("companion_files") or []):
        if not isinstance(extra, dict):
            continue
        rel = _norm_stub_relpath(extra.get("file") or "")
        if rel and extra.get("content") is not None:
            by_file[rel] = extra["content"]
    if not by_file:
        return _dedupe_stub_insertions(stubs)
    applied: set = set()
    for s in stubs:
        rel = _norm_stub_relpath(s.get("file") or "")
        if rel:
            s["file"] = rel
        if rel in by_file:
            s["new_content"] = by_file[rel]
            s["status"] = "detected"
            s["safe_to_insert"] = True
            applied.add(rel)
    for rel, content in by_file.items():
        if rel not in applied:
            stubs.append({
                "file": rel,
                "status": "detected",
                "safe_to_insert": True,
                "new_content": content,
                "line": 0,
            })
    return _dedupe_stub_insertions(stubs)


_MODULE_GLOBALS = frozenset({
    "__file__", "__builtins__", "__path__", "__annotations__", "__dict__", "__cached__",
})

# stdlib modules never imported just to check an attribute (import side effects).
_NO_PROBE_MODULES = frozenset({"antigravity", "this", "turtle", "turtledemo", "tkinter", "idlelib"})


def _module_names_read_before_bound(tree: ast.Module) -> set:
    """Names module-level code reads before the module binds them — a fix
    that calls ``re.compile()`` at line 55 while another fix's ``import re``
    lands at line 123. symtable ignores statement order and counts such a
    name as defined; importing the file raises NameError. Function and lambda
    bodies are skipped (they run later), as are annotations and class bodies."""
    first_bound: dict = {}
    reads: list = []

    def _bind(name: str, line: int) -> None:
        if name not in first_bound or line < first_bound[name]:
            first_bound[name] = line

    def _expr(node) -> None:
        stack = [node]
        while stack:
            n = stack.pop()
            if n is None or isinstance(n, ast.Lambda):
                continue
            if isinstance(n, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                # Loop variables are local to the comprehension; only the first
                # iterable is evaluated in the module's scope.
                local = {t.id for g in n.generators for t in ast.walk(g.target) if isinstance(t, ast.Name)}
                stack.append(n.generators[0].iter)
                inner = [n.key, n.value] if isinstance(n, ast.DictComp) else [n.elt]
                inner += [x for g in n.generators for x in g.ifs] + [g.iter for g in n.generators[1:]]
                reads.extend(
                    x for part in inner for x in ast.walk(part)
                    if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load) and x.id not in local
                )
                continue
            if isinstance(n, ast.Name):
                if isinstance(n.ctx, ast.Load):
                    reads.append(n)
                else:
                    _bind(n.id, n.lineno)
                continue
            if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
                _bind(n.target.id, n.lineno)
            stack.extend(ast.iter_child_nodes(n))

    def _stmts(body) -> None:
        for s in body:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for d in s.decorator_list:
                    _expr(d)
                if isinstance(s, ast.ClassDef):
                    for b in s.bases + [k.value for k in s.keywords]:
                        _expr(b)
                else:
                    for d in s.args.defaults + s.args.kw_defaults:
                        _expr(d)
                _bind(s.name, s.lineno)
            elif isinstance(s, (ast.Import, ast.ImportFrom)):
                for a in s.names:
                    _bind((a.asname or a.name).split(".")[0], s.lineno)
            elif isinstance(s, ast.AnnAssign):
                _expr(s.value)
                _expr(s.target)
            elif isinstance(s, (ast.If, ast.While)):
                _expr(s.test)
                _stmts(s.body)
                _stmts(s.orelse)
            elif isinstance(s, (ast.For, ast.AsyncFor)):
                _expr(s.iter)
                _expr(s.target)
                _stmts(s.body)
                _stmts(s.orelse)
            elif isinstance(s, (ast.With, ast.AsyncWith)):
                for item in s.items:
                    _expr(item.context_expr)
                    _expr(item.optional_vars)
                _stmts(s.body)
            elif isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
                _stmts(s.body)
                for h in s.handlers:
                    _expr(h.type)
                    if h.name:
                        _bind(h.name, h.lineno)
                    _stmts(h.body)
                _stmts(s.orelse)
                _stmts(s.finalbody)
            elif type(s).__name__ == "Match":
                _expr(s.subject)
                for case in s.cases:
                    _expr(case.pattern)
                    _expr(case.guard)
                    _stmts(case.body)
            else:
                _expr(s)

    _stmts(tree.body)
    return {
        n.id for n in reads
        if n.id in first_bound and n.lineno < first_bound[n.id]
    }


def _undefined_names(source: str) -> Optional[set]:
    """Names *source* reads that no enclosing scope binds — each one a
    NameError when that code runs — or None when it can't be analysed
    (syntax error, ``from x import *``).

    Scope-aware via the stdlib ``symtable`` (the interpreter's own name
    resolution): a helper defined inside one function is not visible from
    another, and a parameter removed from a signature but still used in the
    body is caught. Module-level code that reads a name above the line
    that binds it counts as undefined too."""
    try:
        tree = ast.parse(source)
        table = symtable.symtable(source, "<remediation>", "exec")
    except (SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            return None

    known = set(dir(builtins)) | _MODULE_GLOBALS
    for sym in table.get_symbols():
        if sym.is_assigned() or sym.is_imported() or sym.is_namespace():
            known.add(sym.get_name())

    # `global X` + an assignment inside a function also defines X at module level.
    def _declared_globals(t: "symtable.SymbolTable") -> None:
        for sym in t.get_symbols():
            if sym.is_declared_global() and (sym.is_assigned() or sym.is_imported()):
                known.add(sym.get_name())
        for child in t.get_children():
            _declared_globals(child)

    _declared_globals(table)

    undefined: set = set()

    def _walk(t: "symtable.SymbolTable") -> None:
        for sym in t.get_symbols():
            name = sym.get_name()
            if not sym.is_referenced() or name in known:
                continue
            if t.get_type() == "module" or sym.is_global():
                undefined.add(name)
        for child in t.get_children():
            _walk(child)

    _walk(table)
    undefined |= _module_names_read_before_bound(tree)
    return undefined


def _undefined_new_names(new_content: str, original_content: str) -> List[str]:
    """Names that are undefined in the patched file but weren't undefined in
    the original — i.e. NameErrors the fix introduced (``os`` used with no
    ``import os``, a removed parameter still used, a helper nested in the
    wrong function)."""
    new = _undefined_names(new_content)
    if not new:
        return []
    old = _undefined_names(original_content) or set()
    return sorted(new - old)


def _stdlib_import_fixes(name: str, content: str) -> bool:
    """True when ``import <name>`` makes every use of *name* in *content* work:
    *name* is a stdlib module and each use is ``name.attr`` for an attribute
    that module has. ``datetime.now(...)`` is not (that's the class, which
    needs ``from datetime import datetime``)."""
    stdlib = getattr(sys, "stdlib_module_names", frozenset())
    if name not in stdlib or name.startswith("_") or name in _NO_PROBE_MODULES:
        return False
    try:
        module = importlib.import_module(name)
        tree = ast.parse(content)
    except Exception:
        return False
    attrs: set = set()
    attr_value_ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == name:
            attrs.add(node.attr)
            attr_value_ids.add(id(node.value))
    bare = any(
        isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)
        and id(node) not in attr_value_ids
        for node in ast.walk(tree)
    )
    return bool(attrs) and not bare and all(hasattr(module, a) for a in attrs)


# A model allowlist/registry name: APPROVED_MODEL_PREFIXES, ALLOWED_LLMS, ...
_MODEL_ALLOWLIST_NAME_RE = re.compile(
    r"(?i)(approved|allowed|allow|permitted|whitelist).*(model|llm)|(model|llm).*(approved|allowed|allowlist|permitted|whitelist)"
)


def _is_empty_collection(node: ast.AST) -> bool:
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id in ("set", "frozenset", "list", "tuple", "dict")
        and not node.keywords
        and (not node.args or (len(node.args) == 1 and _is_empty_collection(node.args[0])))
    )


def _empty_model_allowlists(tree: ast.AST) -> Dict[str, str]:
    """Model allowlists assigned an empty collection — every model then fails
    the check, so the app refuses the models the organization approved."""
    found: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        if not _is_empty_collection(value):
            continue
        for t in targets:
            if isinstance(t, ast.Name) and _MODEL_ALLOWLIST_NAME_RE.search(t.id):
                found[f"allowlist:{t.id}"] = (
                    f"line {node.lineno}: {t.id} is an empty model allowlist, so every model — "
                    "including approved ones — is rejected"
                )
    return found


# re.<func> → how many positional args it takes before an optional flags argument.
_RE_PATTERN_FUNCS = {
    "compile": 1, "match": 2, "search": 2, "fullmatch": 2, "findall": 2,
    "finditer": 2, "split": 2, "sub": 3, "subn": 3,
}


def _runtime_errors(source: str) -> Optional[Dict[str, str]]:
    """Code that fails every time it runs, keyed so the same problem in the
    original matches: calls whose literal arguments raise (``str.maketrans("abc",
    "ab")``, ``re.compile("(")``) and empty model allowlists. None when *source*
    doesn't parse. compile() and the name check can't see these, and at module
    level a raising call crashes the import."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    errors: Dict[str, str] = _empty_model_allowlists(tree)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)):
            continue
        owner, attr = node.func.value.id, node.func.attr
        try:
            if owner in ("str", "bytes") and attr == "maketrans" and not node.keywords:
                args = [ast.literal_eval(a) for a in node.args]
                (str.maketrans if owner == "str" else bytes.maketrans)(*args)
            elif (owner == "re" and attr in _RE_PATTERN_FUNCS and not node.keywords
                  and len(node.args) == _RE_PATTERN_FUNCS[attr]):
                # Only without flags: re.VERBOSE changes how the pattern parses.
                pattern = ast.literal_eval(node.args[0])
                if isinstance(pattern, (str, bytes)):
                    re.compile(pattern)
        except (ValueError, TypeError, re.error) as exc:
            if isinstance(exc, ValueError) and "malformed node" in str(exc):
                continue  # an argument isn't a literal
            errors[ast.unparse(node)] = f"line {node.lineno}: {type(exc).__name__}: {exc}"
        except (SyntaxError, MemoryError, RecursionError):
            continue
    return errors


def _new_runtime_errors(new_content: str, original_content: str) -> List[str]:
    """Always-failing code (see :func:`_runtime_errors`) the patch introduced."""
    new = _runtime_errors(new_content)
    if not new:
        return []
    old = _runtime_errors(original_content) or {}
    return [msg for call, msg in new.items() if call not in old]


def _add_missing_stdlib_imports(content: str, original_content: str) -> Tuple[str, List[str]]:
    """Add ``import X`` for each undefined name the fixes introduced that a
    stdlib import fixes. Returns (content, names still undefined)."""
    missing = _undefined_new_names(content, original_content)
    to_import = [n for n in missing if _stdlib_import_fixes(n, content)]
    if not to_import:
        return content, missing
    lines = content.splitlines(keepends=True)
    insert_at = safe_prefix_insert_index(lines)
    # Prefer the end of the leading import block, so new imports sit with the rest.
    for node in ast.parse(content).body:
        if node.end_lineno <= insert_at:
            continue  # docstring / __future__ imports
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            break
        insert_at = node.end_lineno
    if insert_at and insert_at <= len(lines) and not lines[insert_at - 1].endswith("\n"):
        lines[insert_at - 1] += "\n"
    lines[insert_at:insert_at] = [f"import {n}\n" for n in to_import]
    logger.info("Added missing import(s) for fix: %s", ", ".join(to_import))
    content = "".join(lines)
    still = _undefined_new_names(content, original_content)
    return content, still


# ---------------------------------------------------------------------------
# C-38 NEW-30 (Wega PR #93): a fix may not import a module the app does not have.
# ``from lineaje_guardrail import lineaje_guardrail`` (no such module anywhere)
# stopped the backend at startup. Same rule as ``unifai_verify/import_gate.py``,
# judged against the checked-out repo: a newly imported module must be stdlib,
# the shared guard, a repo module or package, a module the app already imports,
# or a declared dependency.
_IMPORT_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", "site-packages", ".lineaje",
})
_IMPORT_ALWAYS = frozenset({"__future__", "unifai_guard"})
_DIST_IMPORT_ALIASES = {
    "pyyaml": "yaml", "python_dotenv": "dotenv", "scikit_learn": "sklearn", "pillow": "PIL",
    "beautifulsoup4": "bs4", "opencv_python": "cv2", "opencv_python_headless": "cv2",
    "python_multipart": "multipart", "protobuf": "google", "python_jose": "jose", "pyjwt": "jwt",
    "python_docx": "docx", "python_pptx": "pptx", "pymupdf": "fitz", "attrs": "attr",
    "psycopg2_binary": "psycopg2", "pycryptodome": "Crypto", "google_generativeai": "google",
    "google_cloud_storage": "google", "dnspython": "dns", "python_dateutil": "dateutil",
    "faiss_cpu": "faiss", "faiss_gpu": "faiss", "pypdf2": "PyPDF2",
    "office365_rest_python_client": "office365", "azure_ai_formrecognizer": "azure",
}
_DEP_MANIFEST = re.compile(r"^(?:requirements[^/]*\.txt|pyproject\.toml|setup\.py|setup\.cfg|Pipfile)$")
_REQ_LINE_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_QUOTED_REQ_NAME = re.compile(r"""["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ]|["'])""")
_REPO_MODULES: Dict[str, set] = {}


def _norm_module(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _top_imports(source: str) -> Optional[Dict[str, int]]:
    """Top-level module of each absolute import in *source* → first line; None if it doesn't parse."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    out: Dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.setdefault(alias.name.split(".")[0], node.lineno)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            out.setdefault(node.module.split(".")[0], node.lineno)
    return out


def _declared_deps(filename: str, text: str) -> set:
    names: set = set()
    if filename.endswith(".txt"):
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            m = _REQ_LINE_NAME.match(line) if line and not line.startswith("-") else None
            if m:
                names.add(_norm_module(m.group(1)))
    else:
        names.update(_norm_module(m.group(1)) for m in _QUOTED_REQ_NAME.finditer(text))
        if filename == "Pipfile":
            for line in text.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", line)
                if m:
                    names.add(_norm_module(m.group(1)))
    return names | {_norm_module(_DIST_IMPORT_ALIASES[n]) for n in names if n in _DIST_IMPORT_ALIASES}


def _repo_known_modules(source_dir: str) -> set:
    """Normalised names a fix may import in the checked-out repo (cached per checkout)."""
    key = os.path.realpath(source_dir)
    if key in _REPO_MODULES:
        return _REPO_MODULES[key]
    known: set = set()
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in _IMPORT_SKIP_DIRS]
        rel_root = os.path.relpath(root, source_dir)
        if rel_root != ".":
            known.update(_norm_module(p) for p in rel_root.replace("\\", "/").split("/") if p)
        for fn in files:
            stem, ext = os.path.splitext(fn)
            if ext in (".py", ".pyi", ".so", ".pyd"):
                known.add(_norm_module(stem))
            if ext != ".py" and not _DEP_MANIFEST.match(fn):
                continue
            try:
                path = os.path.join(root, fn)
                if os.path.getsize(path) > 2_000_000:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if ext == ".py":
                known.update(_norm_module(m) for m in (_top_imports(text) or {}))
            if _DEP_MANIFEST.match(fn):
                known.update(_declared_deps(fn, text))
    _REPO_MODULES[key] = known
    return known


def _unresolved_new_imports(content: str, original: str, source_dir: str) -> List[str]:
    """Modules *content* newly imports that the repo does not have (sorted)."""
    new = _top_imports(content)
    if not new:
        return []
    old = _top_imports(original) or {}
    stdlib = frozenset(getattr(sys, "stdlib_module_names", ())) | frozenset(sys.builtin_module_names)
    candidates = [m for m in new if m not in old and m not in stdlib and m not in _IMPORT_ALWAYS]
    if not candidates:
        return []
    known = _repo_known_modules(source_dir)
    return sorted(m for m in candidates if _norm_module(m) not in known)


def _drop_unresolved_imports(content: str, original: str, source_dir: str, rel: str) -> Tuple[str, List[str]]:
    """(content, modules still unresolved). A module-level import of a module the repo
    does not have, whose names the file never uses, is removed: it could only stop the
    app at startup. One the code uses is kept and returned, so the caller drops the
    fixes that use it."""
    missing = _unresolved_new_imports(content, original, source_dir)
    if not missing:
        return content, []
    tree = ast.parse(content)
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    lines = content.splitlines(keepends=True)
    removed: List[str] = []
    for node in reversed(tree.body):
        if isinstance(node, ast.Import):
            mods = [a.name.split(".")[0] for a in node.names]
            bound = [a.asname or a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            mods = [node.module.split(".")[0]]
            bound = [a.asname or a.name for a in node.names]
        else:
            continue
        if not all(m in missing for m in mods) or any(b in used for b in bound):
            continue
        start, end = node.lineno - 1, (node.end_lineno or node.lineno)
        stmt = "".join(lines[start:end]).strip()
        if not stmt.startswith(("import ", "from ")) or ";" in stmt:
            continue
        del lines[start:end]
        removed.append(stmt)
    if removed:
        content = "".join(lines)
        logger.warning(
            "Removed from the fix for %s an import of a module that does not exist (it would stop the app "
            "at startup): %s", rel, " | ".join(reversed(removed)),
        )
    still = _unresolved_new_imports(content, original, source_dir)
    if still:
        logger.warning("Fix for %s imports module(s) that do not exist: %s", rel, ", ".join(still))
    return content, still


def _checked_server_content(rel: str, new_content: str, source_dir: str) -> Optional[str]:
    """Server-sent whole-file content for *rel*, or None when committing it
    would leave a Python file that can't be imported: a SyntaxError, or a name
    the change uses but never defines. A missing stdlib import (``os``,
    ``time``, …) is added instead of rejecting the file. Non-Python files, and
    Python files that didn't compile before the change, pass through."""
    if not rel.endswith(".py"):
        return new_content
    original = ""
    abs_path = os.path.join(source_dir, rel)
    if os.path.isfile(abs_path):
        with open(abs_path, encoding="utf-8", errors="replace") as fh:
            original = fh.read()
        if validate_python_source(original, rel) is not None:
            return new_content
    syntax_err = validate_python_source(new_content, rel)
    if syntax_err:
        logger.warning("Skipped remediation for %s — it would not compile: %s", rel, syntax_err)
        return None
    raises = _new_runtime_errors(new_content, original)
    if raises:
        logger.warning("Skipped remediation for %s — it would fail on every run: %s", rel, "; ".join(raises))
        return None
    content, undefined = _add_missing_stdlib_imports(new_content, original)
    if undefined:
        logger.warning(
            "Skipped remediation for %s — it uses undefined name(s): %s", rel, ", ".join(undefined),
        )
        return None
    content, missing = _drop_unresolved_imports(content, original, source_dir, rel)
    if missing:
        logger.warning(
            "Skipped remediation for %s — it imports module(s) that do not exist: %s", rel, ", ".join(missing),
        )
        return None
    return content


def apply_stub_insertions_to_clone(
    stub_insertions: List[Dict[str, Any]],
    source_dir: str,
) -> Dict[str, str]:
    """Apply server-computed stub_insertions. Returns repo-relative path → content.

    Unsafe / missing / invalid hits are dropped silently — they are not logged
    and are not returned as skipped/failed rows.
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    validated: Dict[str, str] = {}
    for s in _dedupe_stub_insertions(stub_insertions):
        rel = _norm_stub_relpath(s.get("file") or "")
        if not rel:
            continue
        if s.get("status") != "detected":
            continue  # "already_present" — nothing to do
        if s.get("new_content"):
            # Server already instrumented the extracted archive — write the
            # whole file rather than re-applying proposed_stub line-by-line.
            content = _checked_server_content(rel, s["new_content"], source_dir)
            if content is not None:
                validated[rel] = content
            continue
        if rel in validated:
            continue
        if not s.get("safe_to_insert"):
            continue
        by_file.setdefault(rel, []).append(s)

    for rel_path, hits in by_file.items():
        if rel_path in validated:
            continue
        abs_path = os.path.join(source_dir, rel_path)
        if not os.path.isfile(abs_path):
            continue

        with open(abs_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        ext = pathlib.Path(rel_path).suffix.lower()

        sorted_hits = sorted(_collapse_stub_hits(hits), key=lambda h: h.get("line", 0), reverse=True)
        needs_import = False
        for hit in sorted_hits:
            proposed = hit.get("proposed_stub") or ""
            if not proposed:
                continue
            site = str(hit.get("site_id") or "")
            joined = "".join(lines)
            marker = f"site_id={site!r}" if site else ""
            if (marker and marker in joined) or proposed in joined:
                continue
            line = int(hit.get("line") or 0)
            # 1-based line; insert_after=True (result/lhs patterns) must land
            # AFTER the line assigning the variable the stub references —
            # inserting before it is a NameError.
            idx = max(0, line if hit.get("insert_after") else line - 1)
            idx = min(idx, len(lines))
            lines.insert(idx, proposed + "\n")
            needs_import = True

        if needs_import:
            import_block = next(
                (h.get("import_needed") for h in hits if h.get("import_needed")), "",
            )
            marker = _GR_CHECK_MARKERS.get(ext, "def gr_check(")
            if import_block and marker not in "".join(lines):
                lines.insert(safe_prefix_insert_index(lines), import_block.rstrip("\n") + "\n")

        new_content = "".join(lines)
        if ext == ".py":
            syntax_err = validate_python_source(new_content, abs_path)
            if syntax_err:
                continue

        validated[rel_path] = new_content

    if validated:
        logger.info("Applied guardrail stubs in %d file(s)", len(validated))
    return validated


_HARDCODED_GR_ORIGIN = (
    lambda _p: f"{_p.scheme}://{_p.netloc}" if _p.scheme and _p.netloc else ""
)(urllib.parse.urlsplit(MCP_SERVER_URL))
_ENV_EXAMPLE_HEADER = (
    "# Lineaje UnifAI guardrail stub runtime configuration.\n"
    "# Generated by the Lineaje hybrid scan — read directly by gr_stub_client.py's\n"
    "# env-var overrides at POST /enforce time.\n"
    "# If the Lineaje GR/guardrail service runs on the same VM as this codebase,\n"
    "# use https://localhost/enforce instead of a public IP or hostname.\n"
    "\n"
)


def _usable_scan_refresh_token(raw: str) -> str:
    """SCIM refresh token only — never a JWT, URL, or identity ``lineaje_pat_``."""
    s = _normalize_token(raw)
    if not s or s.startswith("http"):
        return ""
    if s.count(".") == 2 and s.startswith("eyJ"):
        return ""
    if s.startswith("lineaje_pat"):
        return ""
    return s


def _origin_for_gr_manifest(server_url: str) -> str:
    """scheme://host[:port] this scan actually connected to, minus any path
    (e.g. the ``/mcp`` in ``--mcp-server-url``) — or "" if unusable (missing,
    unparseable, or loopback: a customer's own runtime guardrail stub cannot
    reach "localhost" meaning this CI runner)."""
    s = (server_url or "").strip()
    if not s:
        return ""
    try:
        parsed = urllib.parse.urlsplit(s)
    except ValueError:
        return ""
    if not parsed.scheme or not parsed.netloc:
        return ""
    host = (parsed.hostname or "").strip().lower()
    if host in ("localhost", "127.0.0.1", "::1") or host.startswith("127."):
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _upsert_env_file_content(existing_text: str, updates: Dict[str, str], header: str) -> str:
    """Write or update ``KEY=VALUE`` entries in ``.env``-style text.

    Mirrors mcp_server.py's ``_upsert_env_file`` minus filesystem I/O —
    ``validated_fixes`` only ever holds content in memory here.
    """
    lines = existing_text.splitlines() if existing_text.strip() else header.splitlines()
    written_keys: set = set()
    new_lines: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            written_keys.add(key)
        else:
            new_lines.append(line)
    for key, val in updates.items():
        if key not in written_keys:
            new_lines.append(f"{key}={val}")
    return "\n".join(new_lines) + "\n"


def _ensure_env_example_in_validated_fixes(
    validated_fixes: Dict[str, str],
    source_dir: str = "",
    refresh_token: str = "",
    server_url: str = "",
) -> None:
    """Write this scan's own SCIM refresh token + MCP server origin into
    customer ``.env.example`` as ``GR_SERVICE_URL`` / ``LINEAJE_REFRESH_TOKEN``
    — the exact env vars ``gr_stub_client.py`` reads as overrides at
    POST /enforce time. Mirrors ``gha_repo_scan.py``'s
    ``_ensure_refresh_token_in_validated_fixes`` and mcp_server.py's
    ``_write_guardrail_runtime_manifest`` so all three insertion paths ship
    the same runtime config file.
    """
    rel = _GUARDRAIL_MANIFEST_REL
    rt = _usable_scan_refresh_token(refresh_token)
    existing_text = validated_fixes.get(rel, "")
    m = re.search(r"^LINEAJE_REFRESH_TOKEN=(.*)$", existing_text, re.MULTILINE)
    # This scan's own credential (rt) wins over whatever was already written
    # (keep) — a pre-existing value here is at best a separately-minted
    # credential for some other tenant, never the one that actually ran this
    # scan. Only fall back to it when this script somehow has no usable
    # token of its own.
    keep = _usable_scan_refresh_token(m.group(1).strip() if m else "")
    token = rt or keep
    if not token:
        logger.warning(
            "No SCIM refresh token for %s — set LINEAJE_PAT_TOKEN "
            "(do not store a JWT or lineaje_pat_ identity PAT)",
            rel,
        )
        return
    # Likewise: the MCP server URL this scan actually used (minus its /mcp
    # path) wins over the hardcoded hosted SaaS origin — a customer's own
    # runtime guardrail stub cannot reach "localhost" meaning this runner,
    # which is why --mcp-server-url is sometimes pointed at localhost/a
    # private IP to route around Azure's public-IP hairpin-NAT limitation.
    base = _origin_for_gr_manifest(server_url) or _HARDCODED_GR_ORIGIN
    updated = _upsert_env_file_content(
        existing_text,
        {"GR_SERVICE_URL": f"{base}/enforce", "LINEAJE_REFRESH_TOKEN": token},
        _ENV_EXAMPLE_HEADER,
    )
    validated_fixes[rel] = updated
    if source_dir:
        dest = os.path.join(source_dir, rel)
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(updated)
        except OSError as exc:
            logger.warning("Could not write %s: %s", dest, exc)
    logger.info("Customer %s LINEAJE_REFRESH_TOKEN=set (SCIM refresh token)", rel)


def _run_mcp_scan_via_client(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
    head_sha: str = "",
    is_last_batch: bool = True,
    sbom_id: str = "",
    run_id: str = "",
) -> Dict[str, Any]:
    from mcp import ClientSession

    async def _scan() -> Dict[str, Any]:
        base_args: Dict[str, Any] = {
            "source_code_repo": source_code_repo,
            "branch_or_tag": branch,
            "files_to_scan": files_to_scan,
        }
        upload_args: Dict[str, Any] = dict(base_args)
        resolved_sbom = (sbom_id or "").strip()
        if resolved_sbom:
            upload_args["sbom_id"] = resolved_sbom
        resolved_run_id = (run_id or "").strip()
        if resolved_run_id:
            upload_args["run_id"] = resolved_run_id
        with open(archive_path, "rb") as _fh:
            upload_args["archive_content_base64"] = base64.b64encode(_fh.read()).decode("ascii")
        scm_headers: Dict[str, str] = {"X-Unifai-Commit-Sha": head_sha} if head_sha else {}

        tok1 = bearer_getter()
        async with streamablehttp_client(
            server_url, headers={"Authorization": f"Bearer {tok1}", **scm_headers},
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                # logger.info("MCP step 1/3: get_upload_url")
                upload_result = _parse_tool_result(
                    await session.call_tool("get_upload_url", arguments=upload_args)
                )
                if not upload_result.get("success"):
                    raise RuntimeError(f"get_upload_url failed: {upload_result.get('error', upload_result)}")
                archive_id = upload_result["archive_id"]
                presigned_url = upload_result["presigned_url"]
                resolved_sbom = (upload_result.get("sbom_id") or resolved_sbom or "").strip()
                resolved_run_id = (upload_result.get("run_id") or resolved_run_id or "").strip()
                # False when a hybrid server kept the source on its own host; missing
                # (None) on servers older than that flag.
                source_s3_uploaded = upload_result.get("source_archive_s3_uploaded")


        if presigned_url:
            # logger.info("MCP step 2/3: upload to S3")
            _upload_to_s3(presigned_url, archive_path)

        tok2 = bearer_getter()
        sse_timeout = int(os.environ.get("UNIFAI_MCP_SSE_READ_TIMEOUT", "1800"))
        async with streamablehttp_client(
            server_url,
            headers={"Authorization": f"Bearer {tok2}", **scm_headers},
            sse_read_timeout=sse_timeout,
        ) as (read2, write2, _):
            async with ClientSession(read2, write2) as session2:
                await session2.initialize()
                # logger.info("MCP step 3/3: analyze_uploaded_archive (timeout=%ds)", sse_timeout)
                analyze_args = dict(base_args)
                analyze_args["archive_id"] = archive_id
                # This script's own URL to reach the MCP server — more reliable
                # than any guess the server could make about its own address.
                analyze_args["mcp_server_location"] = server_url
                # Required so evidence.source_metadata.evidence_type is scm_scan
                # (the server docstring: "Scripts and GitHub Actions MUST pass
                # scm_scan") instead of defaulting to ide_scan.
                analyze_args["scan_type"] = "scm_scan"
                analyze_args["is_last_batch"] = is_last_batch
                if resolved_sbom:
                    analyze_args["sbom_id"] = resolved_sbom
                if resolved_run_id:
                    analyze_args["run_id"] = resolved_run_id
                result = _parse_tool_result(
                    await session2.call_tool("analyze_uploaded_archive", arguments=analyze_args)
                )
                if resolved_sbom and not (result.get("sbom_id") or "").strip():
                    result["sbom_id"] = resolved_sbom
                if resolved_run_id and not (result.get("run_id") or "").strip():
                    result["run_id"] = resolved_run_id
                result["source_archive_s3_uploaded"] = (
                    True if presigned_url else source_s3_uploaded
                )
                return result

    return asyncio.run(_scan())


def run_mcp_scan(
    server_url: str,
    bearer_getter: Callable[[], str],
    source_code_repo: str,
    branch: str,
    files_to_scan: List[str],
    archive_path: str,
    head_sha: str = "",
    is_last_batch: bool = True,
    sbom_id: str = "",
    run_id: str = "",
) -> Dict[str, Any]:
    logger.info("MCP scan: %d files, repo=%s, branch=%s", len(files_to_scan), source_code_repo, branch)
    return _run_mcp_scan_via_client(
        server_url, bearer_getter, source_code_repo, branch, files_to_scan, archive_path,
        head_sha=head_sha, is_last_batch=is_last_batch, sbom_id=sbom_id, run_id=run_id,
    )

# ===========================================================================
# Parallel batch scan
# ===========================================================================

def parallel_batch_scan(
    batches: List[List[str]],
    source_dir: str,
    temp_dir: str,
    source_code_repo: str,
    branch: str,
    head_sha: str,
    run_id: str,
    server_url: str,
    bearer_getter: Callable[[], str],
    max_workers: int = MAX_SCAN_WORKERS,
    manifest_files: Optional[List[str]] = None,
) -> Tuple[
    List[Dict[str, Any]], List[Dict[str, Any]], List[str], List[Dict[str, str]],
    int, List[str], List[Dict[str, Any]], Dict[str, Any],
]:
    all_violations: List[Dict[str, Any]] = []
    all_remediation_actions: List[Dict[str, Any]] = []
    all_reports: List[str] = []
    all_aibom: List[Dict[str, str]] = []
    all_stub_insertions: List[Dict[str, Any]] = []
    # What the server PUT to Lineaje S3, plus whether any batch's source archive went too.
    uploaded: Dict[str, Any] = {"entities": [], "findings": [], "source_archive_s3_uploaded": None}
    aibom_seen: set = set()
    failed_batch_count = 0
    failure_details: List[str] = []
    lock = threading.Lock()
    scan_sbom_id = ""

    def _scan_leaf(label: str, batch_files: List[str]) -> Dict[str, Any]:
        nonlocal scan_sbom_id
        logger.info("Batch %s/%d: %d files", label, len(batches), len(batch_files))
        archive_path = create_batch_archive(
            source_dir, temp_dir, batch_files,
            source_code_repo, branch, head_sha, label, run_id=run_id,
            manifest_files=manifest_files if str(label) == "1" else None,
        )
        retain_batch_archive(archive_path)
        result = run_mcp_scan(
            server_url, bearer_getter, source_code_repo, branch, batch_files, archive_path,
            head_sha=head_sha, is_last_batch=True, sbom_id=scan_sbom_id, run_id=run_id,
        )
        with lock:
            resolved_sbom = (result.get("sbom_id") or "").strip()
            if resolved_sbom and not scan_sbom_id:
                scan_sbom_id = resolved_sbom
        return result

    def _scan_one(batch_idx: int, batch_files: List[str]) -> Tuple[int, List[Tuple[str, Dict[str, Any]]]]:
        """Scan a top-level batch, splitting in half and retrying on 413
        (request too large for the mcp SDK's 4 MiB body cap) until every leaf
        either succeeds or can't be split further. Returns one (label,
        result) pair per leaf batch that was actually sent."""

        def _run(label: str, files: List[str]) -> List[Tuple[str, Dict[str, Any]]]:
            try:
                return [(label, _scan_leaf(label, files))]
            except BaseException as exc:
                if not _is_payload_too_large(exc):
                    raise
                split = split_batch_keeping_manifests_whole(files)
                if not split:
                    # Can't get smaller: skip these files, keep the rest of the batch.
                    detail = (
                        f"Batch {label}: {len(files)} file(s) not scanned, over the MCP "
                        f"request size limit (413): {', '.join(files)}"
                    )
                    logger.warning("%s", detail)
                    with lock:
                        failure_details.append(detail)
                    return []
                first_half, second_half = split
                logger.warning(
                    "Batch %s: 413 Request Entity Too Large (%d files) — "
                    "splitting into %d + %d files and retrying each half",
                    label, len(files), len(first_half), len(second_half),
                )
                return _run(f"{label}a", first_half) + _run(f"{label}b", second_half)

        return batch_idx, _run(str(batch_idx), batch_files)

    def _collect(label: str, mcp_result: Dict[str, Any]) -> None:
        batch_actions = mcp_result.get("remediation_actions", [])
        batch_violations = list(mcp_result.get("violations") or [])
        if not batch_violations:
            batch_violations = [
                {k: v for k, v in a.items() if k != "fix_code"}
                for a in batch_actions
                if a.get("file")
            ]
        batch_report = mcp_result.get("report", "")
        batch_aibom = mcp_result.get("aibom", [])
        batch_stub_insertions = _stub_insertions_from_mcp_result(mcp_result)
        # Errors the server hit while scanning this batch (a policy whose
        # evaluation failed, a remediation that crashed, ...). The batch itself
        # succeeded, so these don't count as a failed batch, but the results
        # are incomplete and the caller has to be told.
        batch_scan_errors = [
            f"Batch {label}: {err}"
            for err in (mcp_result.get("scan_errors") or [])
            if str(err or "").strip()
        ]
        for err in batch_scan_errors:
            logger.warning("%s", err)
        logger.info(
            "Batch %s/%d done: status=%s violations=%d aibom=%d stub_insertions=%d",
            label, len(batches), mcp_result.get("status", "unknown"),
            len(batch_violations), len(batch_aibom), len(batch_stub_insertions),
        )
        with lock:
            all_violations.extend(batch_violations)
            all_remediation_actions.extend(batch_actions)
            all_stub_insertions.extend(batch_stub_insertions)
            failure_details.extend(batch_scan_errors)
            if batch_report:
                all_reports.append(batch_report)
            uploaded["entities"].extend(mcp_result.get("uploaded_entities_json") or [])
            uploaded["findings"].extend(mcp_result.get("uploaded_findings_json") or [])
            src_flag = mcp_result.get("source_archive_s3_uploaded")
            if src_flag is not None:
                uploaded["source_archive_s3_uploaded"] = bool(
                    uploaded["source_archive_s3_uploaded"]) or bool(src_flag)
            for entry in batch_aibom:
                key = (entry.get("name", ""), entry.get("source_file", ""))
                if key not in aibom_seen:
                    aibom_seen.add(key)
                    all_aibom.append(entry)

    workers = min(len(batches), max_workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(_scan_one, idx, files): idx for idx, files in enumerate(batches, 1)}
        for future in as_completed(future_map):
            batch_idx = future_map[future]
            try:
                _, leaf_results = future.result()
                for label, mcp_result in leaf_results:
                    _collect(label, mcp_result)
            except BaseException as exc:
                failed_batch_count += 1
                detail = f"Batch {batch_idx}/{len(batches)} failed: {_describe_exception(exc)}"
                logger.error("%s", detail)
                failure_details.append(detail)

    return (
        all_violations, all_remediation_actions, all_reports, all_aibom,
        failed_batch_count, failure_details, all_stub_insertions, uploaded,
    )

# ===========================================================================
# Report merging — combine each batch's own markdown report (server-rendered,
# one full "# LINEAJE AI POLICY REPORT" per batch) into a single report with
# one Section 1 / 2 / 3 and one Enforcement Summary, instead of N reports
# concatenated back-to-back (one per batch).
# ===========================================================================

_REPORT_SECTION_HEADERS = [
    "## Enforcement Summary",
    "### SECTION 1: AIBOM Discovery",
    "### SECTION 2: Policy Violations",
    "### SECTION 3: Controls Enforced",
    "### AI Component Relationship Graph",
    "### Phase Timing",
]

_ENFORCEMENT_PREVIEW_CAP = 12


def _split_report_sections(report: str) -> Dict[str, str]:
    """*report* → {header: content up to the next known header}, plus the
    text before the first header under ``__preamble__``."""
    positions = sorted(
        (idx, h) for h in _REPORT_SECTION_HEADERS for idx in [report.find(h)] if idx != -1
    )
    sections: Dict[str, str] = {"__preamble__": report[: positions[0][0]] if positions else report}
    for i, (idx, h) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(report)
        sections[h] = report[idx + len(h): end]
    return sections


def _table_rows(block: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    """First markdown table in *block* → (header row, separator row, data rows)."""
    header = sep = None
    data: List[str] = []
    for line in block.splitlines():
        s = line.rstrip()
        if not s.lstrip().startswith("|"):
            continue
        if header is None:
            header = s
        elif sep is None:
            sep = s
        elif not _is_placeholder_row(s):
            data.append(s)
    return header, sep, data


_ENFORCEMENT_PLACEHOLDERS = ("No violations detected.",)
_ENFORCEMENT_COUNT_RE = re.compile(r"(\d+)\s+(remediated|notified)")


def _enforcement_bullet_lines(block: str) -> List[str]:
    """Item lines in an Enforcement Summary block (``ℹ️ **Notified:** …``) —
    not the italic "…and N more" line, the "**Summary:**" line, table rows,
    ``---`` dividers or the "No violations detected." placeholder."""
    return [
        line.strip() for line in block.splitlines()
        if line.strip()
        and not line.strip().startswith(("*", "#", "|", "---"))
        and line.strip() not in _ENFORCEMENT_PLACEHOLDERS
    ]


def _enforcement_counts(block: str) -> Dict[str, int]:
    """``**Summary:** 3 remediated, 2 notified`` → {"remediated": 3, "notified": 2}."""
    counts = {"remediated": 0, "notified": 0}
    for line in block.splitlines():
        if line.strip().startswith("**Summary:**"):
            for n, kind in _ENFORCEMENT_COUNT_RE.findall(line):
                counts[kind] += int(n)
    return counts


def _is_placeholder_row(row: str) -> bool:
    """``| — | — | … |`` rows a batch emits when its table is empty."""
    cells = [c.strip() for c in row.strip().strip("|").split("|")]
    return bool(cells) and cells[0] == "—"


def _mermaid_body(block: str) -> str:
    m = re.search(r"```mermaid\n(.*?)```", block, re.DOTALL)
    return m.group(1) if m else ""


def _merge_mermaid_bodies(bodies: List[str]) -> str:
    """Concatenate per-batch mermaid graphs into one, renaming node ids per
    batch (``model_1`` → ``b0_model_1``) so batches never collide, and
    deduping the (static, identical every time) ``classDef`` lines.

    Node ids can appear more than once per line — as both endpoints of an
    edge (``agent_4 -->|uses| model_7``), or as the subject of a ``class``
    assignment — so renaming has to replace every whole-word occurrence of
    a batch's declared ids in its own lines, not just a line's leading token.
    """
    node_def_lines: List[str] = []
    other_lines: List[str] = []
    classdef_lines: List[str] = []
    seen_classdef: set = set()
    for batch_idx, body in enumerate(bodies):
        declared_ids = re.findall(r"^\s*(\w+)\s*[\[\(\{]", body, re.MULTILINE)
        rename = {nid: f"b{batch_idx}_{nid}" for nid in declared_ids}
        id_pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in rename) + r")\b") if rename else None

        for raw_line in body.splitlines():
            s = raw_line.strip()
            if not s or s == "graph TD":
                continue
            if s.startswith("classDef"):
                if s not in seen_classdef:
                    seen_classdef.add(s)
                    classdef_lines.append(s)
                continue
            renamed = id_pattern.sub(lambda m: rename[m.group(1)], s) if id_pattern else s
            if re.match(r"^\w+\s*[\[\(\{]", s):
                node_def_lines.append(renamed)
            else:
                other_lines.append(renamed)
    lines = ["graph TD"] + [f"    {l}" for l in node_def_lines] + [f"    {l}" for l in other_lines]
    if classdef_lines:
        lines.append("")
        lines.extend(f"    {l}" for l in classdef_lines)
    return "\n".join(lines)


def _dedupe_preserve_order(rows: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for r in rows:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _merge_batch_reports(
    reports: List[str],
    *,
    total_violations: int,
    total_remediation_actions: int,
    total_elapsed: float,
) -> str:
    """Combine each batch's own full markdown report into one report with a
    single Enforcement Summary, Section 1 (AIBOM Discovery), Section 2
    (Policy Violations), Section 3 (Controls Enforced), relationship graph,
    and phase timing — rather than showing one full report per batch.
    """
    reports = [r for r in reports if r and r.strip()]
    if not reports:
        return ""
    if len(reports) == 1:
        return reports[0]

    project_scanned = ""
    enforcement_bullets: List[str] = []
    enforcement_counts = {"remediated": 0, "notified": 0}
    s1_header = s1_sep = None
    s1_rows: List[str] = []
    s2_header = s2_sep = None
    s2_rows: List[str] = []
    s3_header = s3_sep = None
    s3_rows: List[str] = []
    mermaid_bodies: List[str] = []
    phase_totals: Dict[str, float] = {}
    phase_order: List[str] = []

    for report in reports:
        sections = _split_report_sections(report)
        if not project_scanned:
            m = re.search(r"\*\*Project Scanned:\*\*\s*`([^`]*)`", sections.get("__preamble__", ""))
            if m:
                project_scanned = m.group(1)

        enforcement_block = sections.get("## Enforcement Summary", "")
        enforcement_bullets.extend(_enforcement_bullet_lines(enforcement_block))
        for kind, n in _enforcement_counts(enforcement_block).items():
            enforcement_counts[kind] += n

        h, sep, rows = _table_rows(sections.get("### SECTION 1: AIBOM Discovery", ""))
        s1_header, s1_sep = s1_header or h, s1_sep or sep
        s1_rows.extend(rows)

        h, sep, rows = _table_rows(sections.get("### SECTION 2: Policy Violations", ""))
        s2_header, s2_sep = s2_header or h, s2_sep or sep
        s2_rows.extend(rows)

        h, sep, rows = _table_rows(sections.get("### SECTION 3: Controls Enforced", ""))
        s3_header, s3_sep = s3_header or h, s3_sep or sep
        s3_rows.extend(rows)

        mermaid_bodies.append(_mermaid_body(sections.get("### AI Component Relationship Graph", "")))

        _, _, phase_rows = _table_rows(sections.get("### Phase Timing", ""))
        for row in phase_rows:
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            if len(cells) != 2:
                continue
            phase = cells[0].strip("*").strip()
            m = re.match(r"([\d.]+)", cells[1].strip("*").strip())
            if not m or phase.lower() == "total":
                continue
            if phase not in phase_totals:
                phase_order.append(phase)
            phase_totals[phase] = phase_totals.get(phase, 0.0) + float(m.group(1))

    s1_rows = _dedupe_preserve_order(s1_rows)
    s2_rows = _dedupe_preserve_order(s2_rows)
    s3_rows = _dedupe_preserve_order(s3_rows)

    lines: List[str] = ["# LINEAJE AI POLICY REPORT", ""]
    status = "violations_found" if total_violations else "compliant"
    lines.append(
        f"**Run summary:** `{status}` · violations={total_violations} · "
        f"remediation_actions={total_remediation_actions} · elapsed={total_elapsed:.1f}s"
    )
    lines.append("")
    if project_scanned:
        lines.append(f"**Project Scanned:** `{project_scanned}`")
        lines.append("")
    lines.append(f"**Total Time:** {total_elapsed:.1f}s")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Enforcement Summary")
    lines.append("")
    enforcement_bullets = _dedupe_preserve_order(enforcement_bullets)
    notified = max(enforcement_counts["notified"], len(enforcement_bullets))
    remediated = enforcement_counts["remediated"]
    if not total_violations:
        lines.append("No violations detected.")
        lines.append("")
    else:
        preview = enforcement_bullets[:_ENFORCEMENT_PREVIEW_CAP]
        for bullet in preview:
            lines.append(bullet)
            lines.append("")
        remaining = notified - len(preview)
        if remaining > 0:
            lines.append(f"*… and {remaining} more violation(s) — see **SECTION 3: Controls Enforced** below.*")
            lines.append("")
        parts = [f"{n} {kind}" for kind, n in (("remediated", remediated), ("notified", notified)) if n]
        if parts:
            lines.append(f"**Summary:** {', '.join(parts)}")
            lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### SECTION 1: AIBOM Discovery")
    lines.append("")
    lines.append("#### AI Components")
    lines.append("")
    if s1_header:
        lines.extend([s1_header, s1_sep, *s1_rows])
    if not s1_rows:
        lines.append("")
        lines.append("*No AI components discovered.*")
    lines.append("")
    lines.append("### SECTION 2: Policy Violations")
    lines.append("")
    lines.append("*Each row is one **`policy_violation=true`** finding (file × policy).*")
    lines.append("")
    if s2_header:
        lines.extend([s2_header, s2_sep, *s2_rows])
    lines.append("")
    lines.append("### SECTION 3: Controls Enforced")
    lines.append("")
    lines.append("#### Controls enforced")
    lines.append("")
    if s3_header:
        lines.extend([s3_header, s3_sep, *s3_rows])
    lines.append("")
    lines.append("### AI Component Relationship Graph")
    lines.append("")
    lines.append("```mermaid")
    lines.append(_merge_mermaid_bodies(mermaid_bodies))
    lines.append("```")
    lines.append("")
    lines.append("### Phase Timing")
    lines.append("")
    lines.append("| Phase | Time |")
    lines.append("|-------|------|")
    for phase in phase_order:
        lines.append(f"| {phase} | {phase_totals[phase]:.1f}s |")
    lines.append(f"| **Total** | **{sum(phase_totals.values()):.1f}s** |")
    lines.append("")

    return "\n".join(lines)

# ===========================================================================
# JSON output
# ===========================================================================

def build_json_output(
    *,
    status: str,
    repo: str,
    branch: str,
    head_sha: str,
    source_code_repo: str,
    files_scanned: int,
    batches: int,
    failed_batches: int,
    violations: List[Dict[str, Any]],
    aibom: Optional[List[Dict[str, str]]] = None,
    report: str = "",
    remediation_pr: Optional[int] = None,
    remediation_branch: str = "",
    remediation_pr_url: str = "",
    failed_remediation_files: Optional[List[str]] = None,
    scan_errors: Optional[List[str]] = None,
    remediation_actions: Optional[List[Dict[str, Any]]] = None,
    uploaded_entities: Optional[List[Dict[str, Any]]] = None,
    uploaded_findings: Optional[List[Dict[str, Any]]] = None,
    source_archive_s3_uploaded: Optional[bool] = None,
) -> Dict[str, Any]:
    return {
        "status": status,
        "scan_metadata": {
            "repo": repo,
            "branch": branch,
            "head_sha": head_sha,
            "source_code_repo": source_code_repo,
            "scanned_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": files_scanned,
            "batches": batches,
            "failed_batches": failed_batches,
        },
        "report": report,
        "violations": violations,
        "aibom": aibom or [],
        "remediation_pr": remediation_pr,
        "remediation_branch": remediation_branch,
        "remediation_pr_url": remediation_pr_url,
        "failed_remediation_files": failed_remediation_files or [],
        "remediation_actions": remediation_actions or [],
        "uploaded_entities": uploaded_entities or [],
        "uploaded_findings": uploaded_findings or [],
        "source_archive_s3_uploaded": source_archive_s3_uploaded,
        "scan_errors": scan_errors or [],
    }


def print_human_output(output: Dict[str, Any]) -> None:
    status = output.get("status", "unknown")
    violations = output.get("violations", [])
    scan_errors = output.get("scan_errors", [])
    metadata = output.get("scan_metadata", {})
    scanned_at = metadata.get("scanned_at", "")
    branch = metadata.get("branch", "")

    if status == "compliant":
        status_label = "✅ Compliant"
    elif status == "violations_found":
        status_label = "❌ Not Compliant"
    else:
        status_label = status

    logger.info("Result: %s — %d violation(s)", status_label, len(violations))

    print("# UnifAI Security Report")
    print()
    print(f"**Status:** {status_label}")
    if branch:
        print(f"**Branch:** `{branch}`")
    if scanned_at:
        print(f"**Scanned at:** {scanned_at}")
    rem_pr_url = output.get("remediation_pr_url", "")
    if rem_pr_url:
        print(f"**Remediation PR:** {rem_pr_url}")

    if scan_errors:
        print("\n**Errors:**")
        for err in scan_errors:
            print(f"- {err}")
        print()

    if not violations:
        if status == "compliant":
            print("\nNo violations found.")
        _print_uploaded_artifacts(output)
        return

    from collections import defaultdict
    by_file: Dict[str, List[str]] = defaultdict(list)
    for v in violations:
        file_ = v.get("file") or v.get("file_path") or "(unknown)"
        control = v.get("policy_name") or v.get("control") or v.get("policy_id") or "(unknown)"
        by_file[file_].append(control)

    num_files = len(by_file)
    print(f"\n**{len(violations)} violation(s) across {num_files} file(s)**\n")

    print("| File | Policy Violations |")
    print("|------|-------------------|")

    for file_, controls in sorted(by_file.items()):
        numbered = "".join(f"{i}. {c}<br>" for i, c in enumerate(controls, 1))
        print(f"| `{file_}` | {numbered} |")

    _print_uploaded_artifacts(output)


# GitHub caps a step summary at 1 MiB; keep each JSON well under half of that.
UPLOADED_JSON_SUMMARY_LIMIT = int(os.environ.get("UNIFAI_UPLOADED_JSON_SUMMARY_LIMIT", "400000"))


def _print_uploaded_artifacts(output: Dict[str, Any]) -> None:
    """Print the entities/findings JSON the server uploaded to Lineaje, verbatim."""
    artifacts = [
        ("entities.aientity.json", output.get("uploaded_entities") or []),
        ("findings.aifinding.json", output.get("uploaded_findings") or []),
    ]
    if not any(items for _, items in artifacts):
        return
    print("\n### Uploaded to Lineaje\n")
    src = output.get("source_archive_s3_uploaded")
    if src is False:
        print(
            "*Only these scan results were uploaded. The source code stayed on the "
            "MCP host (hybrid mode) and was not uploaded.*\n"
        )
    elif src:
        print("*The source archive was also uploaded to Lineaje (SaaS mode, or "
              "UNIFAI_FORCE_S3_ARCHIVE_UPLOAD=true).*\n")
    for name, items in artifacts:
        text = json.dumps(items, indent=2, default=str)
        truncated = len(text) > UPLOADED_JSON_SUMMARY_LIMIT
        if truncated:
            text = text[:UPLOADED_JSON_SUMMARY_LIMIT].rstrip() + "\n… (truncated)"
        # Full copy always goes to the job log (stderr), even when the summary truncates.
        logger.info("Uploaded %s (%d item(s)):\n%s", name, len(items), json.dumps(items, indent=2, default=str))
        print(f"<details><summary><code>{name}</code> — {len(items)} item(s)"
              f"{' (truncated; full JSON in the job log)' if truncated else ''}</summary>\n")
        print("```json")
        print(text)
        print("```\n</details>\n")


# ===========================================================================
# Patch application (ported from veracode_repo_scan.py, no external deps)
# ===========================================================================

def _normalize_for_patch_match(s: str) -> str:
    return re.sub(r"[ \t]+", " ", s)


def _reindent_replacement(content: str, start: int, replacement: str) -> Tuple[int, str]:
    """(start, replacement) with *replacement* re-indented to the file.

    When a match starts inside a line's leading indentation (the LLM quoted
    ``original`` with or without its indent), replace from the start of that
    line instead, and shift every line of *replacement* so its first line has
    the file's indentation — the lines below keep their indentation relative to
    it. Without this, an ``original`` quoted without its indent keeps the file's
    indent and adds the replacement's own (or none): "unexpected indent" /
    "unindent does not match any outer indentation level"."""
    line_start = content.rfind("\n", 0, start) + 1
    if content[line_start:start].strip():
        return start, replacement  # match starts mid-line — leave it
    line_end = content.find("\n", line_start)
    line = content[line_start: line_end if line_end != -1 else len(content)]
    target = line[: len(line) - len(line.lstrip())]
    rep_lines = replacement.split("\n")
    first = next((l for l in rep_lines if l.strip()), "")
    base = first[: len(first) - len(first.lstrip())]
    shifted = []
    for l in rep_lines:
        if not l.strip():
            shifted.append("")
        elif l.startswith(base):
            shifted.append(target + l[len(base):])
        elif base.startswith(indent := l[: len(l) - len(l.lstrip())]):
            # Less indented than the first line: keep the dedent (W16: a
            # function-level ``return`` after an ``if`` block must not move
            # into the ``if``).
            shifted.append(target[: max(0, len(target) - (len(base) - len(indent)))] + l.lstrip())
        else:
            shifted.append(target + l.lstrip())
    return line_start, "\n".join(shifted)


def _find_fix_span(content: str, original: str) -> Optional[Tuple[int, int]]:
    """(start, end) of the text in *content* that *original* quotes, or None."""
    idx = content.find(original)
    if idx != -1:
        return idx, idx + len(original)

    orig_stripped = original.strip()
    if not orig_stripped:
        return None
    idx = content.find(orig_stripped)
    if idx != -1:
        return idx, idx + len(orig_stripped)

    norm_orig = _normalize_for_patch_match(orig_stripped)
    norm_content = _normalize_for_patch_match(content)
    idx = norm_content.find(norm_orig)
    if idx != -1:
        orig_len = len(orig_stripped)
        real_idx = 0
        norm_walked = 0
        for ci, ch in enumerate(content):
            if norm_walked >= idx:
                real_idx = ci
                break
            norm_walked += len(_normalize_for_patch_match(ch))
        else:
            real_idx = len(content)
        sub = content[real_idx : real_idx + orig_len + 50]
        if orig_stripped in sub:
            actual_idx = content.find(orig_stripped, real_idx)
            if actual_idx != -1:
                return actual_idx, actual_idx + len(orig_stripped)

    orig_lines = [l for l in orig_stripped.splitlines() if l.strip()]
    if orig_lines:
        anchor = orig_lines[0].strip()
        if len(anchor) > 15:
            anchor_idx = content.find(anchor)
            if anchor_idx != -1:
                end_search = content.find(orig_lines[-1].strip(), anchor_idx) if len(orig_lines) > 1 else anchor_idx
                if end_search != -1:
                    end_idx = end_search + len(orig_lines[-1].strip())
                    if end_idx - anchor_idx < len(orig_stripped) * 2:
                        return anchor_idx, end_idx
    return None


def _apply_fix_entry(content: str, original: str, replacement: str) -> Tuple[str, bool]:
    if not original:
        return content, False
    span = _find_fix_span(content, original)
    if span is None:
        return content, False
    start, end = span
    start, replacement = _reindent_replacement(content, start, replacement)
    return content[:start] + replacement + content[end:], True


def _norm_rel_path(p: str) -> str:
    s = p.strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def _resolve_source_file(source_dir: str, filepath: str, file_list: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a violation filepath to (rel_path, content) from the live checkout."""
    raw = filepath.strip()
    if not raw:
        return None, None
    norm_fp = _norm_rel_path(raw)
    root = pathlib.Path(source_dir)

    candidate = root / raw
    if candidate.is_file():
        return norm_fp, candidate.read_text(errors="replace")

    # Try normalised path
    candidate2 = root / norm_fp
    if candidate2.is_file():
        return norm_fp, candidate2.read_text(errors="replace")

    # Basename fallback
    base = pathlib.Path(norm_fp).name
    matches = [f for f in file_list if pathlib.Path(f).name == base]
    if len(matches) == 1:
        full = root / matches[0]
        if full.is_file():
            return _norm_rel_path(matches[0]), full.read_text(errors="replace")

    logger.warning("Cannot resolve remediation file %r in source dir", raw)
    return None, None


_STUB_RUNTIME_FILES = frozenset({"gr_stub_client.py"})
_ENV_FILE_RE = re.compile(r"^\.env(\..+)?$")


def _is_stub_or_env_file(rel: str) -> bool:
    """Guardrail-stub runtime files and .env files — never part of an LLM remediation PR."""
    name = pathlib.PurePosixPath(_norm_rel_path(rel)).name
    return name in _STUB_RUNTIME_FILES or bool(_ENV_FILE_RE.match(name))


_CLOSER_LINE_RE = re.compile(r"^\s*[\)\]\}][\)\]\},;:\s]*$")


def _reindent_from_body(replacement: str) -> str:
    """*replacement* with lines 2+ re-based on their own smallest indent — for an
    LLM answer that dropped the first line's indent but kept the rest (common
    when code is quoted inside a JSON string). ``_reindent_replacement`` then
    lines the block up with the file."""
    lines = replacement.split("\n")
    rest = [l for l in lines[1:] if l.strip()]
    if not rest:
        return replacement
    first_indent = len(lines[0]) - len(lines[0].lstrip())
    base = min(len(l) - len(l.lstrip()) for l in rest)
    if base <= first_indent:
        return replacement
    shift = base - first_indent
    return "\n".join([lines[0]] + [l[shift:] if l.strip() else l for l in lines[1:]])


def _apply_fix_entry_checked(
    content: str, original: str, replacement: str, rel_path: str, check_python: bool,
) -> Tuple[Optional[str], str]:
    """(patched content, "") or (None, reason). For Python, a fix that breaks the
    file is retried with the two repairs matching the usual LLM mistakes before
    it is given up on: the replacement already closes a call whose closing
    bracket lines are still in the file ("unmatched ')'"), or its lines 2+
    carry indentation the first line lost ("unexpected indent")."""
    span = _find_fix_span(content, original)
    if span is None:
        return None, "not found"

    def _splice(rep: str, end: int) -> str:
        start, rep = _reindent_replacement(content, span[0], rep)
        return content[:start] + rep + content[end:]

    def _raises(patched: str) -> str:
        found = _new_runtime_errors(patched, content)
        return "it would fail on every run: " + "; ".join(found) if found else ""

    patched = _splice(replacement, span[1])
    if not check_python:
        return patched, ""
    err = validate_python_source(patched, rel_path)
    if not err:
        raises = _raises(patched)
        return (None, raises) if raises else (patched, "")

    candidates = [_reindent_from_body(replacement)] if _reindent_from_body(replacement) != replacement else []
    candidates.append(replacement)
    for rep in candidates:
        end = span[1]
        for _ in range(4):  # also swallow up to 4 closing-bracket-only lines after the span
            tried = _splice(rep, end)
            if validate_python_source(tried, rel_path) is None:
                raises = _raises(tried)
                return (None, raises) if raises else (tried, "")
            nl = content.find("\n", end)
            if nl == -1:
                break
            next_end = content.find("\n", nl + 1)
            next_end = len(content) if next_end == -1 else next_end
            if not _CLOSER_LINE_RE.match(content[nl + 1:next_end]):
                break
            end = next_end
    return None, err


def _uses_any(text: str, names: List[str]) -> List[str]:
    return [n for n in names if re.search(r"(?<![\w.])" + re.escape(n) + r"\b", text)]


_TOP_LEVEL_DEF_RE = re.compile(
    r"^(?:async\s+def|def|class)\s+([A-Za-z_]\w*)|^([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)", re.M,
)


def _def_line(text: str, m: "re.Match") -> str:
    """The whole line a ``_TOP_LEVEL_DEF_RE`` match starts on, stripped."""
    end = text.find("\n", m.start())
    return text[m.start(): end if end != -1 else len(text)].strip()


def _module_level_names(source: str) -> set:
    """Names bound at module level in *source* (assignments, defs, classes, imports)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {m.group(1) or m.group(2) for m in _TOP_LEVEL_DEF_RE.finditer(source)}
    names: set = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        names.add(n.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((a.asname or a.name.split(".")[0]) for a in node.names)
    return names


def _dedupe_fix_definitions(
    original_content: str, actions: List[Dict[str, Any]], filepath: str,
) -> List[List[Dict[str, Any]]]:
    """Per action, its fix_code entries with colliding module-level names renamed.

    Each policy's fix is generated on its own, so two fixes for one file often
    both add e.g. ``_INJECTION_PATTERNS`` — one a regex, one a list — and
    whichever is defined last silently replaces the other at import time
    ("'list' object has no attribute 'search'"). A name a fix *defines* at
    module level that the file or an earlier fix already defines is renamed
    (``_INJECTION_PATTERNS`` -> ``_INJECTION_PATTERNS_2``) everywhere inside
    that one fix, so both keep working. Names a fix only *uses* are left alone.
    """
    claimed = _module_level_names(original_content)
    # name -> the exact line(s) defining it, so an identical duplicate (two fixes
    # both adding `logger = logging.getLogger(__name__)`) is left alone.
    def_lines: Dict[str, set] = {}
    for m in _TOP_LEVEL_DEF_RE.finditer(original_content):
        def_lines.setdefault(m.group(1) or m.group(2), set()).add(_def_line(original_content, m))
    out: List[List[Dict[str, Any]]] = []
    for action in actions:
        entries = [dict(e) for e in (action.get("fix_code") or [])]
        defined: Dict[str, set] = {}
        replaced: set = set()
        for e in entries:
            pos = _fix_entry_position(original_content, e.get("original", ""))
            if pos < 0:
                continue
            line_start = original_content.rfind("\n", 0, pos) + 1
            if original_content[line_start:pos].strip() or original_content[line_start:line_start + 1] in (" ", "\t"):
                continue  # edit inside an indented block — not a module-level definition
            for m in _TOP_LEVEL_DEF_RE.finditer(e.get("replacement", "")):
                defined.setdefault(m.group(1) or m.group(2), set()).add(_def_line(e.get("replacement", ""), m))
            replaced |= {m.group(1) or m.group(2) for m in _TOP_LEVEL_DEF_RE.finditer(e.get("original", ""))}
        rename: Dict[str, str] = {}
        for name in sorted((set(defined) - replaced) & claimed):
            if all(not l.startswith(("def ", "async def ", "class ")) for l in defined[name]):
                if defined[name] <= def_lines.get(name, set()):
                    continue  # the same assignment again — harmless
            n = 2
            while f"{name}_{n}" in claimed:
                n += 1
            rename[name] = f"{name}_{n}"
        if rename:
            pattern = re.compile(r"(?<![\w.])(" + "|".join(map(re.escape, rename)) + r")\b")
            for e in entries:
                e["replacement"] = pattern.sub(lambda m: rename[m.group(1)], e.get("replacement", ""))
            logger.info(
                "Renamed %s in fix for %r (%s) — another fix or the file already defines it",
                ", ".join(f"{k} -> {v}" for k, v in rename.items()), filepath, action.get("control", ""),
            )
        for name, lines in defined.items():
            def_lines.setdefault(rename.get(name, name), set()).update(lines)
        claimed |= (set(defined) - set(rename)) | set(rename.values())
        out.append(entries)
    return out


def _first_line(snippet: str, limit: int = 120) -> str:
    """First non-blank line of *snippet*, stripped and cut to *limit* chars."""
    line = next((l.strip() for l in snippet.splitlines() if l.strip()), "")
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _fix_entry_position(content: str, original: str) -> int:
    """Where *original* starts in *content* (exact, then stripped, then by its
    first line), or -1 when it can't be found — used only to order fixes."""
    for needle in (original, original.strip(), _first_line(original, limit=10_000)):
        if needle:
            idx = content.find(needle)
            if idx != -1:
                return idx
    return -1


def apply_pipeline_fix_code_to_clone(
    remediation_actions: List[Dict[str, Any]],
    source_dir: str,
    file_list: List[str],
) -> Tuple[Dict[str, str], List[str], List[Dict[str, str]]]:
    """Apply fix_code patches from MCP remediation_actions to checked-out files.

    Returns (validated_fixes, failed_files, fix_table_rows).
    """
    validated_fixes: Dict[str, str] = {}
    failed_files: List[str] = []
    fix_table_rows: List[Dict[str, str]] = []

    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for action in remediation_actions:
        fp = (action.get("file") or "").strip()
        if fp:
            by_file.setdefault(fp, []).append(action)

    for filepath, actions in by_file.items():
        has_fix_code = any(action.get("fix_code") for action in actions)
        if not has_fix_code:
            failed_files.append(filepath)
            continue

        rel_path, original_content = _resolve_source_file(source_dir, filepath, file_list)
        if rel_path is None or original_content is None:
            failed_files.append(filepath)
            continue

        # Only gate Python files that compiled before we touched them — a file
        # that was already broken can't tell us whether a fix broke it.
        check_python = (
            rel_path.endswith(".py")
            and validate_python_source(original_content, rel_path) is None
        )
        # Apply bottom-up: each entry is ordered by where its original snippet
        # sits in the untouched file, last first, so a fix never shifts or
        # rewrites code that a fix above it still has to find. Entries whose
        # snippet can't be located go last, in their original order.
        deduped = _dedupe_fix_definitions(original_content, actions, filepath) if check_python else [
            list(a.get("fix_code") or []) for a in actions
        ]
        entries = [
            (action, fix_entry)
            for action, action_entries in zip(actions, deduped)
            for fix_entry in action_entries
            if (fix_entry.get("original") or "").strip()
        ]
        entries.sort(
            key=lambda e: _fix_entry_position(original_content, e[1]["original"]),
            reverse=True,
        )
        excluded: set = set()
        for _round in range(len(actions) + 1):
            content = original_content
            applied: Dict[int, List[str]] = {}
            for action, fix_entry in entries:
                if id(action) in excluded:
                    continue
                original = fix_entry["original"]
                replacement = fix_entry.get("replacement", "")
                patched, reason = _apply_fix_entry_checked(
                    content, original, replacement, rel_path, check_python,
                )
                if patched is None:
                    if _round == 0 and reason == "not found":
                        logger.info(
                            "Patch not applied for %r (%s) — original snippet (%d chars) not found; "
                            "it starts with: %r",
                            filepath, action.get("control", ""), len(original), _first_line(original),
                        )
                    elif _round == 0:
                        logger.warning(
                            "Rejected fix for %r (%s) — it breaks the file: %s",
                            filepath, action.get("control", ""), reason,
                        )
                    continue
                content = patched
                applied.setdefault(id(action), []).append(replacement)

            undefined: List[str] = []
            if applied and content != original_content and check_python:
                content, undefined = _add_missing_stdlib_imports(content, original_content)
                if not undefined:
                    # C-38 NEW-30: an unused import of a missing module is removed; a
                    # used one drops the fixes that use it, like an undefined name.
                    content, undefined = _drop_unresolved_imports(
                        content, original_content, source_dir, rel_path)
            if not undefined:
                break
            # Drop only the fixes that use the undefined names — typically a helper
            # whose defining entry was lost to a conflicting edit — and keep the rest.
            culprits = [
                a for a in actions
                if id(a) in applied and _uses_any("\n".join(applied[id(a)]), undefined)
            ]
            if not culprits:
                logger.warning(
                    "Rejected all fixes for %r — they use undefined name(s): %s",
                    filepath, ", ".join(undefined),
                )
                applied = {}
                break
            for a in culprits:
                logger.warning(
                    "Dropped fix for %r (%s) — it uses undefined name(s): %s",
                    filepath, a.get("control", ""),
                    ", ".join(_uses_any("\n".join(applied[id(a)]), undefined)),
                )
                excluded.add(id(a))
        applied_actions = [a for a in actions if id(a) in applied]

        if applied_actions and content != original_content:
            validated_fixes[rel_path] = content
            for action in applied_actions:
                fix_table_rows.append({
                    "policy": action.get("control", ""),
                    "description": (action.get("instruction") or "")[:200],
                    "file": filepath,
                })
        else:
            logger.warning("No valid patch applied for %r — needs a manual fix", filepath)
            failed_files.append(filepath)

    return validated_fixes, failed_files, fix_table_rows


# ===========================================================================
# LLM remediation — report / PR sections
# ===========================================================================

def _md_cell(text: Any, limit: int = 300) -> str:
    t = " ".join(str(text or "").split())
    if len(t) > limit:
        t = t[: limit - 1].rstrip() + "…"
    return t.replace("|", "\\|")


def _pr_remediation_details(fix_table: List[Dict[str, str]], limit_chars: int) -> str:
    """Compact per-file remediation list for the PR body (policy + what was changed)."""
    if not fix_table:
        return ""
    lines = ["### Remediation details (LLM)", "", "| File | Policy | Change |", "|------|--------|--------|"]
    for r in fix_table:
        lines.append(
            f"| `{_md_cell(r.get('file'), 100)}` | {_md_cell(r.get('policy'), 100)} | "
            f"{_md_cell(r.get('description'), 200)} |"
        )
    text = "\n".join(lines)
    if len(text) > limit_chars:
        text = text[:limit_chars].rsplit("\n", 1)[0] + "\n\n*… more rows in the scan report.*"
    return text



_PR_REPORT_SECTIONS = (
    "### SECTION 1: AIBOM Discovery",
    "### SECTION 2: Policy Violations",
    "### SECTION 3: Controls Enforced",
)


def _build_fix_pr_body(
    branch: str,
    sha_short: str,
    committed: List[str],
    failed_files: Optional[List[str]],
    fix_table: List[Dict[str, str]],
    report: str,
    limit: int,
    report_note: str = "",
    scan_errors: Optional[List[str]] = None,
) -> str:
    """Remediation PR description: SECTION 1 (AIBOM), SECTION 2 (Policy Violations),
    SECTION 3 (Controls Enforced) from the scan report, then the remediation changes.

    The remediation part is sized first so a long report is what gets truncated, never
    the list of changed files. ``scan_errors`` is accepted but not shown: the PR is
    customer facing and a customer cannot act on them; they are logged as warnings
    where each batch returns (C-38, session 11).
    """
    head = "\n".join([
        "## Lineaje AI Policy Scan",
        "",
        f"Scan of `{branch}` at `{sha_short}`. The remediation changes below are "
        "LLM-suggested fixes for review — merge only what you accept.",
    ])
    failed = failed_files or []
    if failed:
        # User decision (2026-10-05): when any flagged file has no fix, the PR does not
        # list the files with and without fixes; the per-file details below remain.
        remediation = "## Remediation changes"
    else:
        remediation = "\n".join([
            "## Remediation changes",
            "",
            f"### Files remediated ({len(committed)})",
            "",
            "\n".join(f"- `{f}`" for f in committed),
        ])
    details = _pr_remediation_details(fix_table, limit // 3)
    if details:
        remediation += "\n\n" + details

    sections = _split_report_sections(report or "")
    blocks = [f"{h}\n{sections[h].strip()}" for h in _PR_REPORT_SECTIONS if sections.get(h, "").strip()]
    report_md = "\n\n".join(blocks) if blocks else (report or "").strip()

    sep = "\n\n---\n\n"
    note = f"\n\n{report_note}" if report_note else ""
    budget = limit - len(head) - len(remediation) - 2 * len(sep) - len(note)
    parts = [head]
    if report_md and budget > 500:
        if len(report_md) > budget:
            cut = "\n\n*… report truncated — full report in the workflow run summary.*"
            report_md = report_md[: budget - len(cut)].rsplit("\n", 1)[0] + cut
        parts.append(report_md + note)
    parts.append(remediation)
    return sep.join(parts)[:limit]


# ===========================================================================
# Remediation PR creation
# ===========================================================================

def _normalize_github_repo_slug(repo: str) -> str:
    s = (repo or "").strip()
    s = re.sub(r"[\x00-\x1f\x7f]+", "", s)
    s = re.sub(r"\s+", "", s)
    s = s.strip("/")
    if s.lower().endswith(".git"):
        s = s[:-4]
    lower = s.lower()
    marker = "github.com/"
    idx = lower.find(marker)
    if idx != -1:
        s = s[idx + len(marker):]
    s = s.strip("/")
    parts = [p for p in s.split("/") if p]
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return s


def _normalize_git_ref(value: str) -> str:
    return re.sub(r"[\s\x00-\x1f\x7f]+", "", (value or "").strip())


class _GitHubClient:
    """Minimal GitHub REST client (this script's AzureDevOpsClient can't reach github.com)."""

    def __init__(self, token: str, base_url: str = "") -> None:
        self.token = token
        self.base_url = (base_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")

    def _request(
        self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
        *, expected_errors: Optional[set] = None,
    ) -> Any:
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "UniFAI-ADO-Scanner/1.0",
        }
        data = json.dumps(body).encode() if body else None
        if data:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            err = exc.read().decode("utf-8", errors="replace")[:500]
            if expected_errors and exc.code in expected_errors:
                logger.debug("GitHub API %s %s → %s (expected): %s", method, url, exc.code, err)
            else:
                logger.error("GitHub API %s %s → %s: %s", method, url, exc.code, err)
            raise

    def create_branch(self, repo: str, branch_name: str, from_sha: str) -> None:
        repo = _normalize_github_repo_slug(repo)
        self._request("POST", f"/repos/{repo}/git/refs", {"ref": f"refs/heads/{branch_name}", "sha": from_sha})

    def get_file_blob_sha(self, repo: str, path: str, ref: str) -> Optional[str]:
        repo = _normalize_github_repo_slug(repo)
        encoded_path = urllib.parse.quote(path, safe="/")
        qref = urllib.parse.quote(ref, safe="")
        try:
            data = self._request(
                "GET", f"/repos/{repo}/contents/{encoded_path}?ref={qref}", expected_errors={404},
            )
            if isinstance(data, dict) and data.get("type") == "file" and data.get("sha"):
                return str(data["sha"])
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        return None

    def commit_file(
        self, repo: str, branch: str, path: str, content: bytes, message: str, sha: Optional[str] = None,
    ) -> str:
        repo = _normalize_github_repo_slug(repo)
        if sha is None:
            sha = self.get_file_blob_sha(repo, path, branch)
        payload: Dict[str, Any] = {
            "message": message, "content": base64.b64encode(content).decode(), "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        encoded_path = urllib.parse.quote(path, safe="/")
        resp = self._request("PUT", f"/repos/{repo}/contents/{encoded_path}", payload)
        return resp["commit"]["sha"]

    def create_pull_request(self, repo: str, title: str, head: str, base: str, body: str) -> int:
        repo = _normalize_github_repo_slug(repo)
        resp = self._request("POST", f"/repos/{repo}/pulls", {
            "title": title, "head": head, "base": base, "body": body,
        })
        return resp["number"]


def _is_guard_file(path: str) -> bool:
    return os.path.basename(path) in (_GUARD_FILENAME, "unifaiGuard.js", "unifaiGuard.cjs",
                                      "unifaiGuard.mjs", "unifaiGuard.d.ts")


def _commit_with_retry(scm: "_GitHubClient", repo: str, branch: str, filepath: str, content: str,
                       message: str, head_sha: str, attempts: int = 3) -> None:
    """Commit one file; retry GitHub 5xx / 409 answers (409: re-read the file's sha first)."""
    for attempt in range(1, attempts + 1):
        blob_sha: Optional[str] = None
        try:
            blob_sha = scm.get_file_blob_sha(repo, filepath, branch if attempt > 1 else head_sha)
        except Exception:
            pass
        try:
            scm.commit_file(repo, branch, filepath, content.encode("utf-8"), message, sha=blob_sha)
            return
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code is None:
                m = re.search(r"HTTP Error (\d{3})", str(exc))
                code = int(m.group(1)) if m else None
            if attempt == attempts or not (code == 409 or (code or 0) >= 500):
                raise
            logger.warning("Commit of %s failed (%s); retrying (%d/%d)", filepath, exc, attempt, attempts - 1)
            time.sleep(2 ** attempt)


def _create_github_fix_pr(
    github_token: str,
    repo: str,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    report: str = "",
    failed_files: Optional[List[str]] = None,
    scan_errors: Optional[List[str]] = None,
) -> Tuple[Optional[int], str]:
    """Commit LLM remediation (fix_code) patches to a branch and open a PR on github.com."""
    if not validated_fixes:
        return None, ""

    repo = _normalize_github_repo_slug(repo)
    branch = _normalize_git_ref(branch)
    head_sha = _normalize_git_ref(head_sha)
    if not repo:
        logger.error("Cannot create remediation PR: repo slug is empty after normalize.")
        return None, ""
    if not head_sha:
        logger.error("Cannot create remediation branch: head_sha is empty. Pass --head-sha.")
        return None, ""

    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)
    sha_short = head_sha[:7]
    timestamp = time.strftime("%m%d%H%M")
    remediation_branch = f"{REMEDIATION_BRANCH_PREFIX}-{safe_branch.replace('/', '-')}-{sha_short}-{timestamp}"

    scm = _GitHubClient(token=github_token)

    if len(head_sha) < 40:
        try:
            head_sha = scm._request("GET", f"/repos/{repo}/commits/{head_sha}")["sha"]
        except Exception as exc:
            logger.warning("Could not resolve short SHA %s: %s", head_sha, exc)

    try:
        logger.info("Creating remediation branch %s from %s", remediation_branch, sha_short)
        scm.create_branch(repo, remediation_branch, head_sha)
    except Exception as exc:
        logger.error("Failed to create/verify remediation branch: %s", exc)
        return None, remediation_branch

    committed: List[str] = []
    not_committed: List[str] = []
    failed_guard_dirs: set = set()
    # Wega run 12: GitHub answered one contents PUT with a 500 and that file's fix
    # silently vanished from the PR. Transient errors are retried; the shared guard
    # goes first so its importers are never committed without it; a file that still
    # fails is listed under "Files without fixes".
    for filepath, content in sorted(validated_fixes.items(), key=lambda kv: (not _is_guard_file(kv[0]), kv[0])):
        directory = os.path.dirname(filepath).replace("\\", "/")
        if directory in failed_guard_dirs and _GUARD_IMPORT_RE.search(content):
            logger.error("Not committing %s: its shared guard could not be committed", filepath)
            not_committed.append(filepath)
            continue
        policies = ", ".join({r["policy"] for r in fix_table if r.get("file") == filepath}) or "policy violations"
        message = f"fix({filepath}): remediate {policies} [unifai-ghp-scan]"
        try:
            _commit_with_retry(scm, repo, remediation_branch, filepath, content, message, head_sha)
            committed.append(filepath)
            logger.info("Committed fix: %s", filepath)
        except Exception as exc:
            logger.error("Failed to commit %s: %s", filepath, exc)
            not_committed.append(filepath)
            if _is_guard_file(filepath):
                failed_guard_dirs.add(directory)

    if not committed:
        logger.warning("No files committed — skipping PR creation")
        return None, remediation_branch

    title = f"[unifai-bot] fix: AI policy remediation for {branch}@{sha_short}"
    pr_body = _build_fix_pr_body(
        branch, sha_short, committed, list(failed_files or []) + not_committed,
        [r for r in fix_table if r.get("file") not in not_committed], report, GITHUB_PR_BODY_SAFE_LIMIT,
        scan_errors=scan_errors,
    )

    try:
        pr_number = scm.create_pull_request(repo, title, remediation_branch, branch, pr_body)
        logger.info("Created remediation PR #%d — https://github.com/%s/pull/%d", pr_number, repo, pr_number)
        return pr_number, remediation_branch
    except Exception as exc:
        logger.error("Failed to create remediation PR: %s", exc)
        return None, remediation_branch


def _create_fix_pr(
    scm: AzureDevOpsClient,
    branch: str,
    head_sha: str,
    validated_fixes: Dict[str, str],
    fix_table: List[Dict[str, str]],
    *,
    report: str = "",
    failed_files: Optional[List[str]] = None,
    scan_errors: Optional[List[str]] = None,
) -> Tuple[Optional[int], str]:
    """Commit fix_code patches to a remediation branch and open a PR."""
    if not validated_fixes:
        return None, ""

    safe_branch = re.sub(r"[^a-zA-Z0-9._/-]", "-", branch)
    sha_short = head_sha[:7]
    timestamp = time.strftime("%m%d%H%M")
    remediation_branch = f"{REMEDIATION_BRANCH_PREFIX}-{safe_branch.replace('/', '-')}-{sha_short}-{timestamp}"
    if len(head_sha) < 40:
        resolved: Optional[str] = None
        try:
            resolved = scm.get_branch_sha(branch)
        except Exception as exc:
            logger.warning("Could not resolve the tip of %s: %s", branch, exc)
        if not resolved:
            logger.error("Cannot create a remediation branch without the full commit id for %s", branch)
            return None, ""
        head_sha = resolved

    try:
        logger.info("Creating remediation branch %s from %s", remediation_branch, sha_short)
        scm.create_branch(remediation_branch, head_sha)
    except Exception as exc:
        logger.error("Failed to create remediation branch: %s", exc)
        return None, remediation_branch

    # changeType is per file: everything patched here was read off the checkout,
    # so "edit" is the norm, but ask rather than assume.
    existing: Dict[str, bool] = {}
    for filepath in validated_fixes:
        try:
            existing[filepath] = scm.file_exists(filepath, head_sha)
        except Exception as exc:
            logger.debug("Existence check failed for %s (%s) — treating as edit", filepath, exc)
            existing[filepath] = True

    committed = sorted(validated_fixes)
    policies = ", ".join(sorted({r["policy"] for r in fix_table if r.get("policy")})) or "policy violations"
    message = "\n".join(
        [f"fix: remediate {policies} [unifai-ado-scan]", ""]
        + [f"- {f}" for f in committed]
    )

    try:
        scm.push_commit(
            remediation_branch,
            head_sha,
            {f: validated_fixes[f].encode("utf-8") for f in committed},
            message,
            existing=existing,
        )
        logger.info("Committed %d fix(es) to %s", len(committed), remediation_branch)
    except Exception as exc:
        logger.error("Failed to push fixes to %s: %s", remediation_branch, exc)
        return None, remediation_branch

    title = f"[unifai-bot] fix: AI policy remediation for {branch}@{sha_short}"

    pr_body = _build_fix_pr_body(
        branch, sha_short, committed, failed_files, fix_table, report, AZURE_PR_DESCRIPTION_LIMIT,
        report_note="*Full scan report: see the `unifai-report` artifact on the pipeline run.*",
        scan_errors=scan_errors,
    )

    try:
        pr_id = scm.create_pull_request(title, remediation_branch, branch, pr_body)
        logger.info("Created remediation PR !%d — %s", pr_id, scm.pull_request_url(pr_id))
        return pr_id, remediation_branch
    except Exception as exc:
        logger.error("Failed to create remediation PR: %s", exc)
        return None, remediation_branch


# ===========================================================================
# Main scan orchestration
# ===========================================================================

def _azure_branch() -> str:
    """Short branch name from the agent's predefined variables.

    ``Build.SourceBranch`` is ``refs/heads/<name>`` on a CI run but
    ``refs/pull/<id>/merge`` on a PR validation run, where the branch actually
    under review is ``System.PullRequest.SourceBranch``. ``Build.SourceBranchName``
    is only the last path segment, so ``feature/a/b`` would come back as ``b`` —
    it is the last resort rather than the first choice.
    """
    for var in ("SYSTEM_PULLREQUEST_SOURCEBRANCH", "BUILD_SOURCEBRANCH"):
        raw = (os.environ.get(var) or "").strip()
        if raw.startswith("refs/heads/"):
            return raw[len("refs/heads/"):]
    return (os.environ.get("BUILD_SOURCEBRANCHNAME") or "").strip()


def _execute_scan(args: argparse.Namespace) -> int:
    org_url = args.org_url or os.environ.get("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "")
    project = args.project or os.environ.get("SYSTEM_TEAMPROJECT", "")
    repo_name = args.repo or os.environ.get("BUILD_REPOSITORY_NAME", "")
    repo_id = args.repo_id or os.environ.get("BUILD_REPOSITORY_ID", "") or repo_name
    branch = args.branch or _azure_branch()
    head_sha = args.head_sha or os.environ.get("BUILD_SOURCEVERSION", "")
    source_path = os.path.abspath(args.source_path)
    server_url = args.mcp_server_url or os.environ.get("MCP_SERVER_URL", "") or MCP_SERVER_URL

    repo = f"{project}/{repo_name}" if project and repo_name else (repo_name or project)
    source_code_repo = os.environ.get("BUILD_REPOSITORY_URI", "")
    if not source_code_repo:
        if org_url and project and repo_name:
            source_code_repo = (
                f"{org_url.rstrip('/')}/{urllib.parse.quote(project, safe='')}"
                f"/_git/{urllib.parse.quote(repo_name, safe='')}"
            )
        else:
            source_code_repo = source_path

    # Validate config
    missing = [n for n, v in [
        ("BUILD_REPOSITORY_NAME / --repo", repo_name),
        ("BUILD_SOURCEBRANCH / --branch", branch),
    ] if not v]
    if missing:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Missing required config: {', '.join(missing)}"],
        )
        print_human_output(output)
        return 2

    try:
        bearer_getter = build_bearer_getter()
        # Eagerly fetch a token at startup to catch auth errors early
        bearer_getter()
        logger.info("Auth OK — LINEAJE_PAT_TOKEN accepted")
    except Exception as exc:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[], scan_errors=[f"Auth failed: {exc}"],
        )
        print_human_output(output)
        return 2

    run_id = time.strftime("%Y%m%d_%H%M%S")
    scan_start = time.perf_counter()

    logger.info("Scanning source path: %s (repo=%s branch=%s sha=%s)", source_path, repo, branch, head_sha[:7] if head_sha else "?")

    # Step 1: Collect files
    skipped_files: Dict[str, str] = {}
    file_list = collect_repo_files(source_path, getattr(args, "exclude", None), skipped_files)
    if not file_list:
        logger.info("No scannable files found")
        output = build_json_output(
            status="compliant", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=0, batches=0, failed_batches=0,
            violations=[],
        )
        print_human_output(output)
        return 0

    batch_size = _batch_size(len(file_list))
    batches, code_files, manifest_files = pin_manifests_to_first_batch(file_list, batch_size)
    log_file_selection(batches, manifest_files, skipped_files)
    logger.info(
        "Files: %d total (%d code, %d manifests in batch 1) → %d batch(es)",
        len(file_list), len(code_files), len(manifest_files), len(batches),
    )

    # Step 2: MCP scan
    # Persist batch archives on the runner host instead of a TemporaryDirectory
    # (removed when the scan ends). Default: inside the checked-out source tree —
    # a host-mounted workspace in containerized Azure Pipeline / GitHub runner jobs,
    # so the archives outlive the scanner process. .lineaje is excluded from scan
    # input, so persisted archives are never scanned later. UNIFAI_SCAN_ARCHIVE_ROOT
    # moves them outside the workspace (actions/checkout's clean step wipes
    # untracked files such as .lineaje/ on the next run).
    archive_base = (os.environ.get("UNIFAI_SCAN_ARCHIVE_ROOT") or "").strip() or os.path.join(
        source_path, ".lineaje", "scan-archives"
    )
    archive_root = os.path.join(archive_base, f"ado-repo-scan-{run_id}")
    os.makedirs(archive_root, exist_ok=True)
    logger.info("Persisting scan archives to: %s", archive_root)

    (
        all_violations, all_remediation_actions, all_reports, all_aibom,
        failed_batches_count, failure_details, all_stub_insertions, uploaded,
    ) = parallel_batch_scan(
        batches=batches,
        source_dir=source_path,
        temp_dir=archive_root,
        source_code_repo=source_code_repo,
        branch=branch,
        head_sha=head_sha,
        run_id=run_id,
        server_url=server_url,
        bearer_getter=bearer_getter,
        manifest_files=manifest_files or None,
    )

    elapsed = time.perf_counter() - scan_start
    logger.info(
        "Scan complete in %.1fs: %d violation(s), %d AIBOM entr(ies), %d failed batch(es)",
        elapsed, len(all_violations), len(all_aibom), failed_batches_count,
    )

    combined_report = _merge_batch_reports(
        all_reports,
        total_violations=len(all_violations),
        total_remediation_actions=len(all_remediation_actions),
        total_elapsed=elapsed,
    )

    if failed_batches_count and not all_violations:
        output = build_json_output(
            status="error", repo=repo, branch=branch, head_sha=head_sha,
            source_code_repo=source_code_repo, files_scanned=len(file_list),
            batches=len(batches), failed_batches=failed_batches_count,
            violations=[], aibom=all_aibom, report=combined_report,
            scan_errors=failure_details,
        )
        print_human_output(output)
        return 1

    status = "compliant" if not all_violations else "violations_found"
    if failed_batches_count:
        status = "error"

    # Step 3: apply the LLM remediation (remediation_actions[].fix_code) and open
    # a remediation PR from it. Guardrail stubs, gr_stub_client.py and .env
    # files from the server are never applied or committed by this script.
    remediation_pr_number: Optional[int] = None
    remediation_branch = ""
    remediation_pr_url = ""
    failed_rem_files: List[str] = []
    validated_fixes: Dict[str, str] = {}
    fix_table: List[Dict[str, str]] = []

    if all_stub_insertions:
        logger.info(
            "STEP 3: ignoring %d guardrail stub insertion(s) — this script applies LLM remediation only",
            len(all_stub_insertions),
        )
    rem_actions = [a for a in all_remediation_actions if not _is_stub_or_env_file(a.get("file") or "")]
    if rem_actions:
        logger.info("STEP 3: applying LLM remediation (%d action(s))", len(rem_actions))
        validated_fixes, failed_rem_files, fix_table = apply_pipeline_fix_code_to_clone(
            rem_actions, source_path, file_list,
        )
        logger.info(
            "STEP 3: %d file(s) patched, %d file(s) need a manual fix",
            len(validated_fixes), len(failed_rem_files),
        )
    else:
        logger.info("STEP 3: server returned no LLM remediation (remediation_actions is empty)")

    # GitHub token takes precedence over Azure DevOps config.
    github_token = _normalize_token(
        getattr(args, "github_token", None)
        or os.environ.get("GH_TOKEN", "")
        or os.environ.get("GITHUB_TOKEN", "")
    )
    azure_token = _normalize_token(
        getattr(args, "azure_token", None)
        or os.environ.get("SYSTEM_ACCESSTOKEN", "")
        or os.environ.get("AZURE_DEVOPS_EXT_PAT", "")
        or os.environ.get("AZURE_DEVOPS_PAT", "")
    )
    use_github = bool(github_token)
    should_create_pr = bool((github_token or azure_token) and getattr(args, "create_fix_pr", False))
    missing_scm: List[str] = []
    if should_create_pr and not use_github:
        missing_scm = [n for n, v in [
            ("a token (SYSTEM_ACCESSTOKEN / --azure-token)", azure_token),
            ("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI / --org-url", org_url),
            ("SYSTEM_TEAMPROJECT / --project", project),
        ] if not v]

    # Last gate before either PR path: every patched Python file must still
    # compile (C-37 / LIN-35923).
    gated_paths = set(validated_fixes)
    failed_rem_files.extend(_drop_uncompilable_fixes(validated_fixes))
    gated_paths -= set(validated_fixes)
    if gated_paths:
        fix_table = [
            row for row in fix_table
            if _norm_stub_relpath(row.get("file") or "") not in gated_paths
        ]
    failed_rem_files.extend(_add_shared_guard_files(validated_fixes, source_path, fix_table))

    fix_branch_name = (getattr(args, "fix_branch", None) or "").strip()
    if fix_branch_name:
        local_branch = commit_fixes_to_local_branch(source_path, fix_branch_name, validated_fixes)
        if local_branch and not remediation_branch:
            remediation_branch = local_branch

    if should_create_pr and use_github:
        if validated_fixes:
            logger.info("Creating remediation PR on GitHub (%d file(s))", len(validated_fixes))
            try:
                remediation_pr_number, remediation_branch = _create_github_fix_pr(
                    github_token, repo, branch, head_sha,
                    validated_fixes, fix_table,
                    report=combined_report, failed_files=failed_rem_files,
                    scan_errors=failure_details,
                )
                if remediation_pr_number:
                    remediation_pr_url = (
                        f"https://github.com/{_normalize_github_repo_slug(repo)}"
                        f"/pull/{remediation_pr_number}"
                    )
            except Exception as exc:
                logger.error("Remediation PR failed: %s", exc)
        else:
            logger.info("No LLM remediation patches to commit for a remediation PR")
    elif should_create_pr and missing_scm:
        logger.info("Skipping remediation PR — missing %s", ", ".join(missing_scm))
    elif should_create_pr and validated_fixes:
        logger.info("Creating remediation PR (%d file(s))", len(validated_fixes))
        try:
            remediation_pr_number, remediation_branch = _create_fix_pr(
                AzureDevOpsClient(
                    token=azure_token,
                    org_url=org_url,
                    project=project,
                    repository=repo_id,
                ),
                branch, head_sha,
                validated_fixes, fix_table,
                report=combined_report, failed_files=failed_rem_files,
                scan_errors=failure_details,
            )
            if remediation_pr_number:
                remediation_pr_url = AzureDevOpsClient(
                    token=azure_token, org_url=org_url, project=project, repository=repo_id,
                ).pull_request_url(remediation_pr_number)
        except Exception as exc:
            logger.error("Remediation PR failed: %s", exc)
    elif should_create_pr:
        logger.info("No LLM remediation patches to commit for a remediation PR")

    output = build_json_output(
        status=status, repo=repo, branch=branch, head_sha=head_sha,
        source_code_repo=source_code_repo, files_scanned=len(file_list),
        batches=len(batches), failed_batches=failed_batches_count,
        violations=all_violations, aibom=all_aibom, report=combined_report,
        remediation_pr=remediation_pr_number,
        remediation_branch=remediation_branch,
        remediation_pr_url=remediation_pr_url,
        failed_remediation_files=failed_rem_files,
        scan_errors=failure_details,
        remediation_actions=all_remediation_actions,
        uploaded_entities=uploaded["entities"],
        uploaded_findings=uploaded["findings"],
        source_archive_s3_uploaded=uploaded["source_archive_s3_uploaded"],
    )
    print_human_output(output)
    return 0

# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lineaje AI Policy Scanner — Azure Pipelines edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--source-path", default=".",
        help="Path to the checked-out source code (default: current directory)",
    )
    parser.add_argument(
        "--exclude", default=[], action="append", metavar="PATH",
        help="Path relative to --source-path to keep out of the scan, repeatable "
             "(the pipeline passes --exclude .git --exclude .azuredevops)",
    )
    parser.add_argument(
        "--org-url", default="",
        help="Azure DevOps collection URL, e.g. https://dev.azure.com/myorg/ "
             "(default: $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)",
    )
    parser.add_argument(
        "--project", default="",
        help="Azure DevOps project name (default: $SYSTEM_TEAMPROJECT)",
    )
    parser.add_argument(
        "--repo", default="",
        help="Repository name (default: $BUILD_REPOSITORY_NAME)",
    )
    parser.add_argument(
        "--repo-id", default="",
        help="Repository GUID used for REST calls (default: $BUILD_REPOSITORY_ID, "
             "falling back to the repository name)",
    )
    parser.add_argument(
        "--branch", default="",
        help="Branch name without the refs/heads/ prefix (default: derived from "
             "$BUILD_SOURCEBRANCH, or $SYSTEM_PULLREQUEST_SOURCEBRANCH on a PR run)",
    )
    parser.add_argument(
        "--head-sha", default="",
        help="Commit id (default: $BUILD_SOURCEVERSION)",
    )
    parser.add_argument(
        "--mcp-server-url", default="",
        help=f"MCP server URL (default: {MCP_SERVER_URL})",
    )
    parser.add_argument(
        "--azure-token", default="",
        help="Azure DevOps token for creating remediation PRs (default: "
             "$SYSTEM_ACCESSTOKEN, then $AZURE_DEVOPS_EXT_PAT, then $AZURE_DEVOPS_PAT). "
             "If not set, violations are reported but no PR is created.",
    )
    parser.add_argument(
        "--github-token", default="",
        help="GitHub token for creating remediation PRs when --repo is a GitHub "
             "repo (default: $GH_TOKEN, then $GITHUB_TOKEN). Takes precedence over "
             "--azure-token/--org-url/--project when set — this script talks to "
             "whichever host the token is for, GitHub or Azure DevOps, not both.",
    )
    parser.add_argument(
        "--create-fix-pr", default=False, action="store_true",
        help="Create a remediation PR with fix_code patches (default: false).",
    )
    parser.add_argument(
        "--fix-branch", default=None, metavar="NAME",
        help="Also write the validated fixes into --source-path on a new local git "
             "branch NAME and commit them (for a checkout with no remote to open a PR against).",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging to stderr",
    )
    return parser.parse_args(argv or sys.argv[1:])


# ===========================================================================
# Local fix branch (--fix-branch)
# ===========================================================================

def _git(source_path: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", source_path, *args], capture_output=True, text=True, check=False,
    )


def commit_fixes_to_local_branch(
    source_path: str, branch_name: str, validated_fixes: Dict[str, str],
) -> Optional[str]:
    """Write the validated fixes into ``source_path`` on a new git branch and commit them.

    For a checkout with no remote to open a PR against. A repository without any
    commit gets one first (the tree as scanned, before the fixes), so the fix branch
    has a base to diff against. Only the fixed files are staged. Returns the branch
    name, or ``None`` when nothing was committed.
    """
    if not validated_fixes:
        logger.info("--fix-branch: no LLM remediation patches to commit")
        return None
    if _git(source_path, "rev-parse", "--is-inside-work-tree").returncode != 0:
        logger.error("--fix-branch: %s is not a git repository (run `git init` first)", source_path)
        return None
    ident: List[str] = []
    if not _git(source_path, "config", "user.email").stdout.strip():
        ident = ["-c", "user.name=Lineaje UnifAI", "-c", "user.email=unifai@lineaje.local"]
    if _git(source_path, "rev-parse", "--verify", "-q", "HEAD").returncode != 0:
        # .lineaje/ holds this scan's batch archives — never part of the source.
        _git(source_path, "add", "-A", "--", ".", ":(exclude).lineaje")
        done = _git(source_path, *ident, "commit", "-q", "-m", "Source as scanned (before Lineaje remediation)")
        if done.returncode != 0:
            logger.error("--fix-branch: initial commit failed: %s", done.stderr.strip())
            return None
        logger.info("--fix-branch: repository had no commits; committed the scanned tree first")
    made = _git(source_path, "checkout", "-q", "-b", branch_name)
    if made.returncode != 0:
        logger.error("--fix-branch: cannot create branch %s: %s", branch_name, made.stderr.strip())
        return None
    root = pathlib.Path(source_path).resolve()
    written: List[str] = []
    for rel_path, content in sorted(validated_fixes.items()):
        dest = (root / rel_path).resolve()
        if root not in dest.parents:
            logger.warning("--fix-branch: skipping %s (outside the source path)", rel_path)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        written.append(str(dest.relative_to(root)))
    if not written:
        return None
    _git(source_path, "add", "--", *written)
    done = _git(
        source_path, *ident, "commit", "-q", "-m",
        f"Lineaje UnifAI remediation: {len(written)} file(s)",
    )
    if done.returncode != 0:
        logger.error("--fix-branch: commit failed: %s", done.stderr.strip())
        return None
    logger.info("--fix-branch: committed %d fixed file(s) on branch %s", len(written), branch_name)
    return branch_name


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    # Always show INFO from this logger regardless of --debug
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    try:
        return _execute_scan(args)
    except Exception:
        logger.exception("Unhandled error")
        err = {"status": "error", "scan_errors": ["Unhandled exception — see stderr logs"]}
        print_human_output(err)
        return 1


if __name__ == "__main__":
    sys.exit(main())
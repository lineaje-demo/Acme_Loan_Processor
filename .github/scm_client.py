#!/usr/bin/env python3
"""Minimal GitHub SCM client used by the Lineaje AI GitHub Actions scanner.

Uses only the Python standard library.

Expected usage from lineaje_ai_scan.py:

    scm = GitHubClient(token=github_token)
    scm.create_branch(repo, remediation_branch, head_sha)
    blob_sha = scm.get_file_blob_sha(repo, filepath, head_sha)
    scm.commit_file(
        repo,
        remediation_branch,
        filepath,
        content_bytes,
        message,
        sha=blob_sha,
    )
    pr_number = scm.create_pull_request(
        repo,
        title,
        remediation_branch,
        base_branch,
        body,
    )
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional


GITHUB_API_URL = "https://api.github.com"


class GitHubAPIError(RuntimeError):
    """GitHub REST API request failed."""

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        method: str = "",
        path: str = "",
        response: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.method = method
        self.path = path
        self.response = response


class GitHubClient:
    """Small GitHub REST client for remediation branch/commit/PR operations."""

    def __init__(
        self,
        token: str,
        api_url: str = GITHUB_API_URL,
        timeout: int = 60,
    ) -> None:
        self.token = (token or "").strip()
        if not self.token:
            raise ValueError("GitHub token must be non-empty")

        self.api_url = (api_url or GITHUB_API_URL).rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Generic request helper
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Send a GitHub REST API request and return decoded JSON."""

        if not path.startswith("/"):
            path = "/" + path

        url = self.api_url + path

        body: Optional[bytes] = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=body,
            method=method.upper(),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "lineaje-unifai-gha-scan",
                "Content-Type": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                raw = response.read()

                if not raw:
                    return {}

                text = raw.decode("utf-8", errors="replace")

                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return {"raw": text}

        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")

            try:
                parsed: Any = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"raw": raw}

            if isinstance(parsed, dict):
                github_message = parsed.get("message") or raw
            else:
                github_message = raw

            raise GitHubAPIError(
                (
                    f"GitHub API {method.upper()} {path} failed "
                    f"with HTTP {exc.code}: {github_message}"
                ),
                status=exc.code,
                method=method.upper(),
                path=path,
                response=parsed,
            ) from exc

        except urllib.error.URLError as exc:
            raise GitHubAPIError(
                f"GitHub API request failed for {method.upper()} {path}: {exc}",
                method=method.upper(),
                path=path,
            ) from exc

    # ------------------------------------------------------------------
    # Branch handling
    # ------------------------------------------------------------------

    def create_branch(
        self,
        repo: str,
        branch: str,
        from_sha: str,
    ) -> Dict[str, Any]:
        """Create refs/heads/<branch> from a commit SHA.

        If the exact branch already exists, return the existing ref instead
        of failing. This makes reruns safer.
        """

        repo = self._normalize_repo(repo)
        branch = self._normalize_branch(branch)
        from_sha = (from_sha or "").strip()

        if not from_sha:
            raise ValueError("from_sha must be non-empty")

        path = f"/repos/{repo}/git/refs"

        try:
            return self._request(
                "POST",
                path,
                {
                    "ref": f"refs/heads/{branch}",
                    "sha": from_sha,
                },
            )
        except GitHubAPIError as exc:
            # GitHub returns 422 when a ref already exists.
            if exc.status == 422:
                try:
                    return self.get_branch_ref(repo, branch)
                except Exception:
                    pass
            raise

    def get_branch_ref(
        self,
        repo: str,
        branch: str,
    ) -> Dict[str, Any]:
        """Return a branch's git ref."""

        repo = self._normalize_repo(repo)
        branch = self._normalize_branch(branch)

        # Branch names can contain "/" so quote while preserving path shape
        # expected by GitHub's matching-refs endpoint.
        encoded_branch = urllib.parse.quote(branch, safe="/")

        return self._request(
            "GET",
            f"/repos/{repo}/git/ref/heads/{encoded_branch}",
        )

    # ------------------------------------------------------------------
    # File handling
    # ------------------------------------------------------------------

    def get_file_blob_sha(
        self,
        repo: str,
        filepath: str,
        ref: str,
    ) -> str:
        """Return the Git blob SHA for a repository file at the given ref."""

        repo = self._normalize_repo(repo)
        filepath = self._normalize_filepath(filepath)
        ref = (ref or "").strip()

        encoded_path = urllib.parse.quote(filepath, safe="/")
        query = urllib.parse.urlencode({"ref": ref})

        result = self._request(
            "GET",
            f"/repos/{repo}/contents/{encoded_path}?{query}",
        )

        if not isinstance(result, dict):
            raise GitHubAPIError(
                f"Unexpected GitHub contents response for {filepath}: "
                f"{type(result).__name__}"
            )

        sha = result.get("sha")
        if not sha:
            raise GitHubAPIError(
                f"GitHub contents response for {filepath} did not contain sha"
            )

        return str(sha)

    def commit_file(
        self,
        repo: str,
        branch: str,
        filepath: str,
        content: bytes,
        message: str,
        *,
        sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create or update a file on a branch using GitHub's Contents API."""

        repo = self._normalize_repo(repo)
        branch = self._normalize_branch(branch)
        filepath = self._normalize_filepath(filepath)

        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        else:
            content_bytes = bytes(content)

        encoded_path = urllib.parse.quote(filepath, safe="/")

        payload: Dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content_bytes).decode("ascii"),
            "branch": branch,
        }

        # Updating an existing file requires its current blob SHA.
        # Creating a new file must omit sha.
        if sha:
            payload["sha"] = sha

        return self._request(
            "PUT",
            f"/repos/{repo}/contents/{encoded_path}",
            payload,
        )

    # ------------------------------------------------------------------
    # Pull requests
    # ------------------------------------------------------------------

    def create_pull_request(
        self,
        repo: str,
        title: str,
        head_branch: str,
        base_branch: str,
        body: str,
    ) -> int:
        """Create a pull request and return its PR number.

        If GitHub reports that a PR for the same head/base already exists,
        return that existing PR number instead of failing.
        """

        repo = self._normalize_repo(repo)
        head_branch = self._normalize_branch(head_branch)
        base_branch = self._normalize_branch(base_branch)

        try:
            result = self._request(
                "POST",
                f"/repos/{repo}/pulls",
                {
                    "title": title,
                    "head": head_branch,
                    "base": base_branch,
                    "body": body,
                    "maintainer_can_modify": True,
                },
            )
        except GitHubAPIError as exc:
            # A rerun can encounter "A pull request already exists".
            if exc.status == 422:
                existing = self._find_open_pull_request(
                    repo,
                    head_branch,
                    base_branch,
                )
                if existing is not None:
                    return existing
            raise

        if not isinstance(result, dict) or not result.get("number"):
            raise GitHubAPIError(
                f"GitHub create PR response did not contain a PR number: {result!r}"
            )

        return int(result["number"])

    def _find_open_pull_request(
        self,
        repo: str,
        head_branch: str,
        base_branch: str,
    ) -> Optional[int]:
        """Find an existing open PR for the same head/base pair."""

        owner = repo.split("/", 1)[0]

        query = urllib.parse.urlencode(
            {
                "state": "open",
                "head": f"{owner}:{head_branch}",
                "base": base_branch,
                "per_page": "20",
            }
        )

        result = self._request(
            "GET",
            f"/repos/{repo}/pulls?{query}",
        )

        if not isinstance(result, list):
            return None

        for pr in result:
            if not isinstance(pr, dict):
                continue

            number = pr.get("number")
            if number is not None:
                return int(number)

        return None

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_repo(repo: str) -> str:
        value = (repo or "").strip().strip("/")

        if value.startswith("https://github.com/"):
            value = value[len("https://github.com/"):]

        if value.endswith(".git"):
            value = value[:-4]

        parts = value.split("/")

        if len(parts) != 2 or not all(parts):
            raise ValueError(
                f"repo must be in owner/repo form, got {repo!r}"
            )

        return f"{parts[0]}/{parts[1]}"

    @staticmethod
    def _normalize_branch(branch: str) -> str:
        value = (branch or "").strip()

        if value.startswith("refs/heads/"):
            value = value[len("refs/heads/"):]

        if not value:
            raise ValueError("branch must be non-empty")

        return value

    @staticmethod
    def _normalize_filepath(filepath: str) -> str:
        value = (filepath or "").strip().replace("\\", "/")

        while value.startswith("./"):
            value = value[2:]

        value = value.lstrip("/")

        if not value:
            raise ValueError("filepath must be non-empty")

        return value

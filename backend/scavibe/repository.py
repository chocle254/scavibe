"""Public GitHub repository intake pinned to an immutable commit SHA."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

import httpx

from .contracts import AuditContext, SourceFile

GITHUB_REPOSITORY_PATTERN = re.compile(r"^/([^/]+)/([^/]+?)(?:\.git)?/?$")
MAX_SELECTED_FILES = 120
MAX_FILE_BYTES = 128 * 1024
MAX_TOTAL_SOURCE_BYTES = 2 * 1024 * 1024
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go",
    ".rb", ".php", ".cs", ".sql", ".html", ".css", ".json", ".yaml", ".yml",
    ".toml", ".env.example", ".md", ".txt", ".graphql", ".prisma", ".sh",
}
PRIORITY_NAMES = {"package.json", "requirements.txt", "dockerfile", "readme.md"}


class RepositoryIntakeError(RuntimeError):
    """The supplied URL could not be fetched as an auditable public GitHub repo."""


@dataclass(frozen=True)
class RepositorySnapshot:
    context: AuditContext
    selected_paths: list[str]
    source_content_complete: bool


def parse_github_repository(repository_url: str) -> tuple[str, str]:
    parsed = urlparse(repository_url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise RepositoryIntakeError("repository_url must be an HTTPS github.com owner/repository URL")
    match = GITHUB_REPOSITORY_PATTERN.fullmatch(parsed.path)
    if not match:
        raise RepositoryIntakeError("repository_url must identify exactly one GitHub owner and repository")
    return match.group(1), match.group(2)


def _is_text_source(path: str) -> bool:
    lower = path.lower()
    name = lower.rsplit("/", 1)[-1]
    if name in PRIORITY_NAMES or name.startswith(".env.example"):
        return True
    return any(lower.endswith(extension) for extension in TEXT_EXTENSIONS)


def _sort_key(path: str) -> tuple[int, str]:
    name = path.lower().rsplit("/", 1)[-1]
    return (0 if name in PRIORITY_NAMES else 1, path.lower())


async def fetch_public_repository(
    *, audit_id: str, repository_url: str, app_url: str, jurisdictions: list[str], runtime_measurements: list
) -> RepositorySnapshot:
    """Fetch at most 2 MiB of text source and the complete Git tree manifest.

    The selection limits are exact: 120 files, 128 KiB per file, and 2 MiB
    total. A truncated source selection is marked in the audit context and
    cannot support repository-wide absence claims.
    """
    owner, repository = parse_github_repository(repository_url)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "scavibe-audit"}
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    timeout = httpx.Timeout(20.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers) as client:
        repo_response = await client.get(f"https://api.github.com/repos/{owner}/{repository}")
        if repo_response.status_code == 404:
            raise RepositoryIntakeError("GitHub repository was not found or is private without a valid GITHUB_TOKEN")
        if repo_response.status_code != 200:
            raise RepositoryIntakeError(f"GitHub repository metadata request returned HTTP {repo_response.status_code}")
        default_branch = repo_response.json().get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise RepositoryIntakeError("GitHub repository has no readable default branch")
        ref_response = await client.get(f"https://api.github.com/repos/{owner}/{repository}/git/ref/heads/{default_branch}")
        if ref_response.status_code != 200:
            raise RepositoryIntakeError(f"GitHub branch reference request returned HTTP {ref_response.status_code}")
        commit_sha = ref_response.json().get("object", {}).get("sha")
        if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
            raise RepositoryIntakeError("GitHub did not return a 40-character commit SHA")
        tree_response = await client.get(f"https://api.github.com/repos/{owner}/{repository}/git/trees/{commit_sha}?recursive=1")
        if tree_response.status_code != 200:
            raise RepositoryIntakeError(f"GitHub tree request returned HTTP {tree_response.status_code}")
        tree_payload = tree_response.json()
        if tree_payload.get("truncated") is True:
            raise RepositoryIntakeError("GitHub tree response is truncated; Scavibe will not audit an incomplete manifest")
        paths = sorted(
            item["path"]
            for item in tree_payload.get("tree", [])
            if item.get("type") == "blob" and isinstance(item.get("path"), str)
        )
        candidates = sorted((path for path in paths if _is_text_source(path)), key=_sort_key)
        selected: list[SourceFile] = []
        selected_paths: list[str] = []
        total_bytes = 0
        for path in candidates:
            if len(selected) >= MAX_SELECTED_FILES or total_bytes >= MAX_TOTAL_SOURCE_BYTES:
                break
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repository}/{commit_sha}/{path}"
            content_response = await client.get(raw_url, headers={"User-Agent": "scavibe-audit"})
            if content_response.status_code != 200:
                continue
            content_bytes = content_response.content
            if len(content_bytes) > MAX_FILE_BYTES or b"\x00" in content_bytes:
                continue
            try:
                content = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if total_bytes + len(content_bytes) > MAX_TOTAL_SOURCE_BYTES:
                break
            selected.append(SourceFile(path=unquote(path), content=content))
            selected_paths.append(unquote(path))
            total_bytes += len(content_bytes)
    if not selected:
        raise RepositoryIntakeError("no supported UTF-8 text source file was available for audit")
    source_content_complete = len(candidates) == len(selected) and len(selected) < MAX_SELECTED_FILES
    return RepositorySnapshot(
        context=AuditContext(
            audit_id=audit_id,
            repository_url=repository_url,
            app_url=app_url,
            commit_sha=commit_sha,
            source_files=selected,
            repository_paths=paths,
            source_content_complete=source_content_complete,
            runtime_measurements=runtime_measurements,
            jurisdictions=jurisdictions,
        ),
        selected_paths=selected_paths,
        source_content_complete=source_content_complete,
    )

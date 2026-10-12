"""Publication du commentaire sur la Pull Request via l'API GitHub.

Le commentaire commence par un marqueur invisible : à chaque nouvelle exécution, l'agent met
à jour son commentaire au lieu d'en ajouter un autre.

Token attendu : le GITHUB_TOKEN du workflow avec seulement « pull-requests: write ».
"""

from __future__ import annotations

import json
import re
from typing import Callable

from .net import request_json
from .report import COMMENT_MARKER

MAX_COMMENT_CHARS = 60_000  # limite GitHub : 65 536
_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
_PR_REF_RE = re.compile(r"^refs/pull/(\d+)/")


def pull_request_number(env: dict) -> int | None:
    """Numéro de la PR, lu dans l'événement GitHub Actions."""
    try:
        with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as handle:
            number = json.load(handle)["pull_request"]["number"]
        if isinstance(number, int):
            return number
    except (KeyError, OSError, ValueError, TypeError):
        pass
    match = _PR_REF_RE.match(env.get("GITHUB_REF", ""))
    return int(match.group(1)) if match else None


def upsert_comment(
    body: str,
    repo: str,
    pr_number: int,
    token: str,
    api_url: str = "https://api.github.com",
    request: Callable | None = None,
) -> str:
    """Crée ou met à jour le commentaire de l'agent. Retourne « created » ou « updated »."""
    request = request or request_json
    if not _REPO_RE.match(repo):
        raise ValueError("nom de repo invalide")
    if len(body) > MAX_COMMENT_CHARS:
        body = body[:MAX_COMMENT_CHARS] + "\n\n… commentaire tronqué, voir l'artefact `triage.json`.\n"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "clinic-booking-ai-security-agent",
    }
    base = f"{api_url.rstrip('/')}/repos/{repo}/issues"

    for page in range(1, 6):
        comments = request("GET", f"{base}/{pr_number}/comments?per_page=100&page={page}", headers)
        for comment in comments:
            is_bot = (comment.get("user") or {}).get("type") == "Bot"
            if is_bot and str(comment.get("body", "")).startswith(COMMENT_MARKER):
                request("PATCH", f"{base}/comments/{comment['id']}", headers, {"body": body})
                return "updated"
        if len(comments) < 100:
            break
    request("POST", f"{base}/{pr_number}/comments", headers, {"body": body})
    return "created"

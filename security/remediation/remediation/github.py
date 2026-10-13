"""Appels à l'API GitHub : ouvrir la PR de correctif, poser le label, commenter.

Ce module ne contient volontairement AUCUNE fonction de merge ni d'approbation :
une PR de correctif attend toujours une validation humaine.
"""

from __future__ import annotations

import json
import re
from typing import Callable
from urllib.parse import quote

from . import LABEL
from .net import HttpError, request_json

MAX_COMMENT_CHARS = 60_000
_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
_PR_REF_RE = re.compile(r"^refs/pull/(\d+)/")


class GitHub:
    def __init__(self, repo: str, token: str, api_url: str = "https://api.github.com", request: Callable | None = None):
        if not _REPO_RE.match(repo):
            raise ValueError("nom de repo invalide")
        self.repo = repo
        self.owner = repo.split("/")[0]
        self._base = f"{api_url.rstrip('/')}/repos/{repo}"
        self._request = request or request_json
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "clinic-booking-auto-remediation",
        }

    def pulls_for_branch(self, branch: str) -> list[dict]:
        """Toutes les PR (ouvertes ou fermées) déjà créées depuis cette branche."""
        head = quote(f"{self.owner}:{branch}", safe="")
        pulls = self._request("GET", f"{self._base}/pulls?state=all&per_page=20&head={head}", self._headers)
        return [pull for pull in pulls if isinstance(pull, dict)] if isinstance(pulls, list) else []

    def create_pull(self, title: str, head: str, base: str, body: str) -> dict:
        payload = {"title": title, "head": head, "base": base, "body": body, "maintainer_can_modify": False}
        return self._request("POST", f"{self._base}/pulls", self._headers, payload)

    def add_label(self, number: int) -> None:
        try:  # crée le label s'il n'existe pas encore ; « déjà existant » (422) n'est pas une erreur
            self._request(
                "POST", f"{self._base}/labels", self._headers,
                {"name": LABEL, "color": "5319e7", "description": "Correctif proposé par la remédiation automatique"},
            )  # fmt: skip
        except HttpError:
            pass
        self._request("POST", f"{self._base}/issues/{number}/labels", self._headers, {"labels": [LABEL]})

    def upsert_comment(self, number: int, body: str, marker: str) -> str:
        """Crée le commentaire de synthèse, ou met à jour celui d'une exécution précédente."""
        if len(body) > MAX_COMMENT_CHARS:
            body = body[:MAX_COMMENT_CHARS] + "\n\n… commentaire tronqué.\n"
        comments = self._request("GET", f"{self._base}/issues/{number}/comments?per_page=100", self._headers)
        for comment in comments if isinstance(comments, list) else []:
            is_bot = (comment.get("user") or {}).get("type") == "Bot"
            if is_bot and str(comment.get("body", "")).startswith(marker):
                self._request("PATCH", f"{self._base}/issues/comments/{comment['id']}", self._headers, {"body": body})
                return "updated"
        self._request("POST", f"{self._base}/issues/{number}/comments", self._headers, {"body": body})
        return "created"


def pull_request_number(env: dict) -> int | None:
    """Numéro de la PR en cours d'analyse, lu dans l'événement GitHub Actions."""
    try:
        with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as handle:
            number = json.load(handle)["pull_request"]["number"]
        if isinstance(number, int):
            return number
    except (KeyError, OSError, ValueError, TypeError):
        pass
    match = _PR_REF_RE.match(env.get("GITHUB_REF", ""))
    return int(match.group(1)) if match else None

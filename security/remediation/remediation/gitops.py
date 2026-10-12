"""Opérations Git de la remédiation.

Chaque correctif est préparé dans un « worktree » : une copie de travail séparée, dans un
dossier temporaire. Le dossier courant n'est jamais modifié, même si un correctif échoue.

Toutes les commandes sont lancées sans shell, avec des arguments déjà validés par
guardrails.py.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from . import BRANCH_PREFIX, guardrails

GIT_TIMEOUT_SECONDS = 120


class GitError(Exception):
    pass


class Git:
    def __init__(self, repo: Path, remote: str = "origin"):
        self.repo = repo
        self.remote = remote

    def run(self, *args: str, cwd: Path | None = None) -> str:
        try:
            done = subprocess.run(
                ["git", *args], cwd=cwd or self.repo, capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitError(f"git {args[0]} : {type(exc).__name__}") from None
        if done.returncode != 0:
            # Seule la dernière ligne de l'erreur : jamais l'URL du remote, qui peut contenir un token.
            detail = (done.stderr.strip().splitlines() or ["erreur"])[-1]
            raise GitError(f"git {args[0]} a échoué : {detail[:200]}")
        return done.stdout

    def fetch(self, branch: str) -> None:
        _check_branch(branch)
        self.run("fetch", "--quiet", self.remote, f"+refs/heads/{branch}:refs/remotes/{self.remote}/{branch}")

    def remote_branch_exists(self, branch: str) -> bool:
        _check_branch(branch)
        return bool(self.run("ls-remote", "--heads", self.remote, f"refs/heads/{branch}").strip())

    def add_worktree(self, path: Path, branch: str, base: str) -> None:
        _check_branch(branch)
        _check_branch(base)
        self.run("worktree", "add", "--quiet", "-B", branch, str(path), f"refs/remotes/{self.remote}/{base}")

    def changed_files(self, worktree: Path) -> list[str]:
        """Fichiers réellement modifiés, ajoutés ou supprimés dans le worktree."""
        output = self.run("status", "--porcelain", "--untracked-files=all", "-z", cwd=worktree)
        files = []
        for entry in filter(None, output.split("\0")):
            if entry[:2].strip() and entry[0] in "RC":
                raise GitError("renommage inattendu dans le correctif")
            files.append(entry[3:])
        return files

    def commit(self, worktree: Path, files: list[str], message: str, author_name: str, author_email: str) -> str:
        self.run("add", "--", *files, cwd=worktree)
        self.run(
            "-c", f"user.name={author_name}", "-c", f"user.email={author_email}",
            "commit", "--quiet", "-m", message, cwd=worktree,
        )  # fmt: skip
        return self.run("rev-parse", "HEAD", cwd=worktree).strip()

    def push(self, branch: str) -> None:
        _check_branch(branch)
        # Pas de --force : si la branche existe déjà sur le remote, le push échoue.
        self.run("push", "--quiet", self.remote, f"refs/heads/{branch}:refs/heads/{branch}")

    def delete_remote_branch(self, branch: str) -> None:
        """Retire une branche de correctif restée sans PR. Ne lève jamais d'erreur."""
        if not branch.startswith(BRANCH_PREFIX):
            return
        try:
            self.run("push", "--quiet", self.remote, "--delete", f"refs/heads/{branch}")
        except GitError:
            pass

    def remove_worktree(self, path: Path, branch: str) -> None:
        """Nettoyage. Ne lève jamais d'erreur : il est appelé même après un échec."""
        for args in (("worktree", "remove", "--force", str(path)), ("branch", "-D", branch)):
            try:
                self.run(*args)
            except GitError:
                pass


def _check_branch(name: str) -> None:
    if not guardrails.BRANCH_RE.match(name):
        raise GitError("nom de branche refusé")

"""Ligne de commande de la remédiation automatique.

    python -m remediation --triage reports/triage.json            # simulation : n'écrit rien
    python -m remediation --triage reports/triage.json --apply    # ouvre les PR de correctif

Pour chaque paquet vulnérable du triage :
branche autofix/<id> → commit → push → Pull Request (label ai-autofix) → la pipeline se relance.

Garde-fous : nombre maximum de PR, fichiers autorisés seulement, jamais de merge, pas de
doublon, et un commentaire à la place d'un correctif qui n'a pas pu être validé.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import BRANCH_PREFIX, fixers, guardrails
from .fixers import CannotFix
from .github import GitHub, pull_request_number
from .gitops import Git, GitError
from .guardrails import GuardrailError
from .net import HttpError
from .report import SUMMARY_MARKER, Outcome, build_report, commit_message, pr_body, pr_title, render_summary
from .triage_input import Candidate, TriageError, load_triage, select

BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


def log(message: str) -> None:
    # Une seule ligne, préfixée : un texte non fiable ne peut pas injecter de commande
    # GitHub Actions dans les logs.
    print("[remediation] " + " ".join(str(message).split()), flush=True)


def main(argv: list[str] | None = None, env: dict | None = None, run_tool=fixers.run_tool, request=None) -> int:
    env = dict(os.environ) if env is None else env
    parser = argparse.ArgumentParser(prog="remediation", description="Ouvre des PR de correctif à partir du triage.")
    parser.add_argument("--triage", default="reports/triage.json", help="fichier produit par l'agent IA")
    parser.add_argument("--output", default="reports", help="dossier où écrire remediation.json et remediation.md")
    parser.add_argument("--repo-root", default=".", help="racine du repo Git")
    parser.add_argument("--base", default="", help="branche à corriger (défaut : la branche de la PR en cours)")
    parser.add_argument("--max-prs", type=int, default=guardrails.DEFAULT_MAX_PRS, help="nombre maximum de PR par exécution")
    parser.add_argument("--apply", action="store_true", help="créer réellement les branches et les PR (sinon : simulation)")
    args = parser.parse_args(argv)

    try:
        candidates, skipped = select(load_triage(Path(args.triage)))
    except TriageError as exc:
        log(exc)
        return 2
    max_prs = guardrails.clamp_max_prs(args.max_prs)
    base = args.base or env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME") or ""
    root = Path(args.repo_root)
    log(f"{len(candidates)} correctif(s) de dépendance possible(s), {len(skipped)} finding(s) hors périmètre")

    if base.startswith(BRANCH_PREFIX):
        # Sans cette règle, la PR du bot déclencherait la pipeline, qui rouvrirait une PR, etc.
        log("branche de correctif automatique : la remédiation ne se corrige pas elle-même")
        candidates = []

    if not args.apply:
        outcomes = [_simulate(root, candidate) for candidate in candidates]
        api = None
    else:
        token = env.get("AUTOFIX_TOKEN") or env.get("GITHUB_TOKEN") or ""
        repo = env.get("GITHUB_REPOSITORY", "")
        if not (token and repo and guardrails.BRANCH_RE.match(base)):
            log("--apply demande GITHUB_REPOSITORY, un token (AUTOFIX_TOKEN ou GITHUB_TOKEN) et une branche de base valide")
            return 2
        try:
            api = GitHub(repo, token, env.get("GITHUB_API_URL", "https://api.github.com"), request)
            git = Git(root)
            if candidates:
                git.fetch(base)
        except (ValueError, GitError) as exc:
            log(exc)
            return 2
        author = (env.get("AUTOFIX_GIT_NAME") or BOT_NAME, env.get("AUTOFIX_GIT_EMAIL") or BOT_EMAIL)
        outcomes = []
        for candidate in candidates:
            opened = sum(1 for outcome in outcomes if outcome.status == "opened")
            if opened >= max_prs:
                outcomes.append(Outcome.of(candidate, "skipped", reason=f"limite de {max_prs} PR par exécution atteinte"))
                continue
            outcomes.append(_fix(candidate, base, git, api, author, run_tool))

    for outcome in outcomes:
        log(f"{outcome.status} : {outcome.package} {outcome.installed_version} → {outcome.target_version} {outcome.reason or outcome.pr_url}")

    report = build_report(outcomes, skipped, "apply" if args.apply else "dry-run", base, max_prs)
    summary = render_summary(report)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "remediation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_dir / "remediation.md").write_text(summary, encoding="utf-8")
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(summary)

    number = pull_request_number(env)
    if api is not None and number and (outcomes or skipped):
        try:
            log(f"synthèse sur la PR #{number} : {api.upsert_comment(number, summary, SUMMARY_MARKER)}")
        except (HttpError, TypeError, KeyError, AttributeError) as exc:
            log(f"synthèse non publiée : {exc}")
    return 0


def _simulate(root: Path, candidate: Candidate) -> Outcome:
    """Simulation : on vérifie seulement qu'un correctif est possible, sans rien écrire."""
    try:
        fix = fixers.plan(root, candidate)
        if fix.edits:
            guardrails.check_changed_files(list(fix.edits))
    except (CannotFix, GuardrailError) as exc:
        return Outcome.of(candidate, "failed", reason=str(exc))
    return Outcome.of(candidate, "planned", branch=BRANCH_PREFIX + candidate.id)


def _fix(candidate: Candidate, base: str, git: Git, api: GitHub, author: tuple[str, str], run_tool) -> Outcome:
    branch = BRANCH_PREFIX + candidate.id
    try:
        # Pas de doublon, et on respecte la décision d'un humain qui a fermé la PR.
        for pull in api.pulls_for_branch(branch):
            if pull.get("state") == "open":
                return Outcome.of(candidate, "skipped", branch=branch, reason=f"PR déjà ouverte (#{pull.get('number')})")
            if not pull.get("merged_at"):
                return Outcome.of(candidate, "skipped", branch=branch, reason=f"déjà proposé puis fermé sans merge (#{pull.get('number')})")
        if git.remote_branch_exists(branch):
            return Outcome.of(candidate, "skipped", branch=branch, reason="la branche de correctif existe déjà")
    except (HttpError, GitError) as exc:
        return Outcome.of(candidate, "failed", branch=branch, reason=str(exc))

    with tempfile.TemporaryDirectory(prefix="autofix-") as tmp:
        worktree = Path(tmp) / "repo"
        try:
            git.add_worktree(worktree, branch, base)
            fix = fixers.plan(worktree, candidate)
            fixers.apply(worktree, fix, run_tool)
            changed = git.changed_files(worktree)
            guardrails.check_changed_files(changed)  # sur les fichiers réellement modifiés
            fixers.verify(worktree, candidate)
            git.commit(worktree, changed, commit_message(candidate), *author)
            git.push(branch)
        except (CannotFix, GuardrailError, GitError) as exc:
            return Outcome.of(candidate, "failed", branch=branch, reason=str(exc))
        finally:
            git.remove_worktree(worktree, branch)

    try:
        pull = api.create_pull(pr_title(candidate), branch, base, pr_body(candidate))
        number, url = int(pull["number"]), str(pull.get("html_url", ""))
    except (HttpError, KeyError, TypeError, ValueError) as exc:
        git.delete_remote_branch(branch)  # pas de branche orpheline sans PR
        return Outcome.of(candidate, "failed", branch=branch, reason=f"branche poussée mais PR non créée ({exc})")
    try:
        api.add_label(number)
    except HttpError as exc:
        log(f"label non posé sur la PR #{number} : {exc}")
    return Outcome.of(candidate, "opened", branch=branch, pr_number=number, pr_url=url)


if __name__ == "__main__":
    sys.exit(main())

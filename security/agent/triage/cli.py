"""Ligne de commande de l'agent.

    python -m triage --input reports --output reports --comment

Étapes : lire les SARIF → normaliser → dédupliquer → triage LLM → Risk Score →
reports/triage.json + reports/triage.md (+ commentaire sur la PR).

L'agent conseille, il ne bloque pas : il sort en code 0 même si le LLM ou le commentaire
échouent. Le blocage du merge est le rôle de la quality gate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import github, llm
from .dedupe import TriagedFinding, deduplicate
from .net import HttpError
from .recommend import default_recommendation
from .report import build_triage, render_markdown
from .sarif import load_reports
from .scoring import score


def log(message: str) -> None:
    # Une seule ligne, préfixée : un texte non fiable ne peut pas injecter de commande
    # GitHub Actions (« ::error:: », « ::add-mask:: »...) dans les logs.
    print("[agent] " + " ".join(str(message).split()), flush=True)


def main(argv: list[str] | None = None, env: dict | None = None) -> int:
    env = dict(os.environ) if env is None else env
    parser = argparse.ArgumentParser(prog="triage", description="Agent IA de triage des rapports SARIF.")
    parser.add_argument("--input", default="reports", help="dossier des rapports SARIF (sous-dossiers inclus)")
    parser.add_argument("--output", default="reports", help="dossier où écrire triage.json et triage.md")
    parser.add_argument("--source-root", default=".", help="racine du repo, pour lire le code autour d'un finding")
    parser.add_argument("--llm", choices=("auto", "none"), default="auto", help="auto = Gemini si GEMINI_API_KEY existe")
    parser.add_argument("--model", default="", help=f"modèle Gemini (défaut : {llm.DEFAULT_MODEL})")
    parser.add_argument("--comment", action="store_true", help="publier le résultat en commentaire de la PR")
    parser.add_argument("--check-llm", action="store_true", help="tester l'appel au LLM avec un finding fictif, puis quitter")
    args = parser.parse_args(argv)

    config, reason = llm.config_from_env(args.llm, args.model, env)
    if args.check_llm:
        return check_llm(config, reason)

    input_dir = Path(args.input)
    if not input_dir.is_dir():
        log(f"dossier introuvable : {input_dir}")
        return 2

    raw, warnings = load_reports(input_dir, env.get("GITHUB_WORKSPACE", ""))
    reports = len(list(input_dir.rglob("*.sarif")))
    if reports == 0:
        warnings.append("Aucun rapport SARIF trouvé : rien n'a été analysé.")
    findings = deduplicate(raw)
    for finding in findings:
        finding.recommendation = default_recommendation(finding)
    log(f"{reports} rapport(s) SARIF, {len(raw)} finding(s) bruts, {len(findings)} après déduplication")

    if config is None:
        status = {"provider": None, "model": None, "used": False, "triaged": 0, "error": reason}
    else:
        status = llm.triage(findings, config, Path(args.source_root))
    log(f"triage LLM : {status['triaged']} finding(s) analysé(s)" + (f", erreur : {status['error']}" if status["error"] else ""))

    for finding in findings:
        score(finding)

    triage = build_triage(findings, len(raw), warnings, status, commit=env.get("GITHUB_SHA"))
    markdown = render_markdown(triage)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "triage.json").write_text(json.dumps(triage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_dir / "triage.md").write_text(markdown, encoding="utf-8")
    log(f"écrit : {output_dir / 'triage.json'} et {output_dir / 'triage.md'} (Risk Score max : {triage['summary']['max_risk_score']})")

    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(markdown)
    if args.comment:
        post_comment(markdown, env)
    return 0


def post_comment(markdown: str, env: dict) -> None:
    token = env.get("GITHUB_TOKEN", "")
    repo = env.get("GITHUB_REPOSITORY", "")
    pr_number = github.pull_request_number(env)
    if not (token and repo and pr_number):
        log("commentaire non publié : pas de Pull Request ou pas de GITHUB_TOKEN")
        return
    api_url = env.get("GITHUB_API_URL", "https://api.github.com")
    try:
        log(f"commentaire de la PR #{pr_number} : {github.upsert_comment(markdown, repo, pr_number, token, api_url)}")
    except (HttpError, ValueError, TypeError, KeyError, AttributeError) as exc:
        log(f"commentaire non publié : {exc}")


def check_llm(config: llm.LLMConfig | None, reason: str | None) -> int:
    """Envoie un finding fictif au LLM : vérifie la clé, le modèle et le format de réponse."""
    if config is None:
        log(f"LLM non configuré : {reason}")
        return 1
    sample = TriagedFinding(
        id="test00000000",
        category="code",
        severity="high",
        cvss=8.8,
        tools=["CodeQL"],
        rules=["cs/sql-injection"],
        cwe=["CWE-89"],
        file="api/Controllers/DemoController.cs",
        line=1,
        message="This query depends on a user-provided value.",
        package=None,
    )
    status = llm.triage([sample], config)
    if not status["used"]:
        log(f"échec de l'appel à {config.model} : {status['error'] or 'réponse sans évaluation valide'}")
        return 1
    score(sample)
    log(
        f"OK, {config.model} répond. Faux positif : {sample.false_positive_probability}, "
        f"exploitabilité : {sample.exploitability}, Risk Score : {sample.risk_score}. "
        f"Recommandation : {sample.recommendation}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

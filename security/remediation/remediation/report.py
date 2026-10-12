"""Textes produits par la remédiation : corps de la PR de correctif, synthèse, rapport JSON.

Les textes qui viennent de triage.json (règles, fichiers, recommandations) sont non fiables :
ils passent par md() avant d'être affichés sur GitHub.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from . import SCHEMA_VERSION
from .triage_input import Candidate, Skipped

SUMMARY_MARKER = "<!-- ai-autofix-summary -->"
MAX_SKIPPED_SHOWN = 20

_URL_RE = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>()\[\]]+")
_MD_SPECIAL_RE = re.compile(r"([\\`*_\[\]|~])")
_STATUS_LABEL = {
    "opened": "✅ PR ouverte",
    "planned": "📝 Correctif possible (simulation)",
    "failed": "💬 Pas de correctif sûr",
    "skipped": "⏭️ Ignoré",
}


@dataclass
class Outcome:
    """Ce qui s'est passé pour un correctif."""

    status: str  # opened | planned | failed | skipped
    id: str
    package: str
    ecosystem: str
    manifest: str
    installed_version: str
    target_version: str
    advisories: list[str]
    finding_ids: list[str]
    risk_score: float
    major_bump: bool
    branch: str = ""
    pr_number: int | None = None
    pr_url: str = ""
    reason: str = ""

    @classmethod
    def of(cls, candidate: Candidate, status: str, **extra) -> "Outcome":
        return cls(
            status=status,
            id=candidate.id,
            package=candidate.package,
            ecosystem=candidate.ecosystem,
            manifest=candidate.manifest,
            installed_version=candidate.installed_version,
            target_version=candidate.target_version,
            advisories=candidate.advisories,
            finding_ids=candidate.finding_ids,
            risk_score=candidate.risk_score,
            major_bump=candidate.major_bump,
            **extra,
        )


def md(text, limit: int = 300) -> str:
    """Rend un texte non fiable inoffensif dans un commentaire GitHub."""
    text = _URL_RE.sub("(lien retiré)", str(text))
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _MD_SPECIAL_RE.sub(r"\\\1", text)
    return text.replace("@", "@​")  # espace invisible : empêche de notifier un compte


def pr_title(candidate: Candidate) -> str:
    return f"fix: bump {candidate.package} from {candidate.installed_version} to {candidate.target_version}"


def commit_message(candidate: Candidate) -> str:
    fixed = ", ".join(candidate.advisories) or "une vulnérabilité connue"
    return (
        f"{pr_title(candidate)}\n\n"
        f"Corrige {fixed}.\n"
        f"Correctif proposé par la remédiation automatique (finding {', '.join(candidate.finding_ids)})."
    )


def pr_body(candidate: Candidate) -> str:
    # Toutes ces valeurs ont été validées par guardrails.py (expressions régulières strictes).
    lines = [
        f"## Correctif automatique : {candidate.package} {candidate.installed_version} → {candidate.target_version}",
        "",
        "| | |",
        "|---|---|",
        f"| Paquet | `{candidate.package}` ({candidate.ecosystem}) |",
        f"| Version | `{candidate.installed_version}` → `{candidate.target_version}` |",
        f"| Vulnérabilité(s) | {', '.join(candidate.advisories) or 'non précisé'} |",
        f"| Risk Score | {candidate.risk_score:.1f}/10 |",
        f"| Fichier signalé | `{candidate.manifest}` |",
        f"| Finding(s) du triage | {', '.join(f'`{i}`' for i in candidate.finding_ids)} |",
        "",
    ]
    if candidate.major_bump:
        lines += [
            "> ⚠️ **Changement de version majeure** : le paquet peut avoir changé de comportement. "
            "Lire son changelog avant de merger.",
            "",
        ]
    lines += [
        "## À vérifier avant de merger",
        "- [ ] La pipeline est verte : build, tests et scans",
        "- [ ] Le diff ne contient que la mise à jour attendue",
        "- [ ] Le changelog du paquet ne signale pas de changement cassant",
        "",
        "Cette PR a été ouverte par la remédiation automatique. "
        "**Elle n'est jamais mergée automatiquement** : une approbation humaine est obligatoire.",
        "",
    ]
    return "\n".join(lines)


def build_report(outcomes: list[Outcome], skipped: list[Skipped], mode: str, base: str, max_prs: int) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": mode,  # apply | dry-run
        "base": base,
        "max_prs": max_prs,
        "opened": sum(1 for outcome in outcomes if outcome.status == "opened"),
        "results": [asdict(outcome) for outcome in outcomes],
        "not_fixable": [asdict(item) for item in skipped],
    }


def render_summary(report: dict) -> str:
    lines = [SUMMARY_MARKER, "## Remédiation automatique", ""]
    results = report["results"]
    if report["mode"] == "dry-run":
        lines += ["Mode **simulation** : aucune branche ni Pull Request n'a été créée.", ""]
    if not results:
        lines.append("Aucun paquet vulnérable à mettre à jour dans ce triage.")
    else:
        lines += [
            "| Résultat | Paquet | Version | Vulnérabilité(s) | Détail |",
            "|---|---|---|---|---|",
        ]
        lines += [_row(result) for result in results]
    not_fixable = report["not_fixable"]
    if not_fixable:
        lines += ["", "<details>", f"<summary>{len(not_fixable)} finding(s) non corrigés automatiquement</summary>", ""]
        for item in not_fixable[:MAX_SKIPPED_SHOWN]:
            line = f"- **{md(item['title'], 160)}** : {md(item['reason'], 200)}"
            if item["recommendation"]:
                line += f"<br>Recommandation : {md(item['recommendation'], 300)}"
            lines.append(line)
        if len(not_fixable) > MAX_SKIPPED_SHOWN:
            lines.append(f"- … et {len(not_fixable) - MAX_SKIPPED_SHOWN} autre(s)")
        lines += ["", "</details>"]
    lines += [
        "",
        f"> Au plus {report['max_prs']} PR de correctif par exécution. "
        "Aucune n'est mergée automatiquement : une approbation humaine est obligatoire.",
    ]
    return "\n".join(lines) + "\n"


def _row(result: dict) -> str:
    detail = md(result["reason"], 250)
    if result["status"] == "opened":
        detail = f"#{result['pr_number']} (branche `{result['branch']}`)"
    if result["major_bump"]:
        detail += " ⚠️ version majeure"
    cells = [
        _STATUS_LABEL[result["status"]],
        f"`{result['package']}`",
        f"{result['installed_version']} → {result['target_version']}",
        ", ".join(result["advisories"]) or "non précisé",
        detail.strip(),
    ]
    return "| " + " | ".join(cells) + " |"

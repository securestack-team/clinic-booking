"""Textes produits par la remédiation : corps de la PR de correctif, synthèse, rapport JSON.

Les textes qui viennent de triage.json (règles, fichiers, recommandations) sont non fiables :
ils passent par md() avant d'être affichés sur GitHub.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from . import SCHEMA_VERSION
from .codefix import TITLE, CodeCandidate
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
    kind: str  # dependency (v1) | code (v2, patch proposé par LLM)
    risk_score: float
    finding_ids: list[str]
    # correctif de dépendance
    package: str = ""
    ecosystem: str = ""
    manifest: str = ""
    installed_version: str = ""
    target_version: str = ""
    advisories: list[str] = field(default_factory=list)
    major_bump: bool = False
    # patch de code
    file: str = ""
    line: int = 0
    cwe: list[str] = field(default_factory=list)
    fix: str = ""  # sql | authz | secret
    # résultat
    branch: str = ""
    pr_number: int | None = None
    pr_url: str = ""
    reason: str = ""

    @property
    def label(self) -> str:
        if self.kind == "code":
            return f"patch LLM ({self.fix}) {self.file}:{self.line}"
        return f"{self.package} {self.installed_version} → {self.target_version}"

    @classmethod
    def of(cls, candidate: Candidate, status: str, **extra) -> "Outcome":
        return cls(
            status=status,
            id=candidate.id,
            kind="dependency",
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

    @classmethod
    def of_code(cls, candidate: CodeCandidate, status: str, **extra) -> "Outcome":
        return cls(
            status=status,
            id=candidate.id,
            kind="code",
            risk_score=candidate.risk_score,
            finding_ids=[candidate.id],
            file=candidate.file,
            line=candidate.line,
            cwe=candidate.cwe,
            fix=candidate.kind,
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


def code_pr_title(candidate: CodeCandidate) -> str:
    return f"fix: {TITLE[candidate.kind]} in {candidate.file.rsplit('/', 1)[-1]}"


def code_commit_message(candidate: CodeCandidate) -> str:
    return (
        f"{code_pr_title(candidate)}\n\n"
        f"Corrige {', '.join(candidate.cwe)} ({candidate.file}, ligne {candidate.line}).\n"
        f"Patch proposé par un LLM via la remédiation automatique (finding {candidate.id})."
    )


def code_pr_body(candidate: CodeCandidate, explanation: str) -> str:
    lines = [
        f"## Correctif automatique proposé par un LLM : {TITLE[candidate.kind]}",
        "",
        "> ⚠️ **Ce patch a été écrit par un LLM.** Il compile, mais personne ne l'a encore relu. "
        "Lire le diff ligne par ligne avant d'approuver.",
        "",
        "| | |",
        "|---|---|",
        f"| Fichier | `{candidate.file}`, ligne {candidate.line} |",
        f"| Vulnérabilité | {', '.join(candidate.cwe)} ({md(candidate.rule, 120)}) |",
        f"| Risk Score | {candidate.risk_score:.1f}/10 |",
        f"| Finding du triage | `{candidate.id}` |",
        f"| Explication du LLM | {md(explanation, 400) or 'aucune'} |",
        "",
    ]
    if candidate.kind == "secret":
        lines += [
            "> 🔑 **Le secret reste dans l'historique Git.** Cette PR le retire du code, mais il doit "
            "être **révoqué** et remplacé, puis rangé dans Key Vault / user-secrets.",
            "",
        ]
    lines += [
        "## À vérifier avant de merger",
        "- [ ] Le diff ne fait que corriger la vulnérabilité, rien d'autre",
        "- [ ] La pipeline est verte : build, tests et scans (le finding a disparu)",
        "- [ ] Le comportement de l'endpoint est toujours le bon",
        "",
        "Contrôles déjà passés : un seul fichier modifié, patch de petite taille, pas de secret ajouté, "
        "`dotnet build` réussi. **Cette PR n'est jamais mergée automatiquement.**",
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
        lines.append("Aucun correctif automatique possible pour ce triage.")
    else:
        lines += [
            "| Résultat | Correctif | Vulnérabilité(s) | Détail |",
            "|---|---|---|---|",
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
    if result["kind"] == "code":
        # Chemin et CWE viennent du triage, mais ont été validés par guardrails.py.
        fix = f"Patch LLM : {TITLE[result['fix']]}<br>`{result['file']}`, ligne {result['line']}"
        vulnerabilities = ", ".join(result["cwe"])
    else:
        fix = f"`{result['package']}` {result['installed_version']} → {result['target_version']}"
        vulnerabilities = ", ".join(result["advisories"]) or "non précisé"
    return "| " + " | ".join([_STATUS_LABEL[result["status"]], fix, vulnerabilities, detail.strip()]) + " |"

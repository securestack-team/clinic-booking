"""Sorties de l'agent : reports/triage.json (pour la remédiation) et le commentaire Markdown.

Tout texte affiché dans le commentaire vient d'un scanner ou du LLM, donc potentiellement
d'un attaquant : il passe par md(), qui neutralise le Markdown, le HTML, les liens et les
mentions.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from datetime import datetime, timezone

from . import SCHEMA_VERSION
from .dedupe import TriagedFinding
from .sarif import SEVERITIES

COMMENT_MARKER = "<!-- ai-security-agent -->"
MAX_COMMENT_FINDINGS = 25

_RISK_LEVELS = ("critical", "high", "medium", "low")
_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
_LEVEL_FR = {"critical": "critique", "high": "élevé", "medium": "moyen", "low": "faible", "info": "info"}
_URL_RE = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>()\[\]]+")
_MD_SPECIAL_RE = re.compile(r"([\\`*_\[\]|~])")


def sort_findings(findings: list[TriagedFinding]) -> list[TriagedFinding]:
    return sorted(
        findings,
        key=lambda f: (-f.risk_score, -SEVERITIES.index(f.severity), f.file, f.line, f.id),
    )


def build_triage(
    findings: list[TriagedFinding],
    raw_count: int,
    warnings: list[str],
    llm_status: dict,
    commit: str | None = None,
    now: datetime | None = None,
) -> dict:
    findings = sort_findings(findings)
    now = now or datetime.now(timezone.utc)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": commit or None,
        "llm": llm_status,
        "summary": {
            "raw_findings": raw_count,
            "findings": len(findings),
            "max_risk_score": max((f.risk_score for f in findings), default=0.0),
            "by_risk_level": {
                level: sum(1 for f in findings if f.risk_level == level) for level in _RISK_LEVELS
            },
            "warnings": warnings,
        },
        "findings": [asdict(f) for f in findings],
    }


def md(text, limit: int = 300) -> str:
    """Rend un texte non fiable inoffensif dans un commentaire GitHub."""
    text = _URL_RE.sub("(lien retiré)", str(text))
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _MD_SPECIAL_RE.sub(r"\\\1", text)
    return text.replace("@", "@​")  # espace invisible : empêche de notifier un compte


def render_markdown(triage: dict) -> str:
    summary = triage["summary"]
    findings = triage["findings"]
    lines = [COMMENT_MARKER, "## Agent IA de sécurité : triage des findings", ""]

    if not findings:
        lines.append("✅ **Aucun finding** dans les rapports SARIF analysés.")
    else:
        counts = " · ".join(
            f"{_ICON[level]} {_LEVEL_FR[level]} : {summary['by_risk_level'][level]}"
            for level in _RISK_LEVELS
            if summary["by_risk_level"][level]
        )
        lines.append(
            f"**{summary['findings']} finding(s)** après déduplication "
            f"({summary['raw_findings']} bruts) · Risk Score maximum : "
            f"**{summary['max_risk_score']:.1f}/10** · {counts}"
        )
    lines += ["", _llm_line(triage["llm"]), ""]

    if findings:
        lines += [
            "| Risk Score | Sévérité scanner | Finding | Emplacement | Outil(s) | Faux positif | Recommandation |",
            "|---|---|---|---|---|---|---|",
        ]
        lines += [_row(finding) for finding in findings[:MAX_COMMENT_FINDINGS]]
        hidden = len(findings) - MAX_COMMENT_FINDINGS
        if hidden > 0:
            lines += ["", f"… et {hidden} autre(s) finding(s) moins prioritaires : voir l'artefact `triage.json`."]
        lines += [
            "",
            "> Le Risk Score sert à **prioriser**. La quality gate de la pipeline reste basée sur "
            "les sévérités brutes des scanners : l'agent ne peut pas débloquer un merge.",
        ]

    for warning in summary["warnings"]:
        lines += ["", f"⚠️ {md(warning)}"]
    lines += ["", _FORMULA]
    return "\n".join(lines) + "\n"


def _llm_line(llm: dict) -> str:
    if llm.get("used"):
        line = f"Triage LLM : ✅ {md(llm.get('model'))} ({llm.get('triaged')} finding(s) analysé(s))"
        if llm.get("error"):
            line += f", puis interrompu ({md(llm['error'])}) : le reste garde sa sévérité brute"
        return line + "."
    reason = llm.get("error") or "non configuré"
    return f"Triage LLM : ⚠️ indisponible ({md(reason)}). Les scores utilisent les **sévérités brutes** des scanners."


def _row(finding: dict) -> str:
    title = f"**{md(', '.join(finding['rules']), 120)}**"
    if finding["cwe"]:
        title += f" ({md(', '.join(finding['cwe']), 60)})"
    title += f"<br>{md(finding['message'], 200)}"
    if finding["occurrences"] > 1:
        title += f"<br>{finding['occurrences']} signalements fusionnés"

    location = md(finding["file"] or "(sans fichier)", 120)
    if finding["line"]:
        location += f":{finding['line']}"

    if finding["category"] == "secret":
        false_positive = "non envoyé au LLM"
    elif finding["llm_triaged"]:
        false_positive = f"{round(finding['false_positive_probability'] * 100)} %"
        # Le LLM contredit le scanner sur une faille grave : c'est à un humain de trancher.
        if finding["false_positive_probability"] >= 0.5 and finding["severity"] in ("high", "critical"):
            false_positive += " ⚠️ à confirmer par un humain"
    else:
        false_positive = "non évalué"

    recommendation = md(finding["recommendation"], 400)
    if finding["llm_triaged"] and finding["rationale"]:
        recommendation += f"<br>*Analyse : {md(finding['rationale'], 300)}*"

    cells = [
        f"{_ICON[finding['risk_level']]} **{finding['risk_score']:.1f}**",
        _LEVEL_FR[finding["severity"]],
        title,
        location,
        md(", ".join(finding["tools"]), 80),
        false_positive,
        recommendation,
    ]
    return "| " + " | ".join(cells) + " |"


_FORMULA = """\
<details>
<summary>Comment est calculé le Risk Score ?</summary>

**Risk Score = Sévérité × Exposition × Confiance** (de 0 à 10)

- **Sévérité** (0 à 10) : score CVSS donné par le scanner, sinon critical 9.5, high 8.0, medium 5.5, low 2.0.
- **Exposition** (0 à 1) : où se trouve le code (API 1.0, web/mobile/infra 0.9, tests 0.4), pondérée par l'exploitabilité estimée par le LLM.
- **Confiance** (0 à 1) : 1 − probabilité de faux positif estimée par le LLM, jamais sous 0.5. Sans LLM : 1.0.

Un secret vaut toujours 9.5 et n'est jamais envoyé au LLM. Le LLM peut baisser un score, jamais le monter ni supprimer un finding.
Niveaux : 🔴 critique ≥ 9 · 🟠 élevé ≥ 7 · 🟡 moyen ≥ 4 · 🟢 faible < 4.
</details>"""

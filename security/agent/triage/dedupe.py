"""Déduplication : plusieurs scanners signalent souvent le même problème.

Deux findings sont « le même » quand ils ont la même clé :
- secret      : même fichier et même ligne (Gitleaks et Trivy voient le même secret) ;
- dépendance  : même CVE, même paquet, même fichier ;
- code/config : même fichier, même ligne et même CWE (CodeQL et Semgrep sur la même faille) ;
                sans CWE, on ne fusionne que les doublons exacts (même outil, même règle).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .sarif import SEVERITIES, Finding


@dataclass
class TriagedFinding:
    """Un finding dédupliqué, enrichi ensuite par le score et le triage LLM."""

    id: str
    category: str
    severity: str
    cvss: float | None
    tools: list[str]
    rules: list[str]
    cwe: list[str]
    file: str
    line: int
    message: str
    package: dict | None
    occurrences: int = 1
    # Remplis par scoring.py et llm.py
    exposure: float = 0.0
    confidence: float = 1.0
    false_positive_probability: float | None = None
    exploitability: float | None = None
    risk_score: float = 0.0
    risk_level: str = "low"
    rationale: str = ""
    recommendation: str = ""
    llm_triaged: bool = False


def dedupe_key(finding: Finding) -> tuple:
    if finding.category == "secret":
        return ("secret", finding.file, finding.line)
    if finding.category == "dependency":
        package = (finding.package or {}).get("name", "")
        return ("dependency", finding.rule.upper(), package, finding.file)
    if finding.cwe:
        return (finding.category, finding.file, finding.line, finding.cwe[0])
    return (finding.category, finding.file, finding.line, finding.tool.lower(), finding.rule)


def deduplicate(findings: list[Finding]) -> list[TriagedFinding]:
    groups: dict[tuple, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(dedupe_key(finding), []).append(finding)
    return [_merge(key, group) for key, group in groups.items()]


def _merge(key: tuple, group: list[Finding]) -> TriagedFinding:
    # On garde le finding le plus grave comme référence (sévérité, message).
    worst = max(group, key=lambda f: (SEVERITIES.index(f.severity), f.cvss or 0.0))
    scores = [f.cvss for f in group if f.cvss is not None]
    return TriagedFinding(
        # Identifiant stable d'une exécution à l'autre : sert au nom de branche autofix/<id>.
        id=hashlib.sha256("|".join(map(str, key)).encode()).hexdigest()[:12],
        category=worst.category,
        severity=worst.severity,
        cvss=max(scores) if scores else None,
        tools=sorted({f.tool for f in group}),
        rules=sorted({f.rule for f in group}),
        cwe=sorted({cwe for f in group for cwe in f.cwe}, key=lambda c: int(c[4:])),
        file=worst.file,
        line=worst.line,
        message=worst.message,
        package=next((f.package for f in group if f.package), None),
        occurrences=len(group),
    )

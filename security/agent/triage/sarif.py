"""Lecture des rapports SARIF 2.1.0 et normalisation des findings.

Chaque scanner (CodeQL, Semgrep, Trivy, Gitleaks, Checkov...) range ses informations à des
endroits un peu différents. Ce module les ramène au même format :
outil, règle, sévérité, CWE, fichier, ligne, message.

Un rapport SARIF est une donnée NON FIABLE : il contient des extraits du code de la PR.
On ne fait donc que lire des champs, on n'exécute et on n'ouvre rien à partir de son contenu.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from .redact import redact

# Du moins grave au plus grave : l'index sert à comparer deux sévérités.
SEVERITIES = ("info", "low", "medium", "high", "critical")

MAX_SARIF_BYTES = 50 * 1024 * 1024
MAX_MESSAGE_CHARS = 1000

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_CONFIG_TOOLS = {"checkov", "hadolint", "kics", "tfsec"}
# CWE « secret en dur » : ces findings sont traités comme des secrets (jamais envoyés au LLM).
_SECRET_CWES = {"CWE-259", "CWE-321", "CWE-798"}
_TRIVY_KEYS = {"package", "installed version", "fixed version", "message"}
_CWE_RE = re.compile(r"cwe[-_ /]?0*(\d+)", re.IGNORECASE)
_ADVISORY_RE = re.compile(r"^(CVE|GHSA)-", re.IGNORECASE)
_CODEQL_LINK_RE = re.compile(r"\[([^\]]+)\]\(\d+\)")  # « [texte](1) » : renvoi interne de CodeQL


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str  # info | low | medium | high | critical
    cvss: float | None  # champ SARIF « security-severity » (0 à 10), s'il existe
    cwe: list[str]
    file: str
    line: int
    message: str
    category: str  # secret | dependency | config | code
    package: dict | None = None  # dépendances : nom, version installée, version corrigée


def load_reports(input_dir: Path, workspace: str = "") -> tuple[list[Finding], list[str]]:
    """Lit tous les *.sarif du dossier (sous-dossiers inclus).

    Un rapport illisible ne fait pas planter l'agent : il est signalé dans les avertissements.
    """
    findings: list[Finding] = []
    warnings: list[str] = []
    for path in sorted(input_dir.rglob("*.sarif")):
        try:
            if path.stat().st_size > MAX_SARIF_BYTES:
                raise ValueError("fichier trop volumineux")
            findings.extend(parse_sarif(json.loads(path.read_text(encoding="utf-8")), workspace))
        except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError) as exc:
            warnings.append(f"{path.name} ignoré : {type(exc).__name__}: {exc}")
    return findings, warnings


def parse_sarif(sarif: dict, workspace: str = "") -> list[Finding]:
    findings = []
    for run in sarif.get("runs") or []:
        tool = str(run.get("tool", {}).get("driver", {}).get("name") or "inconnu")
        rules = _rules_by_id(run)
        driver_rules = run.get("tool", {}).get("driver", {}).get("rules") or []
        for result in run.get("results") or []:
            if result.get("suppressions") or result.get("kind") in ("pass", "notApplicable"):
                continue
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id")
            index = result.get("ruleIndex")
            if not rule_id and isinstance(index, int) and 0 <= index < len(driver_rules):
                rule_id = driver_rules[index].get("id")
            rule_id = str(rule_id or "regle-inconnue")
            findings.append(_normalize(tool, rule_id, rules.get(rule_id, {}), result, workspace))
    return findings


def _rules_by_id(run: dict) -> dict[str, dict]:
    """Index des règles. CodeQL range les siennes dans tool.extensions, les autres dans driver."""
    tool = run.get("tool", {})
    index: dict[str, dict] = {}
    for component in [tool.get("driver") or {}, *(tool.get("extensions") or [])]:
        for rule in component.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                index.setdefault(str(rule["id"]), rule)
    return index


def _normalize(tool: str, rule_id: str, rule: dict, result: dict, workspace: str) -> Finding:
    rule_props = rule.get("properties") or {}
    result_props = result.get("properties") or {}
    tags = [str(t) for t in [*(rule_props.get("tags") or []), *(result_props.get("tags") or [])]]

    cwe = _cwes(tags, rule)
    category = _category(tool, rule_id, tags, cwe)
    cvss = _to_float(result_props.get("security-severity") or rule_props.get("security-severity"))
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    file, line = _location(result, workspace)
    message = str((result.get("message") or {}).get("text") or "").strip()
    message = _CODEQL_LINK_RE.sub(r"\1", message)

    # Trivy écrit ses messages en lignes « Clé: valeur » : on en tire une phrase lisible.
    fields = _trivy_fields(tool, message)
    package = _package(rule_id, fields) if category == "dependency" else None
    if package:
        summary = str((rule.get("shortDescription") or {}).get("text") or "paquet vulnérable")
        message = f"{package['name']} {package['installed_version']} : {summary}"
    elif fields.get("message"):
        message = fields["message"]
    # Le message finit dans un commentaire public : on y masque aussi tout ce qui ressemble
    # à un secret (un scanner recopie parfois un bout de code dans son message).
    message = redact(message)
    if category == "secret":
        # Le message d'un scanner de secrets peut contenir un morceau du secret : on ne le
        # garde pas. Seuls la règle, le fichier et la ligne sortent de l'agent.
        message = f"Secret détecté (règle {rule_id})."

    return Finding(
        tool=tool,
        rule=rule_id,
        severity=_severity(category, tags, cvss, level),
        cvss=cvss,
        cwe=cwe,
        file=file,
        line=line,
        message=message[:MAX_MESSAGE_CHARS],
        category=category,
        package=package,
    )


def _category(tool: str, rule_id: str, tags: list[str], cwe: list[str]) -> str:
    tool = tool.lower()
    tags_lower = {t.lower() for t in tags}
    if tool == "gitleaks" or "secret" in tags_lower or _SECRET_CWES.intersection(cwe):
        return "secret"
    if "vulnerability" in tags_lower or _ADVISORY_RE.match(rule_id):
        return "dependency"
    if "misconfiguration" in tags_lower or tool in _CONFIG_TOOLS:
        return "config"
    return "code"


def _severity(category: str, tags: list[str], cvss: float | None, level: str | None) -> str:
    if category == "secret":
        return "critical"  # règle du projet : tout secret bloque la pipeline
    for tag in tags:  # Trivy écrit son niveau dans les tags : « HIGH », « CRITICAL »...
        if tag in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return tag.lower()
    if cvss is not None:  # mêmes seuils que l'onglet Security de GitHub
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low" if cvss > 0 else "info"
    return _LEVEL_TO_SEVERITY.get(str(level), "medium")  # défaut SARIF : « warning »


def _cwes(tags: list[str], rule: dict) -> list[str]:
    texts = list(tags)
    for relation in rule.get("relationships") or []:
        target = relation.get("target") or {}
        if "cwe" in str((target.get("toolComponent") or {}).get("name", "")).lower():
            texts.append(f"cwe-{target.get('id')}")
    found: list[str] = []
    for text in texts:
        for number in _CWE_RE.findall(text):
            cwe = f"CWE-{int(number)}"
            if cwe not in found:
                found.append(cwe)
    return found


def _location(result: dict, workspace: str) -> tuple[str, int]:
    locations = result.get("locations") or [{}]
    physical = locations[0].get("physicalLocation") or {}
    uri = unquote(str((physical.get("artifactLocation") or {}).get("uri") or ""))
    line = (physical.get("region") or {}).get("startLine")
    return _relative_path(uri, workspace), line if isinstance(line, int) and line > 0 else 0


def _relative_path(uri: str, workspace: str) -> str:
    if "://" in uri and not uri.startswith("file://"):
        return uri  # DAST (ZAP) : la « localisation » est une URL
    path = uri.removeprefix("file://").replace("\\", "/")
    for root in (workspace, "/github/workspace", "/repo"):
        if root and path.startswith(root.rstrip("/") + "/"):
            path = path[len(root.rstrip("/")) + 1 :]
            break
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def _trivy_fields(tool: str, message: str) -> dict[str, str]:
    if tool.lower() != "trivy":
        return {}
    fields = {}
    for row in message.splitlines():
        key, separator, value = row.partition(":")
        if separator and key.strip().lower() in _TRIVY_KEYS:
            fields[key.strip().lower()] = value.strip()
    return fields


def _package(rule_id: str, fields: dict[str, str]) -> dict | None:
    """Paquet vulnérable signalé par Trivy : c'est ce que la remédiation doit mettre à jour."""
    if "package" not in fields:
        return None
    return {
        "name": fields["package"],
        "installed_version": fields.get("installed version", ""),
        "fixed_version": fields.get("fixed version", ""),
        "advisory": rule_id,
    }


def _to_float(value) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:  # NaN
        return None
    return min(max(number, 0.0), 10.0)

"""Lecture de reports/triage.json (produit par l'agent IA) et choix des findings à corriger.

v1 : seuls les paquets vulnérables (catégorie « dependency ») NuGet et npm sont corrigés.
Tout le reste est listé comme « non corrigé automatiquement », avec la raison.

Plusieurs CVE sur le même paquet donnent UN seul correctif : sinon on ouvrirait deux PR qui
modifient la même ligne.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from . import guardrails
from .versions import is_major_bump, parse, pick_fixed_version

MAX_TRIAGE_BYTES = 20 * 1024 * 1024
SUPPORTED_SCHEMA_MAJOR = "1."

_NUGET_FILES = ("packages.lock.json", "directory.packages.props", "packages.props")
_NPM_FILES = ("package-lock.json",)


class TriageError(Exception):
    """triage.json est absent ou inutilisable."""


@dataclass
class Candidate:
    """Un correctif à tenter : monter un paquet vers une version corrigée."""

    id: str  # identifiant du finding le plus risqué du groupe → branche autofix/<id>
    ecosystem: str  # nuget | npm
    manifest: str  # fichier signalé par le scanner (lockfile ou .props)
    package: str
    installed_version: str
    target_version: str
    risk_score: float
    advisories: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)

    @property
    def major_bump(self) -> bool:
        return is_major_bump(self.installed_version, self.target_version)


@dataclass
class Skipped:
    """Un finding que la remédiation ne corrige pas, et pourquoi."""

    id: str
    title: str
    reason: str
    recommendation: str = ""


def load_triage(path: Path) -> dict:
    try:
        if path.stat().st_size > MAX_TRIAGE_BYTES:
            raise TriageError("triage.json trop volumineux")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TriageError(f"triage.json illisible ({type(exc).__name__})") from None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise TriageError("triage.json : liste « findings » absente")
    if not str(data.get("schema_version", "")).startswith(SUPPORTED_SCHEMA_MAJOR):
        raise TriageError("triage.json : version de schéma non gérée")
    return data


def ecosystem_of(file: str) -> str | None:
    name = PurePosixPath(file).name.lower()
    if name in _NUGET_FILES:
        return "nuget"
    if name in _NPM_FILES:
        return "npm"
    return None


def select(triage: dict) -> tuple[list[Candidate], list[Skipped]]:
    """Retourne (correctifs à tenter, triés du plus risqué au moins risqué ; findings écartés)."""
    groups: dict[tuple, Candidate] = {}
    skipped: list[Skipped] = []

    findings = [f for f in triage["findings"] if isinstance(f, dict)]
    findings.sort(key=lambda f: _number(f.get("risk_score")), reverse=True)
    for finding in findings:
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not guardrails.FINDING_ID_RE.match(finding_id):
            skipped.append(Skipped("?", "finding sans identifiant valide", "entrée invalide"))
            continue
        try:
            candidate = _candidate(finding)
        except _NotFixable as exc:
            skipped.append(Skipped(finding_id, _title(finding), str(exc), _text(finding.get("recommendation"))))
            continue
        key = (candidate.manifest, candidate.package.lower())
        if key not in groups:
            groups[key] = candidate
            continue
        # Même paquet, autre CVE : on garde la version cible la plus haute.
        group = groups[key]
        group.finding_ids.append(candidate.id)
        group.advisories += [a for a in candidate.advisories if a not in group.advisories]
        if parse(candidate.target_version) > parse(group.target_version):
            group.target_version = candidate.target_version
    return list(groups.values()), skipped


class _NotFixable(Exception):
    pass


def _candidate(finding: dict) -> Candidate:
    category = finding.get("category")
    if category != "dependency":
        raise _NotFixable(_OUT_OF_SCOPE.get(category, "type de finding non géré"))
    package = finding.get("package")
    if not isinstance(package, dict):
        raise _NotFixable("le scanner n'a pas indiqué le paquet à mettre à jour")

    try:
        manifest = guardrails.safe_relative_path(finding.get("file"))
    except guardrails.GuardrailError:
        raise _NotFixable("chemin de fichier refusé") from None
    if guardrails.is_forbidden(manifest):
        raise _NotFixable("fichier dans un dossier que la remédiation n'a pas le droit de modifier")
    ecosystem = ecosystem_of(manifest)
    if ecosystem is None:
        raise _NotFixable("type de fichier de dépendances non géré en v1 (NuGet et npm seulement)")

    name = package.get("name")
    if not guardrails.valid_package_name(ecosystem, name):
        raise _NotFixable("nom de paquet refusé")
    installed = _text(package.get("installed_version"))
    if parse(installed) is None:
        raise _NotFixable("version installée illisible")
    fixed = _text(package.get("fixed_version"))
    if not fixed:
        raise _NotFixable("aucune version corrigée n'existe encore pour ce paquet")
    target = pick_fixed_version(installed, fixed)
    if target is None:
        raise _NotFixable("version corrigée illisible ou plus ancienne que la version installée")

    advisory = _text(package.get("advisory"))
    return Candidate(
        id=finding["id"],
        ecosystem=ecosystem,
        manifest=manifest,
        package=name,
        installed_version=installed,
        target_version=target,
        risk_score=_number(finding.get("risk_score")),
        advisories=[advisory] if guardrails.ADVISORY_RE.match(advisory) else [],
        finding_ids=[finding["id"]],
    )


_OUT_OF_SCOPE = {
    "secret": "un secret ne se corrige pas par une PR : il faut le révoquer",
    "code": "correctif de code : prévu en v2 (patch proposé par LLM)",
    "config": "correctif de configuration : prévu en v2",
}


def _title(finding: dict) -> str:
    rules = finding.get("rules")
    rule = rules[0] if isinstance(rules, list) and rules else "finding"
    return f"{_text(rule)} dans {_text(finding.get('file'))}"


def _text(value) -> str:
    return value.strip()[:400] if isinstance(value, str) else ""


def _number(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return 0.0
    return float(value)

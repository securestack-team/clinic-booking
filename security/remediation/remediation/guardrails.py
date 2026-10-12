"""Garde-fous : ce que la remédiation n'a pas le droit de faire, quoi que dise son entrée.

reports/triage.json vient de rapports de scan, donc du code de la PR : c'est une donnée NON
FIABLE. Chaque valeur utilisée (identifiant, chemin, nom de paquet, version) est vérifiée ici
avant de servir à nommer une branche, modifier un fichier ou lancer une commande.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

# Demande du projet : ne jamais modifier la pipeline ni l'infrastructure.
FORBIDDEN_PREFIXES = (".github/", "infra/", ".git/")

# v1 : une PR de correctif ne peut toucher qu'à des fichiers de dépendances.
ALLOWED_FILE_NAMES = {"packages.lock.json", "package.json", "package-lock.json"}
ALLOWED_SUFFIXES = (".csproj", ".props")

DEFAULT_MAX_PRS = 3
HARD_MAX_PRS = 10
MAX_FILES_PER_FIX = 8

FINDING_ID_RE = re.compile(r"^[0-9a-f]{12}$")
ADVISORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,39}$")
BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,100}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._@ /-]{1,300}$")
_NUGET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_NPM_NAME_RE = re.compile(r"^(@[a-z0-9][a-z0-9._~-]{0,99}/)?[a-z0-9][a-z0-9._~-]{0,99}$")


class GuardrailError(Exception):
    """Une règle de sécurité interdit cette action."""


def safe_relative_path(path: str) -> str:
    """Chemin relatif au repo, normalisé. Refuse ../, les chemins absolus et les caractères exotiques."""
    if not isinstance(path, str) or not _PATH_RE.match(path) or path.startswith("/"):
        raise GuardrailError("chemin refusé")
    parts = PurePosixPath(path).parts
    if not parts or ".." in parts:
        raise GuardrailError("chemin refusé")
    return "/".join(parts)


def is_forbidden(path: str) -> bool:
    return (path.lower() + "/").startswith(FORBIDDEN_PREFIXES)


def is_allowed_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in ALLOWED_FILE_NAMES or name.endswith(ALLOWED_SUFFIXES)


def check_changed_files(paths: list[str]) -> None:
    """Vérifie les fichiers RÉELLEMENT modifiés, après l'exécution du correctif."""
    if not paths:
        raise GuardrailError("le correctif n'a modifié aucun fichier")
    if len(paths) > MAX_FILES_PER_FIX:
        raise GuardrailError(f"trop de fichiers modifiés ({len(paths)})")
    for path in paths:
        clean = safe_relative_path(path)
        if is_forbidden(clean):
            raise GuardrailError(f"modification interdite dans {clean}")
        if not is_allowed_file(clean):
            raise GuardrailError(f"fichier non autorisé pour un correctif de dépendance : {clean}")


def valid_package_name(ecosystem: str, name: str) -> bool:
    pattern = _NPM_NAME_RE if ecosystem == "npm" else _NUGET_NAME_RE
    return isinstance(name, str) and bool(pattern.match(name))


def clamp_max_prs(value: int) -> int:
    return max(0, min(value, HARD_MAX_PRS))

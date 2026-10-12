"""Correctifs v1 : monter un paquet vulnérable vers sa version corrigée.

Trois temps, pour ne jamais proposer un patch non validé :
1. plan()   : décide quoi modifier, sans rien écrire. Lève CannotFix si le cas n'est pas sûr.
2. apply()  : écrit les fichiers et régénère le lockfile avec l'outil officiel (dotnet, npm).
3. verify() : relit le fichier signalé par le scanner et vérifie que la version vulnérable
              n'y est plus.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable

from .triage_input import Candidate
from .versions import at_least, parse

MAX_MANIFEST_BYTES = 5 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 300

_TAG_RE = re.compile(r"<(?:PackageReference|PackageVersion)\b[^>]*>", re.IGNORECASE)
_NAME_ATTR_RE = re.compile(r'\b(?:Include|Update)\s*=\s*"([^"]*)"', re.IGNORECASE)
_VERSION_ATTR_RE = re.compile(r'(\bVersion\s*=\s*")([^"]*)(")', re.IGNORECASE)
_SENSITIVE_ENV_RE = re.compile(r"TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|_KEY$", re.IGNORECASE)
_NPM_DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


class CannotFix(Exception):
    """Pas de correctif sûr : la remédiation commente au lieu d'ouvrir une PR."""


@dataclass
class Plan:
    edits: dict[str, str] = field(default_factory=dict)  # chemin relatif → nouveau contenu
    command: list[str] | None = None  # régénération du lockfile
    command_dir: str = "."


# --- 1. Planifier -------------------------------------------------------------------------


def plan(root: Path, candidate: Candidate) -> Plan:
    if candidate.ecosystem == "nuget":
        return _plan_nuget(root, candidate)
    if candidate.ecosystem == "npm":
        return _plan_npm(root, candidate)
    raise CannotFix("écosystème non géré")


def _plan_nuget(root: Path, candidate: Candidate) -> Plan:
    manifest = PurePosixPath(candidate.manifest)
    directory = manifest.parent

    if manifest.name.lower().endswith("packages.props"):
        # Gestion centralisée des versions : la version est dans le fichier signalé.
        text, changed, _, _ = bump_msbuild(_read(root, str(manifest)), candidate.package, candidate.target_version)
        if not changed:
            raise CannotFix("paquet introuvable dans le fichier .props, ou déjà à jour")
        has_lockfile = any(_project_files(root, directory, "packages.lock.json", recursive=True))
        command = ["dotnet", "restore", "--force-evaluate"] if has_lockfile else None
        return Plan({str(manifest): text}, command, str(directory))

    # Fichier signalé = packages.lock.json : la version à changer est dans le .csproj voisin.
    edits: dict[str, str] = {}
    declared = False  # le paquet est-il référencé directement quelque part ?
    declared_without_version = False
    for project in _project_files(root, directory, "*.csproj"):
        text, changed, found, without_version = bump_msbuild(_read(root, project), candidate.package, candidate.target_version)
        declared = declared or found
        declared_without_version = declared_without_version or without_version
        if changed:
            edits[project] = text
    if declared_without_version:
        props = _find_upwards(root, directory, "Directory.Packages.props")
        if props:
            text, changed, found, _ = bump_msbuild(_read(root, props), candidate.package, candidate.target_version)
            declared = declared or found
            if changed:
                edits[props] = text
    if not declared:
        raise CannotFix(
            "dépendance transitive : le paquet n'est pas référencé directement dans le projet. "
            "Mettre à jour le paquet parent ou ajouter une référence directe."
        )
    return Plan(edits, ["dotnet", "restore", "--force-evaluate"], str(directory))


def _plan_npm(root: Path, candidate: Candidate) -> Plan:
    directory = PurePosixPath(candidate.manifest).parent
    try:
        package_json = json.loads(_read(root, str(directory / "package.json")))
    except ValueError:
        raise CannotFix("package.json illisible") from None
    sections = [package_json.get(name) for name in _NPM_DEPENDENCY_SECTIONS] if isinstance(package_json, dict) else []
    declared = [section[candidate.package] for section in sections if isinstance(section, dict) and candidate.package in section]
    if not declared:
        raise CannotFix(
            "dépendance transitive : le paquet n'est pas dans package.json. "
            "Mettre à jour le paquet parent ou utiliser « overrides »."
        )
    # --package-lock-only : ne télécharge ni n'installe rien dans node_modules.
    # --ignore-scripts    : aucun script d'installation d'un paquet ne s'exécute dans la pipeline.
    command = [
        "npm", "install", f"{candidate.package}@{candidate.target_version}",
        "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
    ]  # fmt: skip
    if parse(str(declared[0])) is not None:
        command.append("--save-exact")  # le projet épingle une version exacte : on garde ce style
    return Plan({}, command, str(directory))


def bump_msbuild(text: str, package: str, target: str) -> tuple[str, bool, bool, bool]:
    """Change Version="..." pour ce paquet dans un .csproj ou un .props, sans toucher au reste.

    Retourne (texte, modifié ?, paquet trouvé avec une version ?, paquet déclaré sans version ?).
    """
    changed = False
    found = False
    without_version = False

    def replace(match: re.Match) -> str:
        nonlocal changed, found, without_version
        tag = match.group(0)
        name = _NAME_ATTR_RE.search(tag)
        if not name or name.group(1).lower() != package.lower():  # les noms NuGet ignorent la casse
            return tag
        version = _VERSION_ATTR_RE.search(tag)
        if not version:
            without_version = True
            return tag
        if parse(version.group(2)) is None:
            raise CannotFix("la version du paquet est une plage ou une variable MSBuild")
        found = True
        if at_least(version.group(2), target):
            return tag  # déjà à jour ici : seul le lockfile est en retard
        changed = True
        return _VERSION_ATTR_RE.sub(rf"\g<1>{target}\g<3>", tag, count=1)

    return _TAG_RE.sub(replace, text), changed, found, without_version


# --- 2. Appliquer -------------------------------------------------------------------------


def run_tool(command: list[str], cwd: Path) -> tuple[int, str]:
    """Lance dotnet ou npm, sans shell et sans les secrets de l'environnement.

    Un fichier de projet venu d'une PR peut faire exécuter du code pendant une restauration :
    l'outil ne doit donc pas voir le token GitHub.
    """
    env = {key: value for key, value in os.environ.items() if not _SENSITIVE_ENV_RE.search(key)}
    try:
        done = subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, text=True, timeout=TOOL_TIMEOUT_SECONDS, check=False
        )
    except FileNotFoundError:
        raise CannotFix(f"l'outil « {command[0]} » n'est pas installé sur la machine") from None
    except subprocess.TimeoutExpired:
        raise CannotFix(f"« {command[0]} » n'a pas répondu à temps") from None
    return done.returncode, (done.stdout + done.stderr)[-2000:]


def apply(root: Path, fix: Plan, run: Callable = run_tool) -> None:
    for path, content in fix.edits.items():
        _resolve(root, path).write_text(content, encoding="utf-8")
    if fix.command:
        code, _ = run(fix.command, _resolve(root, fix.command_dir))
        if code != 0:
            raise CannotFix(f"« {' '.join(fix.command[:2])} » a échoué (code {code})")


# --- 3. Vérifier --------------------------------------------------------------------------


def verify(root: Path, candidate: Candidate) -> None:
    """Le fichier signalé par le scanner ne doit plus contenir de version vulnérable."""
    name = PurePosixPath(candidate.manifest).name.lower()
    text = _read(root, candidate.manifest)
    try:
        if name == "packages.lock.json":
            versions = _nuget_lock_versions(json.loads(text), candidate.package)
        elif name == "package-lock.json":
            versions = _npm_lock_versions(json.loads(text), candidate.package)
        else:
            versions = _msbuild_versions(text, candidate.package)
    except (ValueError, AttributeError, TypeError):
        raise CannotFix("fichier de dépendances illisible après le correctif") from None
    if not versions:
        raise CannotFix("paquet introuvable dans le fichier de dépendances après le correctif")
    if not all(at_least(version, candidate.target_version) for version in versions):
        raise CannotFix("la version vulnérable est toujours présente après le correctif")


def _nuget_lock_versions(lock: dict, package: str) -> list[str]:
    return [
        str(entry.get("resolved", ""))
        for framework in (lock.get("dependencies") or {}).values()
        for name, entry in framework.items()
        if name.lower() == package.lower()
    ]


def _npm_lock_versions(lock: dict, package: str) -> list[str]:
    packages = lock.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 et 3
        suffix = "node_modules/" + package
        return [str(entry.get("version", "")) for path, entry in packages.items() if path == suffix or path.endswith("/" + suffix)]
    entry = (lock.get("dependencies") or {}).get(package)  # lockfileVersion 1
    return [str(entry.get("version", ""))] if entry else []


def _msbuild_versions(text: str, package: str) -> list[str]:
    versions = []
    for tag in _TAG_RE.findall(text):
        name = _NAME_ATTR_RE.search(tag)
        version = _VERSION_ATTR_RE.search(tag)
        if name and version and name.group(1).lower() == package.lower():
            versions.append(version.group(2))
    return versions


# --- Fichiers -----------------------------------------------------------------------------


def _resolve(root: Path, relative: str) -> Path:
    """Chemin réel dans le repo. Refuse tout ce qui en sort, lien symbolique compris."""
    base = root.resolve()
    target = (base / relative).resolve()
    if not target.is_relative_to(base):
        raise CannotFix("chemin hors du repo")
    return target


def _read(root: Path, relative: str) -> str:
    target = _resolve(root, relative)
    try:
        if target.stat().st_size > MAX_MANIFEST_BYTES:
            raise CannotFix("fichier de dépendances trop volumineux")
        return target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise CannotFix(f"fichier introuvable ou illisible : {relative}") from None


def _project_files(root: Path, directory: PurePosixPath, pattern: str, recursive: bool = False) -> list[str]:
    base = _resolve(root, str(directory))
    if not base.is_dir():
        return []
    found = base.rglob(pattern) if recursive else base.glob(pattern)
    ignored = {"bin", "obj", "node_modules", ".git"}
    return sorted(
        path.relative_to(root.resolve()).as_posix()
        for path in found
        if path.is_file() and not ignored.intersection(path.relative_to(base).parts)
    )


def _find_upwards(root: Path, directory: PurePosixPath, name: str) -> str | None:
    current = directory
    while True:
        candidate = current / name
        if _resolve(root, str(candidate)).is_file():
            return str(candidate)
        if current in (PurePosixPath("."), PurePosixPath("")) or current == current.parent:
            return None
        current = current.parent

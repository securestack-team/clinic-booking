"""Exécute les outils de la PR dans Docker, sans accès aux identifiants du runner.

Le bot et son client Git restent sur l'hôte approuvé. Seule une copie des sources,
sans métadonnées Git, est montée dans le conteneur. Seuls les changements de
dépendances autorisés reviennent ; les sorties de compilation restent jetables.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path

from . import guardrails
from .fixers import CannotFix, MAX_MANIFEST_BYTES, TOOL_TIMEOUT_SECONDS

IMAGES = {"dotnet": "mcr.microsoft.com/dotnet/sdk:10.0", "npm": "node:22-bookworm-slim"}
IGNORED = {".git", "bin", "obj", "node_modules", ".terraform", "__pycache__"}


def inventory(root: Path) -> dict[str, str]:
    """Inventorie les fichiers ordinaires ; ne suit jamais un lien du conteneur."""
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in IGNORED]
        for name in [*dirs, *files]:
            if name in IGNORED:
                continue
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise CannotFix("le bac à sable refuse les liens et fichiers spéciaux")
            relative = path.relative_to(root).as_posix()
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(65536), b""):
                    digest.update(block)
            result[relative] = digest.hexdigest()
    return result


def copy_back(source: Path, target: Path, before: dict[str, str]) -> None:
    """Valide TOUT le résultat avant la première écriture sur le dépôt de l'hôte."""
    after = inventory(source)
    if before.keys() - after.keys():
        raise CannotFix("l'outil a supprimé un fichier source")
    changed = sorted(path for path in after if before.get(path) != after[path])
    if not changed:
        return
    guardrails.check_changed_files(changed)
    edits = []
    for relative in changed:
        path = source / relative
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise CannotFix("sortie du bac à sable trop volumineuse")
        destination = target / relative
        if not destination.resolve().is_relative_to(target.resolve()):
            raise CannotFix("destination hors du dépôt")
        edits.append((destination, path.read_bytes()))
    for path, content in edits:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def docker_command(program: str, args: list[str], source: Path, relative_cwd: str, name: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--name", name,
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=256", "--memory=2g", "--cpus=2",
        "--network=bridge", "--tmpfs", "/tmp:rw,nosuid,nodev,size=1g",
        "--mount", f"type=bind,source={source},target=/workspace",
        "--workdir", "/workspace/" + relative_cwd,
        "--env", "HOME=/tmp", "--env", "DOTNET_CLI_HOME=/tmp/dotnet",
        "--env", "NUGET_PACKAGES=/tmp/nuget", "--env", "npm_config_cache=/tmp/npm",
        "--env", "DOTNET_CLI_TELEMETRY_OPTOUT=1", "--env", "DOTNET_NOLOGO=1",
        "--entrypoint", program, IMAGES[program], *args,
    ]


def run_tool(command: list[str], cwd: Path) -> tuple[int, str]:
    if not command or command[0] not in IMAGES:
        raise CannotFix("outil non autorisé dans le bac à sable")
    try:
        # Cette commande Git interne ne lance ni hook ni code MSBuild de la PR.
        root = Path(subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], cwd=cwd, text=True, stderr=subprocess.DEVNULL,
            timeout=30,
        ).strip()).resolve()
        relative_cwd = cwd.resolve().relative_to(root).as_posix()
    except (OSError, ValueError, subprocess.SubprocessError):
        raise CannotFix("racine Git introuvable pour le bac à sable") from None

    name = "autofix-tool-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="autofix-sandbox-") as tmp:
        source = Path(tmp) / "source"
        # Validation avant copytree pour refuser aussi les liens du dépôt d'entrée.
        inventory(root)
        shutil.copytree(root, source, ignore=shutil.ignore_patterns(*IGNORED), symlinks=True)
        before = inventory(source)
        argv = docker_command(command[0], command[1:], source, relative_cwd, name)
        # Aucun héritage de token, config Docker/Git ou autre secret de l'environnement.
        docker_env = {"PATH": os.defpath, "HOME": tmp, "DOCKER_CONFIG": tmp}
        try:
            done = subprocess.run(
                argv, env=docker_env, capture_output=True, text=True,
                timeout=TOOL_TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise CannotFix("outil isolé indisponible ou délai dépassé ; aucun repli sur l'hôte") from None
        finally:
            # Une interruption du client Docker ne doit pas laisser le conteneur actif.
            try:
                subprocess.run(
                    ["docker", "rm", "--force", name], env=docker_env,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if done.returncode == 0:
            copy_back(source, root, before)
        return done.returncode, (done.stdout + done.stderr)[-2000:]

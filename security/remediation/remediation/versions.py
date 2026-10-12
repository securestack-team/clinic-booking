"""Comparaison de versions et choix de la version corrigée.

Trivy donne parfois plusieurs versions corrigées (« 2.3.1, 3.0.1 »), une par branche du paquet.
On prend la plus petite version supérieure à celle installée, de préférence dans la même
version majeure : c'est la mise à jour qui risque le moins de casser le code.
"""

from __future__ import annotations

import re

# 1.2.3, 1.2.3.4 (NuGet), 1.2.3-beta.1 : rien d'autre n'est accepté.
VERSION_RE = re.compile(r"^(\d{1,9})((?:\.\d{1,9}){0,3})(-[0-9A-Za-z.-]{1,40})?$")


def parse(version: str) -> tuple | None:
    """Clé de tri d'une version, ou None si le texte n'est pas une version simple."""
    match = VERSION_RE.match(version.strip())
    if not match:
        return None
    numbers = [int(match.group(1)), *(int(part) for part in match.group(2).split(".") if part)]
    numbers += [0] * (4 - len(numbers))
    prerelease = match.group(3) or ""
    # Une préversion (1.2.3-beta) est plus petite que la version finale (1.2.3).
    return (*numbers, 0 if prerelease else 1, prerelease)


def pick_fixed_version(installed: str, fixed: str) -> str | None:
    """Version cible à partir du champ « fixed_version » du triage, ou None si aucune ne convient."""
    current = parse(installed)
    if current is None:
        return None
    candidates = []
    for text in fixed.split(","):
        key = parse(text)
        if key is not None and key > current and not key[5]:  # jamais vers une préversion
            candidates.append((key, text.strip()))
    if not candidates:
        return None
    same_major = [item for item in candidates if item[0][0] == current[0]]
    return min(same_major or candidates)[1]


def is_major_bump(installed: str, target: str) -> bool:
    current, new = parse(installed), parse(target)
    return bool(current and new and new[0] != current[0])


def at_least(version: str, minimum: str) -> bool:
    current, wanted = parse(version), parse(minimum)
    return bool(current and wanted and current >= wanted)

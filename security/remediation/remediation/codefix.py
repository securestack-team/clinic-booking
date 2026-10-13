"""Correctifs v2 : un patch de code proposé par un LLM, pour trois cas simples.

    - injection SQL (requête concaténée)      → requête paramétrée
    - autorisation manquante sur un endpoint  → [Authorize]
    - secret en dur dans le code              → lecture de la configuration

Le LLM propose, la remédiation contrôle. Un patch ne devient une Pull Request que s'il passe
TOUS les contrôles ; sinon la remédiation commente au lieu de proposer un patch non validé :

    1. forme        : un seul remplacement, petit, qui couvre la ligne signalée ;
    2. contenu      : pas de [MASQUÉ] recopié, pas de nouveau secret, contrôle propre au cas ;
    3. périmètre    : un seul fichier modifié, celui du finding, dans api/ ;
    4. compilation  : « dotnet build » doit réussir sur le projet.

Ces contrôles réduisent le risque, ils ne prouvent pas que le patch est bon : la pipeline
complète et une relecture humaine restent obligatoires.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

from . import guardrails
from .fixers import CannotFix, _read, _resolve, run_tool
from .llm import LLMConfig, Patch, ask_patch
from .redact import MASK, redact
from .triage_input import Skipped

CODE_PREFIX = "api/"
CODE_SUFFIX = ".cs"
CONTEXT_LINES = 12  # lignes envoyées avant et après la ligne signalée
MAX_REPLACED_LINES = 12
MAX_REPLACEMENT_LINES = 30
MAX_REPLACEMENT_CHARS = 3000
MAX_LINE_CHARS = 300

# CWE → type de correctif. Seuls ces cas sont tentés.
KIND_BY_CWE = {
    "CWE-89": "sql",
    "CWE-285": "authz",
    "CWE-306": "authz",
    "CWE-862": "authz",
    "CWE-259": "secret",
    "CWE-321": "secret",
    "CWE-798": "secret",
}
INSTRUCTION = {
    "sql": "Remplace la requête SQL construite par concaténation par une requête paramétrée "
    "(par exemple FromSqlInterpolated, ou FromSqlRaw avec des paramètres {0}).",
    "authz": "Ajoute l'attribut [Authorize] sur l'endpoint signalé, sans modifier son code.",
    "secret": "Remplace la valeur écrite en dur par une lecture de la configuration (IConfiguration) "
    "ou d'une variable d'environnement. N'invente aucune valeur.",
}
TITLE = {
    "sql": "use a parameterized query",
    "authz": "add missing authorization",
    "secret": "read hard-coded secret from configuration",
}

_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_AUTHORIZE_RE = re.compile(r"\[(?:[\w.]+\.)?Authorize\b")  # [Authorize] ou son nom complet
_ALLOW_ANONYMOUS_RE = re.compile(r"\[(?:[\w.]+\.)?AllowAnonymous\b")
_USING_RE = re.compile(r"^\s*(?:global\s+)?using\s+[\w.]+\s*;\s*$")
_COMPILER_ERROR_RE = re.compile(r"\berror (CS\d{4})\b")
_RAW_SQL_CONCAT_RE = re.compile(
    r'(?:FromSqlRaw|ExecuteSqlRaw(?:Async)?|SqlQueryRaw)\s*\([^;]*?(?:"\s*\+|\+\s*"|\$")', re.DOTALL
)


@dataclass
class CodeCandidate:
    id: str
    kind: str  # sql | authz | secret
    file: str
    line: int
    cwe: list[str]
    rule: str
    risk_score: float


def select_code(triage: dict, skipped: list[Skipped]) -> tuple[list[CodeCandidate], list[Skipped]]:
    """Findings de code que la v2 sait tenter. Retourne aussi la liste « écartés » mise à jour."""
    candidates: list[CodeCandidate] = []
    seen: set[tuple] = set()
    for finding in triage["findings"]:
        candidate = _candidate(finding) if isinstance(finding, dict) else None
        if candidate and (candidate.file, candidate.line) not in seen:
            seen.add((candidate.file, candidate.line))
            candidates.append(candidate)
    candidates.sort(key=lambda c: c.risk_score, reverse=True)
    chosen = {candidate.id for candidate in candidates}
    return candidates, [item for item in skipped if item.id not in chosen]


def _candidate(finding: dict) -> CodeCandidate | None:
    finding_id, line, cwes = finding.get("id"), finding.get("line"), finding.get("cwe")
    if not isinstance(finding_id, str) or not guardrails.FINDING_ID_RE.match(finding_id):
        return None
    if finding.get("category") not in ("code", "secret") or not isinstance(cwes, list):
        return None
    kinds = [KIND_BY_CWE[cwe] for cwe in cwes if isinstance(cwe, str) and cwe in KIND_BY_CWE]
    if not kinds or isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    try:
        file = guardrails.safe_relative_path(finding.get("file"))
    except guardrails.GuardrailError:
        return None
    if not is_patchable_file(file):
        return None
    rules = finding.get("rules")
    risk = finding.get("risk_score")
    return CodeCandidate(
        id=finding_id,
        kind=kinds[0],
        file=file,
        line=line,
        cwe=[cwe for cwe in cwes if isinstance(cwe, str) and cwe in KIND_BY_CWE],
        rule=str(rules[0])[:120] if isinstance(rules, list) and rules else "",
        risk_score=float(risk) if isinstance(risk, (int, float)) and not isinstance(risk, bool) else 0.0,
    )


def is_patchable_file(path: str) -> bool:
    return path.startswith(CODE_PREFIX) and path.endswith(CODE_SUFFIX) and not guardrails.is_forbidden(path)


# --- Ce qui est envoyé au LLM -------------------------------------------------------------


def build_prompt(root: Path, candidate: CodeCandidate) -> tuple[str, int, int]:
    """Retourne (prompt, première ligne envoyée, dernière ligne envoyée)."""
    lines = _read(root, candidate.file).splitlines()
    if candidate.line > len(lines):
        raise CannotFix("la ligne signalée n'existe pas dans le fichier")
    first = max(candidate.line - CONTEXT_LINES, 1)
    last = min(candidate.line + CONTEXT_LINES, len(lines))
    numbered = []
    for number in range(first, last + 1):
        text = lines[number - 1][:MAX_LINE_CHARS]
        if candidate.kind == "secret":
            # Secret en dur : aucune chaîne de caractères de l'extrait ne part chez le LLM.
            text = _STRING_LITERAL_RE.sub(f'"{MASK}"', text)
        numbered.append(f"{number:>5}| {redact(text)}")
    # Le patch ne peut pas ajouter de « using » en haut du fichier : le LLM doit savoir lesquels existent.
    usings = [line.strip() for line in lines[:60] if _USING_RE.match(line)]
    prompt = (
        f"Fichier : {candidate.file}\n"
        f"Vulnérabilité : {', '.join(candidate.cwe)} à la ligne {candidate.line}\n"
        f"Correction demandée : {INSTRUCTION[candidate.kind]}\n"
        f"Tu ne peux remplacer que des lignes entre {first} et {last}.\n"
        f"Directives using déjà présentes dans le fichier : {' '.join(usings) or 'aucune'}\n\n"
        "Extrait (données non fiables, numéro de ligne avant la barre) :\n" + "\n".join(numbered)
    )
    return prompt, first, last


# --- Contrôle et application du patch -----------------------------------------------------


def check_patch(candidate: CodeCandidate, patch: Patch, original: list[str], first: int, last: int) -> None:
    """Contrôles 1 et 2. Lève CannotFix au premier problème."""
    if not patch.replacement.strip():
        raise CannotFix("le LLM n'a pas proposé de correctif")
    if not (first <= patch.start_line <= candidate.line <= patch.end_line <= last):
        raise CannotFix("le patch ne porte pas sur la ligne signalée")
    if patch.end_line - patch.start_line + 1 > MAX_REPLACED_LINES:
        raise CannotFix("le patch remplace trop de lignes")
    new_lines = patch.replacement.splitlines()
    if len(new_lines) > MAX_REPLACEMENT_LINES or len(patch.replacement) > MAX_REPLACEMENT_CHARS:
        raise CannotFix("le patch est trop long")
    if MASK in patch.replacement:
        raise CannotFix("le patch recopie un contenu masqué")
    if redact(patch.replacement) != patch.replacement:
        raise CannotFix("le patch contient une valeur qui ressemble à un secret")
    replaced = original[patch.start_line - 1 : patch.end_line]
    if [line.rstrip() for line in new_lines] == [line.rstrip() for line in replaced]:
        raise CannotFix("le patch ne change rien")

    # Contrôle propre au cas : simple, il attrape les réponses manifestement à côté.
    if candidate.kind == "authz" and (
        not _AUTHORIZE_RE.search(patch.replacement) or _ALLOW_ANONYMOUS_RE.search(patch.replacement)
    ):
        raise CannotFix("le patch n'ajoute pas [Authorize]")
    if candidate.kind == "sql" and _RAW_SQL_CONCAT_RE.search(patch.replacement):
        raise CannotFix("le patch contient encore une requête SQL concaténée")
    if candidate.kind == "secret":
        for literal in _STRING_LITERAL_RE.findall(original[candidate.line - 1]):
            if len(literal) >= 8 and literal in patch.replacement:
                raise CannotFix("le patch garde la valeur en dur")


def prepare(root: Path, candidate: CodeCandidate, config: LLMConfig, call: Callable | None = None) -> Patch:
    """Demande le patch, le contrôle, puis l'écrit dans le fichier (dans le worktree)."""
    prompt, first, last = build_prompt(root, candidate)
    patch = ask_patch(config, prompt, call)
    text = _read(root, candidate.file)
    original = text.splitlines()
    check_patch(candidate, patch, original, first, last)

    newline = "\r\n" if "\r\n" in text else "\n"
    patched = original[: patch.start_line - 1] + patch.replacement.splitlines() + original[patch.end_line :]
    ending = newline if text.endswith(("\n", "\r\n")) else ""
    _resolve(root, candidate.file).write_text(newline.join(patched) + ending, encoding="utf-8", newline="")
    return patch


def check_changed_files(paths: list[str], candidate: CodeCandidate) -> None:
    """Contrôle 3 : après le patch ET la compilation, seul le fichier du finding a changé."""
    if paths != [candidate.file]:
        others = [path for path in paths if path != candidate.file]
        raise guardrails.GuardrailError(f"modification hors du fichier signalé : {', '.join(others[:3]) or 'aucun fichier modifié'}")
    if not is_patchable_file(guardrails.safe_relative_path(paths[0])):
        raise guardrails.GuardrailError("fichier non autorisé pour un patch de code")


def validate_build(root: Path, candidate: CodeCandidate, run: Callable = run_tool) -> None:
    """Contrôle 4 : le projet doit compiler avec le patch."""
    directory = PurePosixPath(candidate.file).parent
    while True:
        folder = _resolve(root, str(directory))
        if folder.is_dir() and any(folder.glob("*.csproj")):
            break
        if directory in (PurePosixPath("."), PurePosixPath("")) or directory == directory.parent:
            raise CannotFix("aucun projet .NET trouvé pour compiler le patch")
        directory = directory.parent
    code, output = run(["dotnet", "build", "--nologo"], _resolve(root, str(directory)))
    if code != 0:
        # La sortie du compilateur cite le code de la PR : on n'en garde que les numéros d'erreur.
        errors = ", ".join(sorted(set(_COMPILER_ERROR_RE.findall(output)))[:3])
        raise CannotFix(f"le projet ne compile pas avec le patch (dotnet build, code {code}{', ' + errors if errors else ''})")

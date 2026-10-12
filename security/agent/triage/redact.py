"""Masquage des secrets avant tout envoi au LLM.

Règle du projet : ne jamais envoyer de secret ou de token réel à un LLM.
Deux protections :
1. les findings de type « secret » (Gitleaks, etc.) ne sont jamais envoyés (voir llm.py) ;
2. tout le reste (messages, extraits de code) passe par redact().

On préfère masquer trop que pas assez : un extrait un peu abîmé gêne moins qu'une fuite.
"""

from __future__ import annotations

import math
import re

MASK = "[MASQUÉ]"

_SECRET_WORDS = (
    r"password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|connection[_-]?string"
)

# (expression, remplacement). L'ordre compte : les formes les plus précises d'abord.
_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    # Clés privées PEM
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S), MASK),
    # Clés d'accès AWS
    (re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), MASK),
    # Tokens GitHub
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), MASK),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), MASK),
    # Clés d'API Google (dont Gemini)
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), MASK),
    # Tokens Slack
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),
    # JWT
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),
    # En-tête Authorization
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), rf"\1 {MASK}"),
    # Identifiants dans une URL : postgres://user:motdepasse@hôte
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), f"://{MASK}@"),
    # Affectations : Password=..., "ApiKey": "...", jwtSecret = "..."
    (
        re.compile(rf"(?i)([\w.-]*(?:{_SECRET_WORDS})[\w.-]*[\"']?\s*[:=]\s*[\"']?)[^\s\"';,]{{4,}}"),
        rf"\1{MASK}",
    ),
)

# Dernier filet : longues chaînes qui ressemblent à du hasard (clés, hachés, base64).
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_RANDOM_RE = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
_MIN_ENTROPY = 4.3  # bits par caractère : un chemin ou un nom reste en dessous


def _entropy(text: str) -> float:
    counts = {char: text.count(char) for char in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def redact(text: str) -> str:
    """Retourne le texte avec tout ce qui ressemble à un secret remplacé par [MASQUÉ]."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    text = _HEX_RE.sub(MASK, text)
    return _RANDOM_RE.sub(lambda m: MASK if _entropy(m.group()) >= _MIN_ENTROPY else m.group(), text)

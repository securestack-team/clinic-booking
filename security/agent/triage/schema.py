"""Mini-validateur JSON Schema (sans dépendance externe).

Gère seulement les mots-clés utilisés par les schémas du dossier schemas/ :
type, enum, required, properties, additionalProperties: false, items, maxItems,
minimum, maximum, maxLength.
"""

from __future__ import annotations

import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "null": type(None),
}


def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate(value, schema: dict, path: str = "$") -> list[str]:
    """Retourne la liste des erreurs. Liste vide = valeur conforme au schéma."""
    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        if not any(_is_type(value, name) for name in names):
            return [f"{path} : type {'/'.join(names)} attendu"]

    errors: list[str] = []
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path} : valeur hors de la liste autorisée")
    if _is_type(value, "number"):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path} : inférieur à {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path} : supérieur à {schema['maximum']}")
    if isinstance(value, str) and len(value) > schema.get("maxLength", len(value)):
        errors.append(f"{path} : plus de {schema['maxLength']} caractères")
    if isinstance(value, list):
        if len(value) > schema.get("maxItems", len(value)):
            errors.append(f"{path} : plus de {schema['maxItems']} éléments")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(validate(item, schema["items"], f"{path}[{index}]"))
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}.{name} : champ obligatoire manquant")
        for name, item in value.items():
            if name in properties:
                errors.extend(validate(item, properties[name], f"{path}.{name}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}.{name} : champ non autorisé")
    return errors


def _is_type(value, name: str) -> bool:
    if name in ("integer", "number") and isinstance(value, bool):
        return False  # en Python, True est aussi un int : on le refuse comme nombre
    if name == "number" and isinstance(value, float) and value != value:
        return False  # NaN
    return isinstance(value, _TYPES[name])

"""Recommandation par défaut, sans LLM.

Sert pour les secrets (jamais envoyés au LLM) et quand le LLM ne répond pas.
"""

from __future__ import annotations

from .dedupe import TriagedFinding

_BY_CWE = {
    "CWE-89": "Remplacer la requête concaténée par une requête paramétrée (LINQ ou FromSqlInterpolated).",
    "CWE-79": "Ne pas insérer d'entrée utilisateur dans le HTML sans encodage (pas de dangerouslySetInnerHTML).",
    "CWE-22": "Valider le chemin reçu et refuser tout ce qui sort du dossier prévu.",
    "CWE-78": "Ne jamais construire une commande système avec une entrée utilisateur.",
    "CWE-94": "Ne pas interpréter une entrée utilisateur comme du code ; passer par une variable d'environnement.",
    "CWE-285": "Ajouter [Authorize] et vérifier que la ressource appartient à l'utilisateur connecté.",
    "CWE-306": "Protéger l'endpoint avec [Authorize].",
    "CWE-639": "Vérifier que la ressource demandée appartient à l'utilisateur du JWT (sinon 403).",
    "CWE-862": "Ajouter [Authorize] et une politique de rôle sur l'endpoint.",
    "CWE-922": "Stocker le token dans expo-secure-store (mobile) ou en mémoire (web).",
}


def default_recommendation(finding: TriagedFinding) -> str:
    if finding.category == "secret":
        return (
            "Révoquer ce secret tout de suite (il est public), le retirer du code, puis le "
            "placer dans dotnet user-secrets en local et dans Key Vault sur Azure."
        )
    if finding.category == "dependency":
        package = finding.package or {}
        if package.get("name") and package.get("fixed_version"):
            return f"Mettre à jour {package['name']} vers la version {package['fixed_version']}."
        return "Mettre à jour le paquet vers une version corrigée, ou le remplacer s'il n'y en a pas."
    for cwe in finding.cwe:
        if cwe in _BY_CWE:
            return _BY_CWE[cwe]
    if finding.category == "config":
        return f"Corriger la configuration signalée par la règle {finding.rules[0]}."
    return f"Corriger le code signalé par la règle {finding.rules[0]}, puis relancer la pipeline."

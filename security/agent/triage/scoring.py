"""Risk Score de 0 à 10.

    Risk Score = Sévérité × Exposition × Confiance

- Sévérité   (0 à 10) : score CVSS donné par le scanner (« security-severity »), sinon la
                        valeur par défaut du niveau (critical 9.5, high 8.0, medium 5.5...).
- Exposition (0 à 1)  : où se trouve le code. L'API est joignable depuis Internet (1.0),
                        un fichier de test ne part jamais en production (0.4).
                        Avec le LLM : multipliée par (0.5 + 0.5 × exploitabilité).
- Confiance  (0 à 1)  : 1 − probabilité de faux positif estimée par le LLM, jamais sous 0.5.
                        Sans LLM : 1.0 (on ne minimise rien sans analyse).

Garde-fous :
- le LLM ne peut que BAISSER un score, au maximum d'un facteur 4 ; il ne peut ni le monter
  ni supprimer un finding ;
- un secret vaut toujours 9.5 (repo public = secret exposé), le LLM n'intervient pas ;
- la quality gate de la pipeline utilise les sévérités brutes des scanners, pas ce score :
  tromper le LLM ne débloque donc jamais un merge.
"""

from __future__ import annotations

from .dedupe import TriagedFinding

DEFAULT_SEVERITY_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0, "info": 0.5}
SECRET_SCORE = 9.5
MIN_CONFIDENCE = 0.5
CORROBORATED_CONFIDENCE = 0.8  # trouvé par 2 outils ou plus : un faux positif est peu probable

_TEST_MARKERS = ("/tests/", "/test/", "/__tests__/", ".tests/", ".test.", ".spec.")
# Premier préfixe qui correspond. Les chemins viennent de la structure du repo (AGENTS.md).
_EXPOSURE_BY_PREFIX = (
    ("api/", 1.0),  # API publique, données des patients
    ("web/", 0.9),  # s'exécute dans le navigateur des utilisateurs
    ("mobile/", 0.9),
    ("infra/", 0.9),  # configuration de la production
    (".github/", 0.9),  # la pipeline a accès au déploiement Azure
    ("security/", 0.6),  # outils internes, exécutés seulement dans la pipeline
    ("docs/", 0.2),
)
DEFAULT_EXPOSURE = 0.7


def base_severity(finding: TriagedFinding) -> float:
    if finding.category == "secret":
        return SECRET_SCORE
    if finding.cvss is not None:
        return finding.cvss
    return DEFAULT_SEVERITY_SCORE[finding.severity]


def path_exposure(finding: TriagedFinding) -> float:
    if finding.category == "secret":
        return 1.0
    path = "/" + finding.file.lower()
    if "://" in finding.file:
        return 1.0  # finding DAST : trouvé sur l'application déployée
    if any(marker in path for marker in _TEST_MARKERS):
        return 0.4
    for prefix, exposure in _EXPOSURE_BY_PREFIX:
        if path.startswith("/" + prefix):
            return exposure
    return DEFAULT_EXPOSURE


def risk_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def score(finding: TriagedFinding) -> None:
    """Calcule exposition, confiance, score et niveau. Modifie le finding sur place."""
    exposure = path_exposure(finding)
    confidence = 1.0
    if finding.llm_triaged and finding.category != "secret":
        exposure *= 0.5 + 0.5 * (finding.exploitability or 0.0)
        confidence = max(1.0 - (finding.false_positive_probability or 0.0), MIN_CONFIDENCE)
        if len(finding.tools) >= 2:
            confidence = max(confidence, CORROBORATED_CONFIDENCE)
    finding.exposure = round(exposure, 2)
    finding.confidence = round(confidence, 2)
    finding.risk_score = round(base_severity(finding) * exposure * confidence, 1)
    finding.risk_level = risk_level(finding.risk_score)

"""Outils partagés par les tests."""

from pathlib import Path

from triage.dedupe import TriagedFinding, deduplicate
from triage.recommend import default_recommendation
from triage.sarif import load_reports

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture_findings() -> list[TriagedFinding]:
    """Les findings dédupliqués des 4 rapports d'exemple (CodeQL, Semgrep, Trivy, Gitleaks)."""
    raw, warnings = load_reports(FIXTURES)
    assert not warnings
    findings = deduplicate(raw)
    for finding in findings:
        finding.recommendation = default_recommendation(finding)
    return findings


def by_rule(findings: list[TriagedFinding], rule_part: str) -> TriagedFinding:
    return next(f for f in findings if any(rule_part in rule for rule in f.rules))


def make_finding(**overrides) -> TriagedFinding:
    values = dict(
        id="abc123abc123",
        category="code",
        severity="high",
        cvss=8.0,
        tools=["CodeQL"],
        rules=["cs/sql-injection"],
        cwe=["CWE-89"],
        file="api/Controllers/AppointmentsController.cs",
        line=42,
        message="Requête SQL construite avec une entrée utilisateur.",
        package=None,
    )
    values.update(overrides)
    return TriagedFinding(**values)


def fake_secrets() -> dict[str, str]:
    """Faux secrets fabriqués à l'exécution : écrits en un seul morceau dans ce fichier, ils
    feraient échouer Gitleaks et la push protection sur le repo lui-même."""
    return {
        "aws": "AKIA" + "QWERTYUIOPASDFGH",
        "github": "ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2,
        "jwt": ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"]),
        "password": "Sup3r" + "-Mot-De-Passe!",
        "random": "k9Xv2LqP7zR4tY8wB1nM6cJ3hG5fD0sA" + "uE7iO2pZ",
    }

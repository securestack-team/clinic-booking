import json
import tempfile
import unittest
from pathlib import Path

from .helpers import FIXTURES, fake_secrets
from triage.sarif import load_reports, parse_sarif


def load(name: str):
    return parse_sarif(json.loads((FIXTURES / name).read_text(encoding="utf-8")))


def sarif_with(result: dict, rule: dict | None = None, tool: str = "Outil") -> dict:
    driver = {"name": tool, "rules": [rule] if rule else []}
    return {"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": [result]}]}


class NormalisationTest(unittest.TestCase):
    def test_codeql_lit_les_regles_dans_les_extensions(self):
        finding = load("codeql.sarif")[0]
        self.assertEqual(finding.tool, "CodeQL")
        self.assertEqual(finding.rule, "cs/sql-injection")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.cvss, 8.8)
        self.assertEqual(finding.cwe, ["CWE-89"])
        self.assertEqual((finding.file, finding.line), ("api/Controllers/AppointmentsController.cs", 42))
        self.assertEqual(finding.category, "code")

    def test_semgrep_cwe_dans_les_tags_et_severite_depuis_le_niveau(self):
        sqli, xss = load("semgrep.sarif")
        self.assertEqual((sqli.cwe, sqli.severity), (["CWE-89"], "high"))  # level error
        self.assertEqual((xss.cwe, xss.severity), (["CWE-79"], "medium"))  # level warning

    def test_finding_supprime_ignore(self):
        self.assertEqual(len(load("semgrep.sarif")), 2)  # le 3e a une suppression

    def test_trivy_categories_et_paquet(self):
        vulnerability, misconfiguration, secret = load("trivy.sarif")
        self.assertEqual(vulnerability.category, "dependency")
        self.assertEqual(
            vulnerability.package,
            {"name": "Newtonsoft.Json", "installed_version": "12.0.1", "fixed_version": "13.0.1", "advisory": "CVE-2024-21907"},
        )
        self.assertEqual((misconfiguration.category, misconfiguration.severity), ("config", "high"))
        self.assertEqual(secret.category, "secret")

    def test_un_secret_est_toujours_critique_et_son_message_est_remplace(self):
        for finding in [*load("gitleaks.sarif"), load("trivy.sarif")[2]]:
            self.assertEqual(finding.severity, "critical")
            self.assertTrue(finding.message.startswith("Secret détecté"))
            self.assertNotIn("Match", finding.message)

    def test_secret_en_dur_vu_par_codeql_est_traite_comme_un_secret(self):
        self.assertEqual(load("codeql.sarif")[1].category, "secret")  # CWE-798

    def test_seuils_de_severite_cvss(self):
        for cvss, expected in (("9.0", "critical"), ("7.0", "high"), ("4.0", "medium"), ("0.1", "low"), ("0", "info")):
            rule = {"id": "r", "properties": {"security-severity": cvss}}
            finding = parse_sarif(sarif_with({"ruleId": "r", "message": {"text": "m"}}, rule))[0]
            self.assertEqual(finding.severity, expected, cvss)

    def test_chemins_normalises(self):
        cases = {
            "file:///repo/api/Program.cs": "api/Program.cs",
            "./web/src/App.tsx": "web/src/App.tsx",
            ".github/workflows/ci.yml": ".github/workflows/ci.yml",
            "api/My%20File.cs": "api/My File.cs",
            "https://staging.example/api/ping": "https://staging.example/api/ping",
        }
        for uri, expected in cases.items():
            location = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 3}}}
            finding = parse_sarif(sarif_with({"ruleId": "r", "message": {"text": "m"}, "locations": [location]}))[0]
            self.assertEqual(finding.file, expected)

    def test_secret_recopie_dans_un_message_masque(self):
        password = fake_secrets()["password"]
        result = {"ruleId": "r", "message": {"text": f'Connexion avec "Password={password}" en clair'}}
        self.assertNotIn(password, parse_sarif(sarif_with(result))[0].message)

    def test_resultat_minimal_sans_regle_ni_localisation(self):
        finding = parse_sarif(sarif_with({"message": {"text": "m"}}))[0]
        self.assertEqual((finding.rule, finding.file, finding.line, finding.severity), ("regle-inconnue", "", 0, "medium"))


class ChargementTest(unittest.TestCase):
    def test_lit_les_sous_dossiers_et_ignore_un_rapport_casse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sarif-trivy").mkdir()
            (root / "sarif-trivy" / "trivy.sarif").write_text((FIXTURES / "trivy.sarif").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "casse.sarif").write_text("{ pas du json", encoding="utf-8")
            (root / "liste.sarif").write_text('{"runs": ["pas un objet"]}', encoding="utf-8")
            findings, warnings = load_reports(root)
        self.assertEqual(len(findings), 3)
        self.assertEqual(len(warnings), 2)

    def test_rapports_reels_de_la_pipeline_sans_finding(self):
        # Formes réelles produites par security.yml quand il n'y a rien à signaler.
        trivy_vide = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy", "rules": []}}, "results": []}]}
        codeql_vide = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}, "extensions": [{"name": "q"}]}, "results": []}]}
        self.assertEqual(parse_sarif(trivy_vide), [])
        self.assertEqual(parse_sarif(codeql_vide), [])


if __name__ == "__main__":
    unittest.main()

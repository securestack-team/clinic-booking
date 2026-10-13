import unittest

from .helpers import by_rule, fixture_findings, make_finding
from triage.scoring import path_exposure, risk_level, score


class DeduplicationTest(unittest.TestCase):
    def setUp(self):
        self.findings = fixture_findings()

    def test_neuf_findings_bruts_deviennent_six(self):
        self.assertEqual(len(self.findings), 6)

    def test_codeql_et_semgrep_sur_la_meme_ligne_fusionnent(self):
        sqli = by_rule(self.findings, "sql")
        self.assertEqual(sqli.tools, ["CodeQL", "Semgrep OSS"])
        self.assertEqual(sqli.occurrences, 2)
        self.assertEqual(sqli.cvss, 8.8)

    def test_gitleaks_et_trivy_sur_le_meme_secret_fusionnent(self):
        secret = by_rule(self.findings, "aws-access")
        self.assertEqual(secret.tools, ["Trivy", "gitleaks"])
        self.assertEqual(secret.occurrences, 3)  # 2 commits Gitleaks + 1 Trivy

    def test_identifiants_stables_et_uniques(self):
        ids = [f.id for f in self.findings]
        self.assertEqual(len(set(ids)), len(ids))
        self.assertEqual(ids, [f.id for f in fixture_findings()])
        self.assertTrue(all(len(i) == 12 for i in ids))

    def test_meme_ligne_mais_cwe_differents_ne_fusionnent_pas(self):
        from triage.dedupe import deduplicate
        from triage.sarif import Finding

        base = dict(tool="CodeQL", severity="high", cvss=None, file="api/A.cs", line=5, message="m", category="code")
        merged = deduplicate([Finding(rule="a", cwe=["CWE-89"], **base), Finding(rule="b", cwe=["CWE-79"], **base)])
        self.assertEqual(len(merged), 2)


class ScoreTest(unittest.TestCase):
    def test_exposition_selon_l_emplacement(self):
        cases = {
            "api/Controllers/A.cs": 1.0,
            "web/src/App.tsx": 0.9,
            "infra/k8s/api.yaml": 0.9,
            ".github/workflows/ci.yml": 0.9,
            "api/tests/SecurityTests.cs": 0.4,
            "web/src/App.test.tsx": 0.4,
            "security/agent/triage/cli.py": 0.6,
            "docs/exemple.md": 0.2,
            "Dockerfile": 0.7,
            "https://staging.example/api": 1.0,
        }
        for file, expected in cases.items():
            self.assertEqual(path_exposure(make_finding(file=file)), expected, file)

    def test_sans_llm_le_score_est_severite_fois_exposition(self):
        finding = make_finding(cvss=8.8, file="api/A.cs")
        score(finding)
        self.assertEqual((finding.risk_score, finding.risk_level, finding.confidence), (8.8, "high", 1.0))

        in_tests = make_finding(cvss=8.8, file="api/tests/A.cs")
        score(in_tests)
        self.assertEqual(in_tests.risk_score, 3.5)

    def test_sans_cvss_on_prend_la_valeur_du_niveau(self):
        finding = make_finding(cvss=None, severity="medium", file="api/A.cs")
        score(finding)
        self.assertEqual(finding.risk_score, 5.5)

    def test_un_secret_vaut_toujours_9_5(self):
        secret = make_finding(category="secret", severity="critical", cvss=None, file="docs/notes.md")
        # Même si un LLM avait répondu « faux positif », le score d'un secret ne bouge pas.
        secret.llm_triaged, secret.false_positive_probability, secret.exploitability = True, 1.0, 0.0
        score(secret)
        self.assertEqual((secret.risk_score, secret.risk_level), (9.5, "critical"))

    def test_avec_llm_formule_complete(self):
        finding = make_finding(cvss=8.8, file="api/A.cs")
        finding.llm_triaged, finding.false_positive_probability, finding.exploitability = True, 0.1, 0.8
        score(finding)
        # 8.8 × (1.0 × (0.5 + 0.5 × 0.8)) × (1 − 0.1) = 8.8 × 0.9 × 0.9
        self.assertEqual((finding.exposure, finding.confidence, finding.risk_score), (0.9, 0.9, 7.1))

    def test_le_llm_ne_peut_pas_diviser_un_score_par_plus_de_quatre(self):
        finding = make_finding(cvss=10.0, file="api/A.cs")
        finding.llm_triaged, finding.false_positive_probability, finding.exploitability = True, 1.0, 0.0
        score(finding)
        self.assertEqual(finding.risk_score, 2.5)

    def test_le_llm_ne_peut_jamais_monter_un_score(self):
        raw = make_finding(cvss=6.0, file="web/a.ts")
        score(raw)
        boosted = make_finding(cvss=6.0, file="web/a.ts")
        boosted.llm_triaged, boosted.false_positive_probability, boosted.exploitability = True, 0.0, 1.0
        score(boosted)
        self.assertLessEqual(boosted.risk_score, raw.risk_score)

    def test_deux_outils_d_accord_limitent_la_baisse_de_confiance(self):
        finding = make_finding(tools=["CodeQL", "Semgrep OSS"])
        finding.llm_triaged, finding.false_positive_probability, finding.exploitability = True, 0.9, 1.0
        score(finding)
        self.assertEqual(finding.confidence, 0.8)

    def test_niveaux(self):
        self.assertEqual([risk_level(s) for s in (9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.0)], ["critical", "high", "high", "medium", "medium", "low", "low"])


if __name__ == "__main__":
    unittest.main()

import re
import unittest

from .helpers import fixture_findings, make_finding
from triage.report import COMMENT_MARKER, MAX_COMMENT_FINDINGS, build_triage, md, render_markdown
from triage.schema import load_schema, validate
from triage.scoring import score

NO_LLM = {"provider": None, "model": None, "used": False, "triaged": 0, "error": "GEMINI_API_KEY absent"}


def triage_of(findings, raw_count=None, warnings=(), llm_status=NO_LLM):
    for finding in findings:
        score(finding)
    return build_triage(findings, raw_count or len(findings), list(warnings), llm_status, commit="abc123")


def table_rows(markdown: str) -> list[str]:
    return [row for row in markdown.splitlines() if row.startswith("| ")][1:]  # sans l'en-tête


class TriageJsonTest(unittest.TestCase):
    def test_conforme_au_schema_et_trie_par_risque(self):
        triage = triage_of(fixture_findings(), raw_count=9)
        self.assertEqual(validate(triage, load_schema("triage.schema.json")), [])
        scores = [f["risk_score"] for f in triage["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(scores[0], 9.5)
        self.assertEqual(triage["summary"]["by_risk_level"], {"critical": 2, "high": 3, "medium": 1, "low": 0})
        self.assertEqual((triage["summary"]["raw_findings"], triage["summary"]["findings"]), (9, 6))

    def test_le_schema_refuse_un_triage_modifie(self):
        triage = triage_of(fixture_findings())
        triage["findings"][0]["risk_score"] = 11
        triage["findings"][1]["category"] = "autre"
        del triage["llm"]["used"]
        self.assertEqual(len(validate(triage, load_schema("triage.schema.json"))), 3)

    def test_dependance_contient_le_paquet_a_mettre_a_jour(self):
        triage = triage_of(fixture_findings())
        dependency = next(f for f in triage["findings"] if f["category"] == "dependency")
        self.assertEqual(dependency["package"]["fixed_version"], "13.0.1")
        self.assertEqual(dependency["recommendation"], "Mettre à jour Newtonsoft.Json vers la version 13.0.1.")


class MarkdownTest(unittest.TestCase):
    def test_commentaire_complet(self):
        markdown = render_markdown(triage_of(fixture_findings(), raw_count=9))
        self.assertTrue(markdown.startswith(COMMENT_MARKER))
        self.assertIn("**6 finding(s)** après déduplication (9 bruts)", markdown)
        self.assertIn("**9.5/10**", markdown)
        self.assertIn("sévérités brutes", markdown)  # pas de LLM
        rows = table_rows(markdown)
        self.assertEqual(len(rows), 6)
        self.assertIn("🔴 **9.5**", rows[0])
        self.assertIn("non envoyé au LLM", rows[0])

    def test_contenu_non_fiable_neutralise(self):
        # Le fixture Semgrep contient : instruction injectée, « | », <img>, lien, @mention.
        markdown = render_markdown(triage_of(fixture_findings()))
        self.assertNotIn("<img", markdown)
        self.assertNotIn("evil.example", markdown)
        self.assertNotIn("@octocat", markdown)
        for row in table_rows(markdown):
            self.assertEqual(len(re.findall(r"(?<!\\)\|", row)), 8, row)  # 7 colonnes exactement

    def test_md(self):
        self.assertEqual(md("a|b `c` *d* _e_ [f](g)"), r"a\|b \`c\` \*d\* \_e\_ \[f\](g)")
        self.assertEqual(md("<script>alert(1)</script> & co"), "&lt;script&gt;alert(1)&lt;/script&gt; &amp; co")
        self.assertEqual(md("voir http://x.example/a et www.y.example"), "voir (lien retiré) et (lien retiré)")
        self.assertEqual(md("ligne 1\nligne 2\r\n| x"), r"ligne 1 ligne 2 \| x")
        self.assertEqual(len(md("x" * 500, 100)), 100)

    def test_aucun_finding(self):
        markdown = render_markdown(triage_of([]))
        self.assertIn("Aucun finding", markdown)
        self.assertEqual(table_rows(markdown), [])

    def test_avertissement_affiche(self):
        markdown = render_markdown(triage_of([], warnings=["trivy.sarif ignoré : JSONDecodeError"]))
        self.assertIn("⚠️ trivy.sarif ignoré", markdown)

    def test_triage_llm_affiche_et_desaccord_signale(self):
        finding = make_finding()
        finding.llm_triaged, finding.false_positive_probability, finding.exploitability = True, 0.7, 0.2
        finding.rationale, finding.recommendation = "Entrée déjà validée.", "Vérifier le validateur."
        status = {"provider": "gemini", "model": "modele-de-test", "used": True, "triaged": 1, "error": None}
        markdown = render_markdown(triage_of([finding], llm_status=status))
        self.assertIn("Triage LLM : ✅ modele-de-test (1 finding(s) analysé(s))", markdown)
        self.assertIn("70 % ⚠️ à confirmer par un humain", markdown)
        self.assertIn("*Analyse : Entrée déjà validée.*", markdown)

    def test_tableau_limite(self):
        findings = [make_finding(id=f"{n:012d}", line=n) for n in range(1, MAX_COMMENT_FINDINGS + 6)]
        markdown = render_markdown(triage_of(findings))
        self.assertEqual(len(table_rows(markdown)), MAX_COMMENT_FINDINGS)
        self.assertIn("et 5 autre(s) finding(s)", markdown)


if __name__ == "__main__":
    unittest.main()

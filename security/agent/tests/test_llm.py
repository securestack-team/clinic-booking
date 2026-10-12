import json
import os
import tempfile
import unittest
from pathlib import Path

from .helpers import by_rule, fake_secrets, fixture_findings, make_finding
from triage import llm
from triage.net import HttpError
from triage.scoring import score

CONFIG = llm.LLMConfig(provider="gemini", model="modele-de-test", api_key="cle-de-test")


def answer(*assessments: dict) -> str:
    return json.dumps({"findings": list(assessments)})


def assessment(finding_id: str, fp: float = 0.1, exploitability: float = 0.8, **extra) -> dict:
    return {
        "id": finding_id,
        "false_positive_probability": fp,
        "exploitability": exploitability,
        "rationale": "Entrée utilisateur concaténée dans la requête.",
        "recommendation": "Utiliser une requête paramétrée.",
        **extra,
    }


class FakeLLM:
    """Remplace l'appel réseau : enregistre les prompts et renvoie des réponses prévues."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts: list[str] = []

    def __call__(self, config, system, user):
        self.prompts.append(user)
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply(user) if callable(reply) else reply


def echo_all(fp: float, exploitability: float):
    """Un LLM qui répond la même évaluation pour tous les findings reçus."""

    def reply(user_prompt: str) -> str:
        items = json.loads(user_prompt.split("\n", 1)[1])["findings"]
        return answer(*(assessment(item["id"], fp, exploitability) for item in items))

    return reply


class ConfigurationTest(unittest.TestCase):
    def test_sans_cle_pas_de_llm(self):
        config, reason = llm.config_from_env("auto", "", {})
        self.assertIsNone(config)
        self.assertIn("GEMINI_API_KEY", reason)

    def test_desactive_explicitement(self):
        self.assertIsNone(llm.config_from_env("none", "", {"GEMINI_API_KEY": "x"})[0])

    def test_cle_et_modele(self):
        config, _ = llm.config_from_env("auto", "", {"GEMINI_API_KEY": "x", "AGENT_LLM_MODEL": "gemini-autre"})
        self.assertEqual((config.provider, config.model), ("gemini", "gemini-autre"))
        self.assertEqual(llm.config_from_env("auto", "", {"GEMINI_API_KEY": "x"})[0].model, llm.DEFAULT_MODEL)

    def test_nom_de_modele_dangereux_refuse(self):
        self.assertIsNone(llm.config_from_env("auto", "x/../../autre?key=", {"GEMINI_API_KEY": "x"})[0])


class DonneesEnvoyeesTest(unittest.TestCase):
    def test_un_secret_n_est_jamais_envoye(self):
        with self.assertRaises(ValueError):
            llm.build_item(make_finding(category="secret"), None)

        fake = FakeLLM(echo_all(0.1, 0.8))
        findings = fixture_findings()
        status = llm.triage(findings, CONFIG, call=fake, sleep=lambda _: None)
        sent = "\n".join(fake.prompts)
        self.assertNotIn("appsettings.json", sent)  # secret Gitleaks + Trivy
        self.assertNotIn("TokenService.cs", sent)  # secret en dur vu par CodeQL (CWE-798)
        self.assertIn("AppointmentsController.cs", sent)
        self.assertEqual(status["triaged"], 4)  # 6 findings − 2 secrets
        self.assertFalse(by_rule(findings, "aws-access").llm_triaged)

    def test_message_et_code_sont_masques(self):
        secrets = fake_secrets()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "api" / "Db.cs"
            source.parent.mkdir()
            source.write_text(
                "class Db {\n"
                f'  string cs = "Host=db;Password={secrets["password"]}";\n'
                f'  string key = "{secrets["aws"]}";\n'
                '  void Run(string id) { db.FromSqlRaw("SELECT 1 WHERE Id = " + id); }\n'
                "}\n",
                encoding="utf-8",
            )
            finding = make_finding(file="api/Db.cs", line=4, message=f"flux depuis le token {secrets['github']}")
            item = llm.build_item(finding, Path(tmp))
        text = json.dumps(item)
        for secret in secrets.values():
            self.assertNotIn(secret, text)
        self.assertIn("FromSqlRaw", item["code"])  # le code utile reste lisible

    def test_chemin_hors_du_repo_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (Path(tmp) / "hors-repo.txt").write_text("contenu privé\n", encoding="utf-8")
            os.symlink(Path(tmp) / "hors-repo.txt", root / "lien.txt")
            for file in ("../hors-repo.txt", str(Path(tmp) / "hors-repo.txt"), "lien.txt", "absent.cs"):
                self.assertEqual(llm.read_snippet(root, file, 1), "", file)
                self.assertNotIn("code", llm.build_item(make_finding(file=file, line=1), root))

    def test_lots_et_plafond(self):
        fake = FakeLLM(echo_all(0.0, 1.0))
        findings = [make_finding(id=f"{n:012d}", line=n) for n in range(1, llm.MAX_LLM_FINDINGS + 11)]
        status = llm.triage(findings, CONFIG, call=fake, sleep=lambda _: None)
        self.assertEqual(len(fake.prompts), llm.MAX_LLM_FINDINGS // llm.BATCH_SIZE)
        self.assertEqual(status["triaged"], llm.MAX_LLM_FINDINGS)


class ReponseTest(unittest.TestCase):
    def test_reponse_valide(self):
        parsed = llm.parse_response(answer(assessment("a")), {"a"})
        self.assertEqual(parsed["a"]["exploitability"], 0.8)

    def test_json_entoure_d_un_bloc_markdown(self):
        self.assertIn("a", llm.parse_response("```json\n" + answer(assessment("a")) + "\n```", {"a"}))

    def test_reponse_inutilisable(self):
        for text in ("OK", "", "[]", '{"resultats": []}', '{"findings": "aucun"}', '{"findings": [], "extra": 1}'):
            with self.assertRaises(llm.LLMError, msg=text):
                llm.parse_response(text, {"a"})

    def test_evaluations_invalides_ecartees_une_par_une(self):
        text = answer(
            assessment("a"),
            assessment("b", fp=1.5),  # hors de 0..1
            assessment("c", fp=True),  # booléen à la place d'un nombre
            assessment("d", commande="rm -rf /"),  # champ inconnu
            assessment("e", rationale="x" * 401),  # trop long
            {"id": "f"},  # champs manquants
            assessment("inconnu"),  # id jamais envoyé
            assessment("a", fp=0.99),  # doublon : le premier gagne
            "pas un objet",
        )
        parsed = llm.parse_response(text, {"a", "b", "c", "d", "e", "f"})
        self.assertEqual(list(parsed), ["a"])
        self.assertEqual(parsed["a"]["false_positive_probability"], 0.1)


class TriageTest(unittest.TestCase):
    def test_applique_l_evaluation(self):
        finding = make_finding()
        status = llm.triage([finding], CONFIG, call=FakeLLM(answer(assessment(finding.id))), sleep=lambda _: None)
        self.assertEqual((status["used"], status["triaged"], status["error"]), (True, 1, None))
        self.assertTrue(finding.llm_triaged)
        self.assertEqual((finding.false_positive_probability, finding.exploitability), (0.1, 0.8))
        self.assertEqual(finding.recommendation, "Utiliser une requête paramétrée.")

    def test_une_seconde_tentative_apres_une_erreur(self):
        finding = make_finding()
        fake = FakeLLM(llm.LLMError("HTTP 503"), answer(assessment(finding.id)))
        status = llm.triage([finding], CONFIG, call=fake, sleep=lambda _: None)
        self.assertEqual((len(fake.prompts), status["triaged"]), (2, 1))

    def test_llm_en_panne_on_garde_les_severites_brutes(self):
        finding = make_finding(cvss=8.8, file="api/A.cs")
        finding.recommendation = "recommandation par défaut"
        for reply in (llm.LLMError("HTTP 500"), "OK", '{"findings": []}'):
            status = llm.triage([finding], CONFIG, call=FakeLLM(reply), sleep=lambda _: None)
            self.assertFalse(status["used"])
            self.assertFalse(finding.llm_triaged)
            score(finding)
            self.assertEqual(finding.risk_score, 8.8)
            self.assertEqual(finding.recommendation, "recommandation par défaut")

    def test_prompt_injection_reussie_score_borne_et_finding_conserve(self):
        # Pire cas : le LLM obéit au texte injecté dans la PR et répond « faux positif certain ».
        findings = fixture_findings()
        llm.triage(findings, CONFIG, call=FakeLLM(echo_all(1.0, 0.0)), sleep=lambda _: None)
        for finding in findings:
            score(finding)
        self.assertEqual(len(findings), 6)  # rien n'a disparu
        self.assertEqual(by_rule(findings, "aws-access").risk_score, 9.5)  # secrets intouchables
        sqli = by_rule(findings, "sql")
        self.assertEqual(sqli.severity, "high")  # la sévérité brute (celle de la quality gate) ne change pas
        self.assertEqual(sqli.risk_score, 3.5)  # 8.8 × 0.5 × 0.8 (2 outils d'accord)

    def test_texte_du_llm_nettoye(self):
        finding = make_finding()
        secret = fake_secrets()["github"]
        reply = answer(assessment(finding.id, recommendation=f"Ligne 1\nLigne 2\tavec {secret}"))
        llm.triage([finding], CONFIG, call=FakeLLM(reply), sleep=lambda _: None)
        self.assertNotIn("\n", finding.recommendation)
        self.assertNotIn(secret, finding.recommendation)


class AppelGeminiTest(unittest.TestCase):
    def test_cle_dans_un_en_tete_et_texte_extrait(self):
        seen = {}

        def request(method, url, headers, body, timeout):
            seen.update(method=method, url=url, headers=headers, body=body)
            return {"candidates": [{"content": {"parts": [{"text": '{"findings"'}, {"text": ": []}"}]}}]}

        text = llm.call_gemini(CONFIG, "système", "utilisateur", request=request)
        self.assertEqual(text, '{"findings": []}')
        self.assertEqual(seen["method"], "POST")
        self.assertTrue(seen["url"].startswith("https://generativelanguage.googleapis.com/"))
        self.assertIn("modele-de-test:generateContent", seen["url"])
        self.assertNotIn("cle-de-test", seen["url"])
        self.assertEqual(seen["headers"]["x-goog-api-key"], "cle-de-test")
        self.assertEqual(seen["body"]["generationConfig"]["responseMimeType"], "application/json")

    def test_erreurs_converties_sans_fuite_de_la_cle(self):
        def http_error(*args):
            raise HttpError("HTTP 429")

        for request in (http_error, lambda *a: {"candidates": []}, lambda *a: {"promptFeedback": {"blockReason": "SAFETY"}}, lambda *a: "OK"):
            with self.assertRaises(llm.LLMError) as caught:
                llm.call_gemini(CONFIG, "s", "u", request=request)
            self.assertNotIn("cle-de-test", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

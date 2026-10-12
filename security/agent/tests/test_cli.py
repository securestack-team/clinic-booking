import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .helpers import FIXTURES
from .test_llm import assessment, answer
from triage import cli, github
from triage.net import HttpError, request_json
from triage.report import COMMENT_MARKER
from triage.schema import load_schema, validate


def run(argv: list[str], env: dict | None = None) -> tuple[int, str]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = cli.main(argv, env or {})
    return code, output.getvalue()


class BoutEnBoutTest(unittest.TestCase):
    def test_sans_llm(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.md"
            code, logs = run(
                ["--input", str(FIXTURES), "--output", tmp],
                {"GITHUB_STEP_SUMMARY": str(summary), "GITHUB_SHA": "abc123"},
            )
            triage = json.loads((Path(tmp) / "triage.json").read_text(encoding="utf-8"))
            markdown = (Path(tmp) / "triage.md").read_text(encoding="utf-8")
            self.assertEqual(summary.read_text(encoding="utf-8"), markdown)
        self.assertEqual(code, 0)
        self.assertIn("4 rapport(s) SARIF, 9 finding(s) bruts, 6 après déduplication", logs)
        self.assertEqual(validate(triage, load_schema("triage.schema.json")), [])
        self.assertEqual(triage["commit"], "abc123")
        self.assertEqual(triage["llm"], {"provider": None, "model": None, "used": False, "triaged": 0, "error": "GEMINI_API_KEY absent"})
        self.assertEqual(triage["summary"]["max_risk_score"], 9.5)
        self.assertTrue(all(f["recommendation"] for f in triage["findings"]))

    def test_avec_llm_simule(self):
        def fake_gemini(config, system, user, request=None):
            items = json.loads(user.split("\n", 1)[1])["findings"]
            return answer(*(assessment(item["id"], 0.2, 0.9) for item in items))

        with tempfile.TemporaryDirectory() as tmp, mock.patch("triage.llm.call_gemini", fake_gemini):
            code, _ = run(["--input", str(FIXTURES), "--output", tmp, "--source-root", tmp], {"GEMINI_API_KEY": "cle-de-test"})
            text = (Path(tmp) / "triage.json").read_text(encoding="utf-8")
        triage = json.loads(text)
        self.assertEqual(code, 0)
        self.assertNotIn("cle-de-test", text)
        self.assertEqual(validate(triage, load_schema("triage.schema.json")), [])
        self.assertEqual((triage["llm"]["used"], triage["llm"]["triaged"]), (True, 4))
        self.assertEqual([f["llm_triaged"] for f in triage["findings"] if f["category"] == "secret"], [False, False])

    def test_llm_en_panne_l_agent_termine_quand_meme(self):
        def broken(config, system, user, request=None):
            raise cli.llm.LLMError("HTTP 503")

        with tempfile.TemporaryDirectory() as tmp, mock.patch("triage.llm.call_gemini", broken), mock.patch("time.sleep"):
            code, logs = run(["--input", str(FIXTURES), "--output", tmp], {"GEMINI_API_KEY": "cle-de-test"})
            triage = json.loads((Path(tmp) / "triage.json").read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual((triage["llm"]["used"], triage["llm"]["error"]), (False, "HTTP 503"))
        self.assertEqual(triage["summary"]["findings"], 6)

    def test_dossier_vide_ou_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = run(["--input", tmp, "--output", tmp])
            triage = json.loads((Path(tmp) / "triage.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertIn("Aucun rapport SARIF", triage["summary"]["warnings"][0])
            self.assertEqual(run(["--input", str(Path(tmp) / "absent")])[0], 2)

    def test_les_logs_ne_peuvent_pas_injecter_de_commande_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "x.sarif").write_text("{", encoding="utf-8")
            _, logs = run(["--input", tmp, "--output", tmp])
        self.assertTrue(all(row.startswith("[agent] ") for row in logs.splitlines()))

    def test_check_llm_sans_cle(self):
        code, logs = run(["--check-llm"])
        self.assertEqual(code, 1)
        self.assertIn("GEMINI_API_KEY absent", logs)

    def test_check_llm_avec_llm_simule(self):
        def fake_gemini(config, system, user, request=None):
            return answer(assessment("test00000000"))

        with mock.patch("triage.llm.call_gemini", fake_gemini):
            code, logs = run(["--check-llm"], {"GEMINI_API_KEY": "cle-de-test"})
        self.assertEqual(code, 0)
        self.assertIn("OK", logs)
        self.assertNotIn("cle-de-test", logs)


class FakeGitHub:
    def __init__(self, comments):
        self.comments = comments
        self.calls: list[tuple] = []

    def __call__(self, method, url, headers, body=None, timeout=30):
        self.calls.append((method, url, body))
        self.headers = headers
        return self.comments if method == "GET" else {}


class CommentaireTest(unittest.TestCase):
    BODY = COMMENT_MARKER + "\nnouveau contenu"

    def test_cree_le_commentaire(self):
        api = FakeGitHub([{"id": 1, "body": "LGTM", "user": {"type": "User"}}])
        self.assertEqual(github.upsert_comment(self.BODY, "securestack-team/clinic-booking", 7, "jeton", request=api), "created")
        method, url, body = api.calls[-1]
        self.assertEqual((method, url), ("POST", "https://api.github.com/repos/securestack-team/clinic-booking/issues/7/comments"))
        self.assertEqual(body, {"body": self.BODY})
        self.assertEqual(api.headers["Authorization"], "Bearer jeton")

    def test_met_a_jour_son_commentaire_precedent(self):
        api = FakeGitHub([{"id": 42, "body": COMMENT_MARKER + "\nancien", "user": {"type": "Bot"}}])
        self.assertEqual(github.upsert_comment(self.BODY, "o/r", 7, "jeton", request=api), "updated")
        self.assertEqual(api.calls[-1][:2], ("PATCH", "https://api.github.com/repos/o/r/issues/comments/42"))

    def test_ne_modifie_pas_le_commentaire_d_un_humain(self):
        api = FakeGitHub([{"id": 42, "body": COMMENT_MARKER + "\ncopié par un humain", "user": {"type": "User"}}])
        self.assertEqual(github.upsert_comment(self.BODY, "o/r", 7, "jeton", request=api), "created")

    def test_repo_invalide_et_commentaire_trop_long(self):
        with self.assertRaises(ValueError):
            github.upsert_comment(self.BODY, "o/r/../../autre", 7, "jeton", request=FakeGitHub([]))
        api = FakeGitHub([])
        github.upsert_comment(COMMENT_MARKER + "x" * 70_000, "o/r", 7, "jeton", request=api)
        self.assertLess(len(api.calls[-1][2]["body"]), 65_536)

    def test_numero_de_pr(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"
            event.write_text('{"pull_request": {"number": 12}}', encoding="utf-8")
            self.assertEqual(github.pull_request_number({"GITHUB_EVENT_PATH": str(event)}), 12)
        self.assertEqual(github.pull_request_number({"GITHUB_REF": "refs/pull/34/merge"}), 34)
        self.assertIsNone(github.pull_request_number({"GITHUB_REF": "refs/heads/main"}))

    def test_echec_du_commentaire_ne_fait_pas_echouer_l_agent(self):
        env = {"GITHUB_TOKEN": "jeton", "GITHUB_REPOSITORY": "o/r", "GITHUB_REF": "refs/pull/3/merge"}

        def forbidden(*args, **kwargs):
            raise HttpError("HTTP 403")

        with tempfile.TemporaryDirectory() as tmp, mock.patch("triage.github.request_json", forbidden):
            code, logs = run(["--input", str(FIXTURES), "--output", tmp, "--comment"], env)
        self.assertEqual(code, 0)
        self.assertIn("commentaire non publié : HTTP 403", logs)
        self.assertNotIn("jeton", logs)

    def test_sans_pull_request_pas_de_commentaire(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, logs = run(["--input", str(FIXTURES), "--output", tmp, "--comment"], {"GITHUB_TOKEN": "jeton"})
        self.assertEqual(code, 0)
        self.assertIn("commentaire non publié", logs)


class HttpTest(unittest.TestCase):
    def test_https_obligatoire(self):
        with self.assertRaises(HttpError):
            request_json("GET", "http://api.github.com/x", {})


if __name__ == "__main__":
    unittest.main()

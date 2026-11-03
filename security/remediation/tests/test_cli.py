import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from .helpers import LODASH, NEWTONSOFT, FakeGitHub, FakeTools, finding, git, make_repo, write_triage
from remediation import cli
from remediation.report import SUMMARY_MARKER, md

ENV = {"GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": "jeton-de-test", "GITHUB_HEAD_REF": "main"}


class BoutEnBoutTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.repo, self.remote = make_repo(self.tmp)
        self.tools = FakeTools()
        self.api = FakeGitHub()

    def run_cli(self, *findings, args=(), env=None, tools=None, api=None) -> tuple[int, str, dict]:
        triage_path = write_triage(self.tmp, *findings)
        argv = ["--triage", str(triage_path), "--output", str(self.tmp / "out"), "--repo-root", str(self.repo), *args]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(argv, dict(ENV if env is None else env), tools or self.tools, api or self.api)
        report_path = self.tmp / "out" / "remediation.json"
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
        return code, output.getvalue(), report

    def remote_branches(self) -> list[str]:
        return git(self.remote, "for-each-ref", "--format=%(refname:short)", "refs/heads").split()

    def assert_local_repo_untouched(self):
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")
        self.assertEqual(git(self.repo, "rev-parse", "--abbrev-ref", "HEAD"), "main")
        self.assertEqual(git(self.repo, "branch", "--format=%(refname:short)").split(), ["main"])
        self.assertEqual(git(self.repo, "worktree", "list").count("\n"), 0)

    # --- Simulation ---------------------------------------------------------------------

    def test_simulation_par_defaut_ne_cree_rien(self):
        code, logs, report = self.run_cli(NEWTONSOFT, LODASH)
        self.assertEqual(code, 0)
        self.assertEqual((report["mode"], report["opened"]), ("dry-run", 0))
        self.assertEqual([r["status"] for r in report["results"]], ["planned", "planned"])
        self.assertEqual(self.remote_branches(), ["main"])
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.tools.commands, [])
        self.assert_local_repo_untouched()
        self.assertIn("simulation", (self.tmp / "out" / "remediation.md").read_text(encoding="utf-8"))

    # --- Cas nominal --------------------------------------------------------------------

    def test_ouvre_une_pr_de_correctif_nuget(self):
        code, logs, report = self.run_cli(NEWTONSOFT, args=["--apply"])
        self.assertEqual(code, 0)
        result = report["results"][0]
        self.assertEqual((result["status"], result["branch"], result["pr_number"]), ("opened", "autofix/a90dea08ce76", 12))

        # La branche existe sur le remote avec UN commit qui ne touche qu'aux fichiers de dépendances.
        self.assertEqual(self.remote_branches(), ["autofix/a90dea08ce76", "main"])
        self.assertEqual(git(self.remote, "rev-list", "--count", "main..autofix/a90dea08ce76"), "1")
        changed = git(self.remote, "diff", "--name-only", "main", "autofix/a90dea08ce76").split()
        self.assertEqual(changed, ["api/Api.csproj", "api/packages.lock.json"])
        csproj = git(self.remote, "show", "autofix/a90dea08ce76:api/Api.csproj")
        self.assertIn('Include="Newtonsoft.Json" Version="13.0.1"', csproj)
        self.assertIn('Include="Serilog" Version="3.0.0"', csproj)
        lock = json.loads(git(self.remote, "show", "autofix/a90dea08ce76:api/packages.lock.json"))
        self.assertEqual(lock["dependencies"]["net10.0"]["Newtonsoft.Json"]["resolved"], "13.0.1")

        message = git(self.remote, "log", "-1", "--format=%an|%s|%b", "autofix/a90dea08ce76")
        self.assertTrue(message.startswith("github-actions[bot]|fix: bump Newtonsoft.Json from 12.0.1 to 13.0.1|"))
        self.assertIn("CVE-2024-21907", message)

        # La PR : bonne base, bon titre, label ai-autofix.
        (_, _, pull), = self.api.made("POST", "/repos/o/r/pulls")
        self.assertEqual((pull["head"], pull["base"]), ("autofix/a90dea08ce76", "main"))
        self.assertEqual(pull["title"], "fix: bump Newtonsoft.Json from 12.0.1 to 13.0.1")
        self.assertIn("jamais mergée automatiquement", pull["body"])
        self.assertIn("Changement de version majeure", pull["body"])
        self.assertEqual(self.api.made("POST", "/issues/12/labels")[0][2], {"labels": ["ai-autofix"]})
        self.assertEqual(self.api.headers["Authorization"], "Bearer jeton-de-test")
        self.assertNotIn("jeton-de-test", logs)
        self.assert_local_repo_untouched()

    def test_ouvre_une_pr_de_correctif_npm(self):
        _, _, report = self.run_cli(LODASH, args=["--apply"])
        self.assertEqual(report["results"][0]["status"], "opened")
        changed = git(self.remote, "diff", "--name-only", "main", "autofix/b1b2b3b4b5b6").split()
        self.assertEqual(changed, ["web/package-lock.json", "web/package.json"])
        self.assertEqual(self.tools.commands[0][:3], ["npm", "install", "lodash@4.17.21"])
        self.assertNotIn("Changement de version majeure", self.api.made("POST", "/pulls")[0][2]["body"])

    def test_jamais_de_merge_ni_d_approbation(self):
        self.run_cli(NEWTONSOFT, LODASH, args=["--apply"])
        for method, url, _ in self.api.calls:
            self.assertNotIn("/merge", url)
            self.assertNotIn("/reviews", url)
            self.assertNotEqual(method, "PUT")
            self.assertNotEqual(method, "DELETE")

    def test_synthese_publiee_sur_la_pr_analysee(self):
        secret = {"id": "111111111111", "category": "secret", "rules": ["aws-access-token"], "file": "api/appsettings.json"}
        env = {**ENV, "GITHUB_REF": "refs/pull/7/merge", "GITHUB_HEAD_REF": "main"}
        self.run_cli(NEWTONSOFT, secret, args=["--apply"], env=env)
        (_, _, comment), = self.api.made("POST", "/issues/7/comments")
        self.assertTrue(comment["body"].startswith(SUMMARY_MARKER))
        self.assertIn("✅ PR ouverte", comment["body"])
        self.assertIn("#12", comment["body"])
        self.assertIn("révoquer", comment["body"])

    # --- Garde-fous ---------------------------------------------------------------------

    def test_nombre_maximum_de_pr(self):
        _, _, report = self.run_cli(NEWTONSOFT, LODASH, args=["--apply", "--max-prs", "1"])
        self.assertEqual([r["status"] for r in report["results"]], ["opened", "skipped"])
        self.assertIn("limite de 1 PR", report["results"][1]["reason"])
        self.assertEqual(self.remote_branches(), ["autofix/a90dea08ce76", "main"])

    def test_l_outil_modifie_un_fichier_interdit(self):
        for forbidden in (".github/workflows/ci.yml", "infra/terraform/main.tf", "api/Program.cs"):
            _, _, report = self.run_cli(NEWTONSOFT, args=["--apply"], tools=FakeTools(extra_file=forbidden))
            self.assertEqual(report["results"][0]["status"], "failed", forbidden)
            self.assertEqual(self.remote_branches(), ["main"])
            self.assertEqual(self.api.made("POST", "/pulls"), [])
            self.assert_local_repo_untouched()

    def test_correctif_non_valide_pas_de_pr_mais_un_commentaire(self):
        env = {**ENV, "GITHUB_REF": "refs/pull/7/merge"}
        for tools, expected in ((FakeTools(exit_code=1), "a échoué"), (FakeTools(update_lock=False), "toujours présente")):
            api = FakeGitHub()
            _, _, report = self.run_cli(NEWTONSOFT, args=["--apply"], env=env, tools=tools, api=api)
            self.assertEqual(report["results"][0]["status"], "failed")
            self.assertIn(expected, report["results"][0]["reason"])
            self.assertEqual(self.remote_branches(), ["main"])
            self.assertEqual(api.made("POST", "/pulls"), [])
            self.assertIn("💬 Pas de PR", api.made("POST", "/issues/7/comments")[0][2]["body"])
            self.assert_local_repo_untouched()

    def test_dependance_transitive_commentee(self):
        transitive = finding("e1e2e3e4e5e6", "System.Text.Encodings.Web", "4.7.1", "4.7.2", "api/packages.lock.json")
        _, _, report = self.run_cli(transitive, args=["--apply"])
        self.assertEqual(report["results"][0]["status"], "failed")
        self.assertIn("transitive", report["results"][0]["reason"])
        self.assertEqual(self.tools.commands, [])

    def test_pas_de_doublon(self):
        cases = {
            "PR déjà ouverte (#3)": [{"number": 3, "state": "open", "merged_at": None}],
            "fermé sans merge (#4)": [{"number": 4, "state": "closed", "merged_at": None}],
        }
        for expected, pulls in cases.items():
            api = FakeGitHub(existing_pulls=pulls)
            _, _, report = self.run_cli(NEWTONSOFT, args=["--apply"], api=api)
            self.assertEqual(report["results"][0]["status"], "skipped")
            self.assertIn(expected, report["results"][0]["reason"])
            self.assertEqual(api.made("POST", "/pulls"), [])
        self.assertEqual(self.remote_branches(), ["main"])

    def test_branche_de_correctif_deja_presente(self):
        git(self.repo, "push", "--quiet", "origin", "main:refs/heads/autofix/a90dea08ce76")
        _, _, report = self.run_cli(NEWTONSOFT, args=["--apply"])
        self.assertEqual(report["results"][0]["status"], "skipped")
        self.assertIn("existe déjà", report["results"][0]["reason"])

    def test_pr_non_creee_la_branche_est_retiree(self):
        _, _, report = self.run_cli(NEWTONSOFT, args=["--apply"], api=FakeGitHub(fail_create=True))
        self.assertEqual(report["results"][0]["status"], "failed")
        self.assertIn("GitHub a refusé la PR (HTTP 422)", report["results"][0]["reason"])
        self.assertNotIn("AUTOFIX_TOKEN", report["results"][0]["reason"])
        self.assertEqual(self.remote_branches(), ["main"])

    def test_pr_refusee_faute_de_droits_explique_quoi_faire(self):
        # Cas vu sur la PR #18 : GitHub Actions n'a pas le droit de créer des PR.
        _, _, report = self.run_cli(NEWTONSOFT, args=["--apply"], api=FakeGitHub(fail_create="HTTP 403"))
        reason = report["results"][0]["reason"]
        self.assertIn("HTTP 403", reason)
        self.assertIn("Allow GitHub Actions to create and approve pull requests", reason)
        self.assertIn("AUTOFIX_TOKEN", reason)
        self.assertEqual(self.remote_branches(), ["main"])

    def test_ne_se_corrige_pas_elle_meme(self):
        env = {**ENV, "GITHUB_HEAD_REF": "autofix/a90dea08ce76"}
        code, logs, report = self.run_cli(NEWTONSOFT, args=["--apply"], env=env)
        self.assertEqual((code, report["results"]), (0, []))
        self.assertEqual(self.api.made("POST", "/pulls"), [])

    def test_entree_malveillante_aucune_commande(self):
        attack = finding("aaaaaaaaaaa1", "lodash --registry=http://evil.example", "1.0.0", "1.0.1", "web/package-lock.json")
        _, _, report = self.run_cli(attack, args=["--apply"])
        self.assertEqual(report["results"], [])
        self.assertEqual(len(report["not_fixable"]), 1)
        self.assertEqual(self.tools.commands, [])
        self.assertEqual(self.remote_branches(), ["main"])

    # --- Entrées invalides --------------------------------------------------------------

    def test_apply_sans_token_ou_sans_branche(self):
        for env in ({"GITHUB_REPOSITORY": "o/r", "GITHUB_HEAD_REF": "main"}, {**ENV, "GITHUB_HEAD_REF": "-x"}, {**ENV, "GITHUB_REPOSITORY": "pas un repo"}):
            code, _, _ = self.run_cli(NEWTONSOFT, args=["--apply"], env=env)
            self.assertEqual(code, 2)
        self.assertEqual(self.remote_branches(), ["main"])

    def test_triage_absent(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(["--triage", str(self.tmp / "absent.json")], {})
        self.assertEqual(code, 2)
        self.assertTrue(all(row.startswith("[remediation] ") for row in output.getvalue().splitlines()))

    def test_token_de_remediation_prioritaire(self):
        self.run_cli(NEWTONSOFT, args=["--apply"], env={**ENV, "AUTOFIX_TOKEN": "jeton-du-bot"})
        self.assertEqual(self.api.headers["Authorization"], "Bearer jeton-du-bot")


class TexteTest(unittest.TestCase):
    def test_md_neutralise_le_contenu_non_fiable(self):
        self.assertEqual(md("a|b <img src=x> @octocat https://evil.example/x"), "a\\|b &lt;img src=x&gt; @​octocat (lien retiré)")


if __name__ == "__main__":
    unittest.main()

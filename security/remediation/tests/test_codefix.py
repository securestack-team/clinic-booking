import contextlib
import io
import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from .helpers import (
    AUTHZ, AUTHZ_LINE, CONTROLLER_FILE, GOOD_AUTHZ_PATCH, GOOD_SECRET_PATCH, GOOD_SQL_PATCH, HARDCODED, NEWTONSOFT,
    SERVICE_FILE, SQL_LINE, SQLI, FakeGitHub, FakeLLM, FakeTools, add_api_code, code_finding, fake_signing_key, git,
    make_repo, triage, write_triage,
)  # fmt: skip
from remediation import cli, codefix, llm
from remediation.fixers import CannotFix
from remediation.triage_input import select

ENV = {"GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": "jeton-de-test", "GITHUB_HEAD_REF": "main", "GEMINI_API_KEY": "cle-de-test"}
CONFIG = llm.LLMConfig(model="modele-de-test", api_key="cle-de-test")


def candidates_of(*findings):
    return codefix.select_code(triage(*findings), select(triage(*findings))[1])


class SelectionTest(unittest.TestCase):
    def test_trois_cas_geres(self):
        candidates, skipped = candidates_of(SQLI, AUTHZ, HARDCODED)
        self.assertEqual([(c.kind, c.line) for c in candidates], [("secret", 5), ("sql", SQL_LINE), ("authz", AUTHZ_LINE)])
        self.assertEqual(skipped, [])  # ils ne sont plus « hors périmètre »

    def test_findings_non_eligibles(self):
        others = [
            code_finding("000000000001", "CWE-79", CONTROLLER_FILE, 3),  # XSS : cas non géré
            code_finding("000000000002", "CWE-89", "web/src/api.ts", 3),  # pas du C# dans api/
            code_finding("000000000003", "CWE-89", "api/../.github/workflows/x.cs", 3),
            code_finding("000000000004", "CWE-89", CONTROLLER_FILE, 0),  # pas de ligne
            {"id": "000000000005", "category": "secret", "rules": ["aws-access-token"], "cwe": [], "file": "api/appsettings.json", "line": 3},
            code_finding("pas-un-id", "CWE-89", CONTROLLER_FILE, 3),
        ]
        candidates, skipped = candidates_of(*others)
        self.assertEqual(candidates, [])
        self.assertEqual(len(skipped), 6)

    def test_un_seul_patch_par_ligne(self):
        twin = code_finding("c0de00000009", "CWE-89", CONTROLLER_FILE, SQL_LINE, risk=5.0)
        self.assertEqual(len(candidates_of(SQLI, twin)[0]), 1)


class AvecRepoTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.repo, self.remote = make_repo(self.tmp)
        add_api_code(self.repo)
        (self.sql, self.authz), _ = candidates_of(SQLI, AUTHZ)
        self.secret = candidates_of(HARDCODED)[0][0]


class PromptTest(AvecRepoTest):
    def test_extrait_numerote_autour_de_la_ligne(self):
        prompt, first, last = codefix.build_prompt(self.repo, self.sql)
        self.assertEqual((first, last), (SQL_LINE - codefix.CONTEXT_LINES, 27))
        self.assertIn(f"   {SQL_LINE}|         var rows = _db.Appointments.FromSqlRaw(", prompt)
        self.assertIn("CWE-89 à la ligne 17", prompt)
        self.assertIn("requête paramétrée", prompt)
        self.assertIn("using Microsoft.AspNetCore.Mvc; using Microsoft.EntityFrameworkCore;", prompt)

    def test_secret_en_dur_aucune_chaine_envoyee(self):
        prompt, _, _ = codefix.build_prompt(self.repo, self.secret)
        self.assertNotIn(fake_signing_key(), prompt)
        self.assertNotIn("clinic-booking", prompt)  # même les chaînes voisines sont effacées
        self.assertIn('SigningKey = "[MASQUÉ]"', prompt)

    def test_secrets_masques_dans_le_code_voisin(self):
        path = self.repo / CONTROLLER_FILE
        password = "Sup3r" + "-Mot-De-Passe!"
        path.write_text(path.read_text(encoding="utf-8").replace("    private readonly AppDbContext _db;", f'    private string cs = "Host=db;Password={password}";'), encoding="utf-8")
        self.assertNotIn(password, codefix.build_prompt(self.repo, self.sql)[0])

    def test_ligne_inexistante(self):
        self.sql.line = 999
        with self.assertRaises(CannotFix):
            codefix.build_prompt(self.repo, self.sql)


class ControleDuPatchTest(AvecRepoTest):
    def check(self, candidate, **changes):
        base = {"sql": GOOD_SQL_PATCH, "authz": GOOD_AUTHZ_PATCH, "secret": GOOD_SECRET_PATCH}[candidate.kind]
        patch = llm.parse_patch(json.dumps({**base, **changes}))
        original = (self.repo / candidate.file).read_text(encoding="utf-8").splitlines()
        _, first, last = codefix.build_prompt(self.repo, candidate)
        codefix.check_patch(candidate, patch, original, first, last)

    def test_bons_patchs_acceptes(self):
        for candidate in (self.sql, self.authz, self.secret):
            self.check(candidate)
        # nom complet de l'attribut : nécessaire quand le fichier n'a pas le bon using
        self.check(self.authz, replacement="    [Microsoft.AspNetCore.Authorization.Authorize]\n    public IActionResult Delete(int id)")

    def test_patchs_refuses(self):
        refused = {
            "aucun correctif": (self.sql, {"replacement": "   "}),
            "autre ligne": (self.sql, {"start_line": 24, "end_line": 24}),
            "hors de l'extrait": (self.sql, {"start_line": 1, "end_line": SQL_LINE}),
            "trop de lignes remplacées": (self.authz, {"start_line": 10, "end_line": 26}),
            "trop long": (self.sql, {"replacement": "// x\n" * 40}),
            "contenu masqué recopié": (self.sql, {"replacement": 'var cs = "[MASQUÉ]";'}),
            "nouveau secret": (self.sql, {"replacement": 'var k = "' + "AKIA" + "QWERTYUIOPASDFGH" + '";'}),
            "rien ne change": (self.sql, {"replacement": CONTROLLER_LINE_17()}),
            "toujours concaténé": (self.sql, {"replacement": '        var rows = _db.Appointments.FromSqlRaw("SELECT 1 WHERE a = \'" + name + "\'");'}),
            "toujours concaténé (interpolation)": (self.sql, {"replacement": '        var rows = _db.Appointments.FromSqlRaw($"SELECT 1 WHERE a = \'{name}\'");'}),
            "pas de [Authorize]": (self.authz, {"replacement": "    public IActionResult Delete(int id) // ok"}),
            "[AllowAnonymous] ajouté": (self.authz, {"replacement": "    [Authorize]\n    [AllowAnonymous]\n    public IActionResult Delete(int id)"}),
            "[AllowAnonymous] en nom complet": (self.authz, {"replacement": "    [Authorize]\n    [Microsoft.AspNetCore.Authorization.AllowAnonymous]\n    public IActionResult Delete(int id)"}),
            "attribut qui ressemble": (self.authz, {"replacement": "    [AuthorizeNothing]\n    public IActionResult Delete(int id)"}),
            "valeur en dur gardée": (self.secret, {"replacement": f'    private static string SigningKey => Env("JWT") ?? "{fake_signing_key()}";'}),
        }
        for name, (candidate, changes) in refused.items():
            with self.assertRaises(CannotFix, msg=name):
                self.check(candidate, **changes)

    def test_reponses_du_llm_inutilisables(self):
        for text in ("OK", "[]", "{}", '{"start_line": "17", "end_line": 17, "replacement": "x", "explanation": "y"}',
                     '{"start_line": true, "end_line": 17, "replacement": "x", "explanation": "y"}',
                     '{"start_line": 17, "end_line": 17, "replacement": "x", "explanation": "y", "commande": "rm -rf /"}'):
            with self.assertRaises(llm.LLMError, msg=text):
                llm.parse_patch(text)
        self.assertEqual(llm.parse_patch("```json\n" + json.dumps(GOOD_SQL_PATCH) + "\n```").start_line, SQL_LINE)

    def test_application_du_patch(self):
        codefix.prepare(self.repo, self.authz, CONFIG, FakeLLM(GOOD_AUTHZ_PATCH))
        lines = (self.repo / CONTROLLER_FILE).read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[AUTHZ_LINE - 1 : AUTHZ_LINE + 1], ['    [Authorize(Roles = "Admin")]', "    public IActionResult Delete(int id)"])
        self.assertEqual(len(lines), 28)  # une ligne de plus, le reste intact
        self.assertEqual(lines[16], '        var rows = _db.Appointments.FromSqlRaw("SELECT * FROM Appointments WHERE PatientName = \'" + name + "\'");')

    def test_compilation(self):
        codefix.validate_build(self.repo, self.sql, FakeTools())
        with self.assertRaises(CannotFix) as caught:
            codefix.validate_build(self.repo, self.sql, FakeTools(build_exit_code=1))
        self.assertIn("ne compile pas", str(caught.exception))
        self.assertIn("CS0246", str(caught.exception))
        self.assertNotIn("Authorize", str(caught.exception))  # seul le numéro d'erreur est gardé
        (self.repo / "api/Api.csproj").unlink()
        with self.assertRaises(CannotFix):
            codefix.validate_build(self.repo, self.sql, FakeTools())


def CONTROLLER_LINE_17() -> str:
    from .helpers import CONTROLLER

    return CONTROLLER.splitlines()[SQL_LINE - 1]


class BoutEnBoutTest(AvecRepoTest):
    def run_cli(self, *findings, args=("--apply",), env=None, tools=None, api=None, fake_llm=None):
        self.tools = tools or FakeTools()
        self.api = api or FakeGitHub()
        self.llm = fake_llm or FakeLLM(GOOD_SQL_PATCH)
        argv = ["--triage", str(write_triage(self.tmp, *findings)), "--output", str(self.tmp / "out"), "--repo-root", str(self.repo), *args]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(argv, dict(ENV if env is None else env), self.tools, self.api, self.llm)
        return code, output.getvalue(), json.loads((self.tmp / "out" / "remediation.json").read_text(encoding="utf-8"))

    def remote_branches(self):
        return git(self.remote, "for-each-ref", "--format=%(refname:short)", "refs/heads").split()

    def test_patch_sql_valide_ouvre_une_pr(self):
        code, logs, report = self.run_cli(SQLI)
        result = report["results"][0]
        self.assertEqual((code, result["status"], result["kind"], result["branch"]), (0, "opened", "code", "autofix/c0de00000001"))
        self.assertEqual(git(self.remote, "diff", "--name-only", "main", "autofix/c0de00000001").split(), [CONTROLLER_FILE])
        self.assertIn("FromSqlInterpolated", git(self.remote, "show", f"autofix/c0de00000001:{CONTROLLER_FILE}"))
        self.assertEqual(git(self.remote, "diff", "--shortstat", "main", "autofix/c0de00000001"), "1 file changed, 1 insertion(+), 1 deletion(-)")
        self.assertIn(["dotnet", "build", "--nologo"], self.tools.commands)

        (_, _, pull), = self.api.made("POST", "/repos/o/r/pulls")
        self.assertEqual(pull["title"], "fix: use a parameterized query in AppointmentsController.cs")
        self.assertIn("écrit par un LLM", pull["body"])
        self.assertIn("jamais mergée automatiquement", pull["body"])
        self.assertEqual(self.api.made("POST", "/issues/12/labels")[0][2], {"labels": ["ai-autofix"]})
        self.assertNotIn("cle-de-test", logs)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_secret_en_dur_pr_avec_rappel_de_revocation(self):
        _, _, report = self.run_cli(HARDCODED, fake_llm=FakeLLM(GOOD_SECRET_PATCH))
        self.assertEqual(report["results"][0]["status"], "opened")
        self.assertNotIn(fake_signing_key(), "\n".join(self.llm.prompts))
        self.assertNotIn(fake_signing_key(), git(self.remote, "show", f"autofix/c0de00000003:{SERVICE_FILE}"))
        self.assertIn("révoqué", self.api.made("POST", "/pulls")[0][2]["body"])

    def test_patch_non_valide_pas_de_pr(self):
        cases = {
            "ne compile pas": dict(tools=FakeTools(build_exit_code=1)),
            "toujours concaténé": dict(fake_llm=FakeLLM({**GOOD_SQL_PATCH, "replacement": 'x.FromSqlRaw("a" + name);'})),
            "pas sur la ligne signalée": dict(fake_llm=FakeLLM({**GOOD_SQL_PATCH, "start_line": 24, "end_line": 24})),
            "LLM injoignable": dict(fake_llm=FakeLLM(llm.LLMError("LLM injoignable (HTTP 503)"))),
            "pas du JSON": dict(fake_llm=FakeLLM("Voici le correctif : ...")),
            "hors du fichier": dict(tools=FakeTools(extra_file=".github/workflows/ci.yml")),
        }
        for name, options in cases.items():
            with unittest.mock.patch("time.sleep"):
                _, _, report = self.run_cli(SQLI, **options)
            self.assertEqual(report["results"][0]["status"], "failed", name)
            self.assertEqual(self.remote_branches(), ["main"], name)
            self.assertEqual(self.api.made("POST", "/pulls"), [], name)
            self.assertEqual(git(self.repo, "status", "--porcelain"), "", name)

    def test_sans_cle_pas_d_appel_au_llm(self):
        env = {k: v for k, v in ENV.items() if k != "GEMINI_API_KEY"}
        for args, e in ((("--apply",), env), (("--apply", "--no-llm"), ENV)):
            _, _, report = self.run_cli(SQLI, NEWTONSOFT, args=args, env=e)
            self.assertEqual([r["kind"] for r in report["results"]], ["dependency"])
            self.assertEqual(self.llm.prompts, [])
            self.assertEqual(report["not_fixable"][0]["id"], "c0de00000001")
            git(self.remote, "update-ref", "-d", "refs/heads/autofix/a90dea08ce76")

    def test_simulation_n_appelle_pas_le_llm(self):
        _, _, report = self.run_cli(SQLI, args=())
        self.assertEqual((report["results"][0]["status"], report["results"][0]["kind"]), ("planned", "code"))
        self.assertEqual(self.llm.prompts, [])
        self.assertEqual(self.remote_branches(), ["main"])

    def test_limite_de_pr_commune_et_dependances_d_abord(self):
        _, _, report = self.run_cli(SQLI, NEWTONSOFT, args=("--apply", "--max-prs", "1"))
        self.assertEqual([(r["kind"], r["status"]) for r in report["results"]], [("dependency", "opened"), ("code", "skipped")])
        self.assertEqual(self.llm.prompts, [])  # pas d'appel au LLM pour un correctif qui ne sera pas publié

    def test_synthese_avec_un_patch_de_code(self):
        env = {**ENV, "GITHUB_REF": "refs/pull/7/merge"}
        self.run_cli(SQLI, AUTHZ, env=env, fake_llm=FakeLLM(GOOD_SQL_PATCH, {**GOOD_AUTHZ_PATCH, "replacement": "    public IActionResult Delete(int id) // rien"}))
        body = self.api.made("POST", "/issues/7/comments")[0][2]["body"]
        self.assertIn("✅ PR ouverte | Patch LLM : use a parameterized query", body)
        self.assertIn("💬 Pas de PR | Patch LLM : add missing authorization", body)
        self.assertIn("n'ajoute pas \\[Authorize\\]", body)


if __name__ == "__main__":
    unittest.main()

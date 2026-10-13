"""Outils partagés par les tests : faux repo Git, faux dotnet/npm, fausse API GitHub."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog" Version="3.0.0" />
  </ItemGroup>
</Project>
"""

NUGET_LOCK = {
    "version": 1,
    "dependencies": {
        "net10.0": {
            "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1"},
            "Serilog": {"type": "Direct", "requested": "[3.0.0, )", "resolved": "3.0.0"},
            "System.Text.Encodings.Web": {"type": "Transitive", "resolved": "4.7.1"},
        }
    },
}

PACKAGE_JSON = {"name": "web", "version": "0.1.0", "dependencies": {"lodash": "^4.17.20"}, "devDependencies": {"vite": "^5.0.0"}}

NPM_LOCK = {
    "name": "web",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "web", "dependencies": {"lodash": "^4.17.20"}},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/minimist": {"version": "1.2.5"},
    },
}


def git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
    )  # fmt: skip
    return done.stdout.strip()


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def make_repo(tmp: Path) -> tuple[Path, Path]:
    """Crée un remote « origin » (bare) et un clone avec une API .NET et un site web vulnérables."""
    remote = tmp / "origin.git"
    repo = tmp / "repo"
    subprocess.run(["git", "init", "--quiet", "--bare", "-b", "main", str(remote)], check=True)
    subprocess.run(["git", "clone", "--quiet", str(remote), str(repo)], check=True, capture_output=True)
    for folder in ("api", "web", ".github/workflows", "infra/terraform"):
        (repo / folder).mkdir(parents=True)
    (repo / "api/Api.csproj").write_text(CSPROJ, encoding="utf-8")
    write_json(repo / "api/packages.lock.json", NUGET_LOCK)
    write_json(repo / "web/package.json", PACKAGE_JSON)
    write_json(repo / "web/package-lock.json", NPM_LOCK)
    (repo / ".github/workflows/ci.yml").write_text("name: CI\n", encoding="utf-8")
    (repo / "infra/terraform/main.tf").write_text("# infra\n", encoding="utf-8")
    git(repo, "checkout", "--quiet", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "chore: initial")
    git(repo, "push", "--quiet", "origin", "main")
    return repo, remote


def finding(finding_id: str, package: str, installed: str, fixed: str, file: str, risk: float = 7.5, advisory: str = "CVE-2024-21907", **extra) -> dict:
    return {
        "id": finding_id,
        "category": "dependency",
        "severity": "high",
        "risk_score": risk,
        "rules": [advisory],
        "file": file,
        "line": 5,
        "package": {"name": package, "installed_version": installed, "fixed_version": fixed, "advisory": advisory},
        "recommendation": f"Mettre à jour {package} vers la version {fixed}.",
        **extra,
    }


NEWTONSOFT = finding("a90dea08ce76", "Newtonsoft.Json", "12.0.1", "13.0.1", "api/packages.lock.json")
LODASH = finding("b1b2b3b4b5b6", "lodash", "4.17.20", "4.17.21", "web/package-lock.json", risk=6.0, advisory="CVE-2021-23337")


def triage(*findings: dict) -> dict:
    return {"schema_version": "1.0", "findings": list(findings)}


def write_triage(tmp: Path, *findings: dict) -> Path:
    path = tmp / "triage.json"
    write_json(path, triage(*findings))
    return path


class FakeTools:
    """Remplace dotnet et npm : fait ce que ferait le vrai outil sur le lockfile."""

    def __init__(self, exit_code: int = 0, update_lock: bool = True, extra_file: str | None = None, build_exit_code: int = 0):
        self.exit_code = exit_code
        self.update_lock = update_lock
        self.extra_file = extra_file  # fichier modifié « en douce » par l'outil
        self.build_exit_code = build_exit_code  # résultat de « dotnet build » (v2)
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], cwd: Path) -> tuple[int, str]:
        self.commands.append(command)
        if command[:2] == ["dotnet", "build"] and self.build_exit_code:
            return self.build_exit_code, "Controllers/X.cs(22,6): error CS0246: The type or namespace name 'Authorize' could not be found"
        if self.exit_code:
            return self.exit_code, "erreur simulée"
        if self.extra_file:
            target = _worktree_root(cwd) / self.extra_file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("modifié par l'outil\n", encoding="utf-8")
        if self.update_lock and command[0] == "dotnet":
            self._dotnet_restore(cwd)
        if self.update_lock and command[0] == "npm":
            self._npm_install(cwd, command[2])
        return 0, ""

    @staticmethod
    def _dotnet_restore(cwd: Path) -> None:
        lock_path = cwd / "packages.lock.json"
        if not lock_path.exists():
            return
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        declared = {}
        for source in [*cwd.glob("*.csproj"), *[p / "Directory.Packages.props" for p in (cwd, *cwd.parents)][:4]]:
            if source.is_file():
                declared.update(re.findall(r'Include="([^"]+)" Version="([^"]+)"', source.read_text(encoding="utf-8")))
        for framework in lock["dependencies"].values():
            for name, entry in framework.items():
                if name in declared:
                    entry["resolved"] = declared[name]
                    entry["requested"] = f"[{declared[name]}, )"
        write_json(lock_path, lock)

    @staticmethod
    def _npm_install(cwd: Path, spec: str) -> None:
        name, _, version = spec.rpartition("@")
        package_json = json.loads((cwd / "package.json").read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies"):
            if name in package_json.get(section, {}):
                package_json[section][name] = f"^{version}"
        write_json(cwd / "package.json", package_json)
        lock = json.loads((cwd / "package-lock.json").read_text(encoding="utf-8"))
        lock["packages"][""]["dependencies"][name] = f"^{version}"
        lock["packages"][f"node_modules/{name}"]["version"] = version
        write_json(cwd / "package-lock.json", lock)


def _worktree_root(cwd: Path) -> Path:
    return Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip())


class FakeGitHub:
    """Remplace l'API GitHub : enregistre les appels et répond comme elle."""

    def __init__(self, existing_pulls: list[dict] | None = None, fail_create: bool = False):
        self.existing_pulls = existing_pulls or []
        self.fail_create = fail_create
        self.calls: list[tuple[str, str, dict | None]] = []
        self.next_number = 12

    def __call__(self, method: str, url: str, headers: dict, body: dict | None = None, timeout: int = 30):
        from remediation.net import HttpError

        self.calls.append((method, url, body))
        self.headers = headers
        if method == "GET" and "/pulls?" in url:
            return self.existing_pulls
        if method == "GET" and "/comments" in url:
            return []
        if method == "POST" and url.endswith("/pulls"):
            if self.fail_create:
                raise HttpError("HTTP 422")
            number, self.next_number = self.next_number, self.next_number + 1
            return {"number": number, "html_url": f"https://github.com/o/r/pull/{number}"}
        return {}

    def made(self, method: str, url_part: str) -> list[tuple]:
        return [call for call in self.calls if call[0] == method and url_part in call[1]]


# --- v2 : code de l'API et LLM simulé ---------------------------------------------------

CONTROLLER = """using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Api.Controllers;

[ApiController]
[Route("api/appointments")]
public class AppointmentsController : ControllerBase
{
    private readonly AppDbContext _db;

    public AppointmentsController(AppDbContext db) => _db = db;

    [HttpGet("search")]
    public IActionResult Search(string name)
    {
        var rows = _db.Appointments.FromSqlRaw("SELECT * FROM Appointments WHERE PatientName = '" + name + "'");
        return Ok(rows);
    }

    [HttpDelete("{id}")]
    public IActionResult Delete(int id)
    {
        _db.Appointments.Remove(_db.Appointments.Find(id)!);
        return NoContent();
    }
}
"""
SQL_LINE, AUTHZ_LINE, SECRET_LINE = 17, 22, 5
CONTROLLER_FILE = "api/Controllers/AppointmentsController.cs"
SERVICE_FILE = "api/Services/TokenService.cs"


def fake_signing_key() -> str:
    """Fausse valeur fabriquée à l'exécution : écrite d'un seul tenant ici, elle ferait réagir Gitleaks."""
    return "clinic-" + "signing-key-" + "2026-demo"


def add_api_code(repo: Path) -> None:
    """Ajoute au faux repo un contrôleur vulnérable et un service avec un secret en dur, puis pousse."""
    (repo / "api/Controllers").mkdir()
    (repo / "api/Services").mkdir()
    (repo / CONTROLLER_FILE).write_text(CONTROLLER, encoding="utf-8")
    (repo / SERVICE_FILE).write_text(
        "namespace Api.Services;\n\npublic class TokenService\n{\n"
        f'    private const string SigningKey = "{fake_signing_key()}";\n'
        '    private const string Issuer = "clinic-booking";\n}\n',
        encoding="utf-8",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "feat: api code")
    git(repo, "push", "--quiet", "origin", "main")


def code_finding(finding_id: str, cwe: str, file: str, line: int, category: str = "code", risk: float = 8.8, rule: str = "cs/regle") -> dict:
    return {"id": finding_id, "category": category, "severity": "high", "risk_score": risk, "rules": [rule], "cwe": [cwe], "file": file, "line": line, "recommendation": "Corriger."}


SQLI = code_finding("c0de00000001", "CWE-89", CONTROLLER_FILE, SQL_LINE, rule="cs/sql-injection")
AUTHZ = code_finding("c0de00000002", "CWE-862", CONTROLLER_FILE, AUTHZ_LINE, risk=7.0, rule="cs/missing-authorization")
HARDCODED = code_finding("c0de00000003", "CWE-798", SERVICE_FILE, SECRET_LINE, category="secret", risk=9.5, rule="cs/hardcoded-credentials")

GOOD_SQL_PATCH = {
    "start_line": SQL_LINE,
    "end_line": SQL_LINE,
    "replacement": '        var rows = _db.Appointments.FromSqlInterpolated($"SELECT * FROM Appointments WHERE PatientName = {name}");',
    "explanation": "La valeur est passée en paramètre au lieu d'être concaténée.",
}
GOOD_AUTHZ_PATCH = {
    "start_line": AUTHZ_LINE,
    "end_line": AUTHZ_LINE,
    "replacement": '    [Authorize(Roles = "Admin")]\n    public IActionResult Delete(int id)',
    "explanation": "L'endpoint de suppression exige maintenant un utilisateur authentifié.",
}
GOOD_SECRET_PATCH = {
    "start_line": SECRET_LINE,
    "end_line": SECRET_LINE,
    "replacement": '    private static string SigningKey => Environment.GetEnvironmentVariable("JWT_SIGNING_KEY") ?? throw new InvalidOperationException();',
    "explanation": "La clé est lue depuis l'environnement.",
}


class FakeLLM:
    """Remplace Gemini : enregistre les prompts, renvoie les réponses prévues (une par appel)."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts: list[str] = []

    def __call__(self, config, system, user):
        self.prompts.append(user)
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply if isinstance(reply, str) else json.dumps(reply)

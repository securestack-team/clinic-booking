import os
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from remediation import sandbox
from remediation.fixers import CannotFix
from remediation.guardrails import GuardrailError
from .helpers import make_repo


class SandboxFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / "repo"
        self.source = Path(self.tmp.name) / "sandbox"
        self.target.mkdir()
        (self.target / "Api.csproj").write_text("original")
        (self.target / "Program.cs").write_text("source original")
        (self.target / "infra").mkdir()
        (self.target / "infra/main.tf").write_text("infrastructure")
        shutil.copytree(self.target, self.source)
        self.before = sandbox.inventory(self.source)

    def test_only_dependency_changes_return_and_build_outputs_do_not(self):
        (self.source / "Api.csproj").write_text("updated dependency")
        (self.source / "packages.lock.json").write_text("{}")
        (self.source / "obj").mkdir()
        (self.source / "obj/generated.txt").write_text("build artifact")
        sandbox.copy_back(self.source, self.target, self.before)
        self.assertEqual((self.target / "Api.csproj").read_text(), "updated dependency")
        self.assertTrue((self.target / "packages.lock.json").is_file())
        self.assertFalse((self.target / "obj").exists())

    def test_forbidden_change_rejects_everything_before_copying(self):
        (self.source / "Api.csproj").write_text("updated dependency")
        (self.source / "infra/main.tf").write_text("unexpected change")
        with self.assertRaises(GuardrailError):
            sandbox.copy_back(self.source, self.target, self.before)
        self.assertEqual((self.target / "Api.csproj").read_text(), "original")
        self.assertEqual((self.target / "infra/main.tf").read_text(), "infrastructure")

    def test_tool_cannot_change_csharp_source_during_build(self):
        (self.source / "Program.cs").write_text("unexpected change")
        with self.assertRaises(GuardrailError):
            sandbox.copy_back(self.source, self.target, self.before)
        self.assertEqual((self.target / "Program.cs").read_text(), "source original")

    def test_deleted_source_is_rejected(self):
        (self.source / "Program.cs").unlink()
        with self.assertRaises(CannotFix):
            sandbox.copy_back(self.source, self.target, self.before)

    def test_symlink_cannot_read_or_overwrite_host_file(self):
        outside = Path(self.tmp.name) / "outside"
        outside.write_text("private marker")
        (self.source / "Api.csproj").unlink()
        (self.source / "Api.csproj").symlink_to(outside)
        with self.assertRaises(CannotFix):
            sandbox.copy_back(self.source, self.target, self.before)
        self.assertEqual(outside.read_text(), "private marker")
        self.assertEqual((self.target / "Api.csproj").read_text(), "original")

    def test_fifo_is_rejected_without_opening_it(self):
        os.mkfifo(self.source / "packages.lock.json")
        with self.assertRaises(CannotFix):
            sandbox.copy_back(self.source, self.target, self.before)


class SandboxRunnerTest(unittest.TestCase):
    def test_docker_failure_never_falls_back_to_host_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = make_repo(Path(tmp))
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(argv[0], "docker")
                self.assertNotIn("AUTOFIX_TOKEN", kwargs["env"])
                self.assertNotIn("GEMINI_API_KEY", kwargs["env"])
                if argv[1] == "run":
                    raise FileNotFoundError("docker unavailable")
                return subprocess.CompletedProcess(argv, 0)

            with patch.dict(os.environ, {"AUTOFIX_TOKEN": "fake", "GEMINI_API_KEY": "fake"}):
                with patch.object(sandbox.subprocess, "run", side_effect=run):
                    # check_output utilise aussi subprocess.run : fournir seulement la racine Git.
                    with patch.object(sandbox.subprocess, "check_output", return_value=str(repo)):
                        with self.assertRaises(CannotFix):
                            sandbox.run_tool(["dotnet", "restore"], repo)
            self.assertEqual(len(calls), 2)  # lancement et nettoyage, jamais dotnet sur l'hôte

    def test_arbitrary_host_command_is_rejected(self):
        with self.assertRaises(CannotFix):
            sandbox.run_tool(["sh", "-c", "echo unexpected"], Path("."))


@unittest.skipUnless(os.environ.get("RUN_SANDBOX_DOCKER_TESTS") == "1", "Docker adversarial test opt-in")
class DockerBoundaryTest(unittest.TestCase):
    def test_build_cannot_read_runner_credentials_or_socket_and_lockfile_returns(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo, _ = make_repo(base)
            outside = base / "runner-credentials"
            outside.write_text("FAKE-PUBLICATION-CREDENTIAL")
            image = "clinic-sandbox-test:" + uuid.uuid4().hex
            image_root = base / "image"
            image_root.mkdir()
            (image_root / "Dockerfile").write_text(
                "FROM alpine@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11\n"
                "COPY probe /usr/local/bin/dotnet\n"
            )
            (image_root / "probe").write_text(
                "#!/bin/sh\nset -eu\n"
                "test -z \"${AUTOFIX_TOKEN:-}\"\n"
                "test -z \"${GEMINI_API_KEY:-}\"\n"
                f"test ! -e '{outside}'\n"
                "test ! -e /workspace/.git\n"
                "test ! -e /var/run/docker.sock\n"
                "test -z \"${RUNNER_TEMP:-}\"\n"
                "if touch /etc/should-not-write 2>/dev/null; then exit 9; fi\n"
                "echo '{}' > packages.lock.json\n"
                "echo runner-credentials-inaccessible\n"
            )
            (image_root / "probe").chmod(0o755)
            try:
                subprocess.run(
                    ["docker", "build", "--network=none", "-t", image, str(image_root)],
                    check=True, capture_output=True, timeout=90,
                )
                with patch.dict(sandbox.IMAGES, {"dotnet": image}):
                    with patch.dict(os.environ, {
                        "AUTOFIX_TOKEN": "FAKE-PUBLICATION-CREDENTIAL",
                        "GEMINI_API_KEY": "FAKE-LLM-CREDENTIAL", "RUNNER_TEMP": str(base),
                    }):
                        code, output = sandbox.run_tool(["dotnet", "restore"], repo / "api")
                self.assertEqual(code, 0, output)
                self.assertIn("runner-credentials-inaccessible", output)
                self.assertEqual((repo / "api/packages.lock.json").read_text().strip(), "{}")
                self.assertEqual(outside.read_text(), "FAKE-PUBLICATION-CREDENTIAL")
            finally:
                subprocess.run(["docker", "image", "rm", "-f", image], capture_output=True, timeout=30)

"""Tests for the secure-code secret scanner and git hook installer.

Run from the plugin root:  python -m unittest discover -s tests -v
Fake secrets are assembled at runtime, so this file never contains a literal secret.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills" / "secure-code" / "scripts"))

import install_git_hook as inst  # noqa: E402
import scan_secrets as s  # noqa: E402

GH = "ghp_" + "A1b2C3d4E5" * 4
ANT = "sk-" + "ant-api03-" + "Xy7_Qw9-Lm" * 3
PRIV = "-----BEGIN " + "RSA PRIVATE KEY-----"
PW = "Hunter2" + "Pass9"


def rules(text: str, config: bool = False) -> list[str]:
    return [r for r, _ in s.scan_line(text, config)]


class ScanLineTests(unittest.TestCase):
    def test_detects_token_formats(self) -> None:
        cases = [(f'token = "{GH}"', "github-token"), (f"key={ANT}", "anthropic-api-key"), (PRIV, "private-key")]
        for text, rule in cases:
            with self.subTest(rule=rule):
                self.assertEqual(rules(text), [rule])

    def test_anthropic_key_is_not_also_reported_as_openai(self) -> None:
        self.assertNotIn("openai-api-key", rules(ANT))

    def test_generic_assignment_in_python_js_json(self) -> None:
        for text in (f'DB_PASSWORD = "{PW}"', f'"apiKey": "{PW}"', f'api_key: str = "{PW}"', f"const clientSecret = '{PW}'"):
            with self.subTest(text=text):
                self.assertEqual(rules(text), ["secret-assignment"])

    def test_placeholders_and_non_secret_names_are_ignored(self) -> None:
        for text in (
            'password = "<PASSWORD>"',
            'api_key = "your-api-key-here"',
            'secret = "${SECRET}"',
            f'password_hash = "{PW}"',
            'token = os.environ["TOKEN"]',
            'bypass = "something-long"',
            "",
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), [])

    def test_allow_pragma(self) -> None:
        self.assertEqual(rules(f'password = "{PW}"  # {s.ALLOW_PRAGMA}'), [])

    def test_connection_string(self) -> None:
        self.assertEqual(s.scan_line(f"postgres://app:{PW}@db:5432/x", False), [("connection-string-password", PW)])
        self.assertEqual(rules("postgres://app:<password>@db:5432/x"), [])

    def test_unquoted_value_only_in_config_files(self) -> None:
        self.assertEqual(rules(f"PASSWORD={PW}", config=True), ["config-secret"])
        self.assertEqual(rules(f"password = {PW}", config=False), [])

    def test_c_and_cpp_secrets(self) -> None:
        self.assertEqual(rules(f'#define API_KEY "{PW}"'), ["c-define-secret"])
        self.assertEqual(rules(f'#  define DB_PASSWORD L"{PW}"'), ["c-define-secret"])
        self.assertEqual(rules(f'static const char *password = "{PW}";'), ["secret-assignment"])
        self.assertEqual(rules(f'std::string token{{"{PW}"}};'), [])  # shortcut: brace-init not detected
        self.assertEqual(rules('#define TOKEN_LEN 32'), [])

    def test_powershell_plaintext_password(self) -> None:
        self.assertEqual(rules(f'ConvertTo-SecureString "{PW}" -AsPlainText -Force'), ["powershell-plaintext-password"])

    def test_detects_more_token_formats(self) -> None:
        b64 = "Ab3+Cd5/Ef7" * 8
        cases = [
            ("SG." + "aB3dE5gH7jK9mN1pQ3sT5v" + "." + "xY2" * 14 + "z", "sendgrid-key"),
            ("SK" + "0a1b2c3d" * 4, "twilio-key"),
            ("pypi-" + "AgEIcHlwaS5vcmc" + "Qw3Er5Ty7U" * 6, "pypi-token"),
            ("M" + "Tk4NjIyNDgzNDcxOTI1MjQ4" + "." + "GaBcDe" + "." + "xY2zW4vU6" * 3, "discord-bot-token"),
            ("AccountName=x;" + "AccountKey=" + b64[:86] + "==", "azure-storage-key"),
            ('"auth": "' + "dXNlcjpwYXNzd29yZDEyMw" + '=="', "docker-auth"),
            ("Authorization: " + "Bearer " + "aB3dE5gH7jK9mN1pQ3sT5v", "bearer-token"),
            (f"https://deploy:{PW}@example.org/repo.git", "connection-string-password"),
        ]
        for text, rule in cases:
            with self.subTest(rule=rule):
                self.assertEqual(rules(text), [rule])

    def test_new_rules_ignore_normal_code(self) -> None:
        for text in (
            'headers = {"Authorization": f"Bearer {token}"}',
            "Authorization: Bearer <ACCESS_TOKEN_GOES_HERE_1234>",
            "http://localhost:8080/path@x",
            "https://x-access-token:$GITHUB_TOKEN@github.com/o/r.git",
            "SKIP_ALL_THE_THINGS = 1",
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), [])

    def test_key_and_pass_style_names(self) -> None:
        for name in ("SECRET_KEY", "JWT_SECRET_KEY", "ENCRYPTION_KEY", "signingKey", "MASTER_KEY", "auth_key", "DB_PASS"):
            with self.subTest(name=name):
                self.assertEqual(rules(f'{name} = "{PW}"'), ["secret-assignment"])
        for text in (f'compass = "{PW}"', f'PRIMARY_KEY = "{PW}"', f'keyboard = "{PW}"', f'bypass = "{PW}"'):
            with self.subTest(text=text):
                self.assertEqual(rules(text), [])

    def test_literal_fallback_for_env_secret(self) -> None:
        for text in (
            f'os.environ.get("API_KEY", "{PW}")',
            f"os.getenv('DB_PASSWORD', default='{PW}')",
            f'config("SECRET_KEY", default="{PW}")',
            f'const k = process.env.API_KEY || "{PW}";',
            f"const t = import.meta.env.VITE_TOKEN ?? '{PW}'",
        ):
            with self.subTest(text=text):
                self.assertEqual(rules(text), ["env-default-secret"])
        for text in ('os.environ.get("API_KEY", "")', f'os.getenv("LOG_LEVEL", "{PW}")', 'process.env.API_KEY || ""'):
            with self.subTest(text=text):
                self.assertEqual(rules(text), [])

    def test_strict_mode_reports_a_pragma_that_hides_a_secret(self) -> None:
        self.assertEqual(rules(f'password = "{PW}"  # {s.ALLOW_PRAGMA}'), [])
        self.assertEqual(
            [r for r, _ in s.scan_line(f'password = "{PW}"  # {s.ALLOW_PRAGMA}', False, strict=True)], [s.EXCEPTION_RULE]
        )
        self.assertEqual(s.scan_line(f"Add the comment `{s.ALLOW_PRAGMA}` on the line.", False, strict=True), [])

    def test_mask_never_shows_more_than_four_chars(self) -> None:
        self.assertEqual(s.mask("abcdefgh"), "abcd***")
        self.assertEqual(s.mask("abcd"), "***")
        self.assertEqual(s.mask(""), "***")


class FileAndDiffTests(unittest.TestCase):
    def test_sensitive_file_names(self) -> None:
        for path, expected in (
            (".env", True), ("config/prod.env", True), (".env.local", True), (".env.example", False),
            ("id_ed25519", True), ("id_ed25519.pub", False), ("certs/server.key", True), ("src/app.py", False),
            (".git-credentials", True), ("putty/key.ppk", True), ("prod.tfvars", True), ("prod.tfvars.example", False),
            ("gcp-service-account.json", True), ("kubeconfig", True), (".htpasswd", True), (".aws/credentials", True),
            ("data/app.db", True), ("package.json", False),
        ):
            with self.subTest(path=path):
                self.assertEqual(s.is_sensitive_file(path), expected)

    def test_parse_diff_tracks_files_and_line_numbers(self) -> None:
        diff = "\n".join([
            "diff --git a/a.py b/a.py", "--- a/a.py", "+++ b/a.py", "@@ -0,0 +3,2 @@", "+first", "+++x",
            "diff --git a/gone.py b/gone.py", "--- a/gone.py", "+++ /dev/null", "@@ -1 +0,0 @@", "-old",
        ])
        self.assertEqual(list(s.parse_diff(diff)), [("", "a.py", 3, "first"), ("", "a.py", 4, "++x")])

    def test_parse_diff_empty(self) -> None:
        self.assertEqual(list(s.parse_diff("")), [])

    def test_commit_command_detection(self) -> None:
        def actions(command: str) -> list[tuple[str, str]]:
            return [(sub, repo.replace("\\", "/")) for sub, repo in s.guarded_git(command, "/r")]

        self.assertEqual(actions("git commit -m x"), [("commit", "/r")])
        self.assertEqual(actions("git add . && git commit -am 'x' && git push"), [("commit", "/r"), ("push", "/r")])
        self.assertEqual(actions("git -C sub commit -m x"), [("commit", "/r/sub")])
        self.assertEqual(actions("cd 'my app' && git commit -m x"), [("commit", "/r/my app")])
        self.assertEqual(actions("Set-Location sub; git push origin main"), [("push", "/r/sub")])
        self.assertEqual(actions("git status"), [])
        self.assertEqual(actions("git log --grep commit"), [])
        self.assertEqual(actions("/usr/bin/git push"), [("push", "/r")])
        self.assertEqual(actions('& "C:\\Program Files\\Git\\bin\\git.exe" commit -m x'), [("commit", "/r")])
        self.assertEqual(actions("git -p commit -m x"), [("commit", "/r")])
        self.assertEqual(actions("legit commit"), [])

    def test_allow_pragma_does_not_hide_secret_in_command_text(self) -> None:
        command = f"git commit -m '{s.ALLOW_PRAGMA} {GH}'"
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/nowhere"})
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(s.claude_hook(payload, lambda args, cwd: (_ for _ in ()).throw(OSError())), 2)

    def test_claude_hook_blocks_secret_in_command_text(self) -> None:
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": f"git commit -m 'use {GH}'"}, "cwd": "/nowhere"})
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(s.claude_hook(payload, lambda args, cwd: (_ for _ in ()).throw(OSError())), 2)
        self.assertNotIn(GH, err.getvalue())

    def test_hook_mode_blocks_when_the_scan_fails(self) -> None:
        def broken_git(args, cwd):  # type: ignore[no-untyped-def]
            if list(args) == ["rev-parse", "--is-inside-work-tree"]:
                return "true"
            raise subprocess.CalledProcessError(128, "git")

        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}, "cwd": "/r"})
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(s.main(["--claude-hook"], stdin_text=payload, git=broken_git), 2)
        self.assertIn("blocked", err.getvalue())

    def test_claude_hook_ignores_bad_input_and_other_tools(self) -> None:
        self.assertEqual(s.claude_hook("not json"), 0)
        self.assertEqual(s.claude_hook(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "x"}})), 0)

    def test_claude_hook_uses_injected_git(self) -> None:
        calls: list[list[str]] = []

        def fake_git(args, cwd):  # type: ignore[no-untyped-def]
            calls.append(list(args))
            raise subprocess.CalledProcessError(128, "git")

        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}, "cwd": "/nowhere"})
        self.assertEqual(s.claude_hook(payload, fake_git), 0)
        self.assertEqual(calls, [["rev-parse", "--is-inside-work-tree"]])


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class GitIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(["git", *args], cwd=self.repo, capture_output=True, check=True)

    def write(self, rel: str, text: str) -> None:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def quiet_main(self, *argv: str, stdin_text: str | None = None) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return s.main(list(argv), stdin_text=stdin_text)

    def hook_payload(self, command: str) -> str:
        return json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(self.repo)})

    def test_staged_secret_is_found_with_line_number(self) -> None:
        self.write("app.py", f'print("hi")\nAPI_KEY = "{GH}"\n')
        self.git("add", "app.py")
        self.assertEqual(s.scan_staged(str(self.repo)), [s.Finding("app.py", 2, "github-token", GH[:4] + "***")])
        self.assertEqual(self.quiet_main("--staged", str(self.repo)), 1)

    def test_clean_staged_change_passes(self) -> None:
        self.write("app.py", 'print("hi")\n')
        self.git("add", "app.py")
        self.assertEqual(self.quiet_main("--staged", str(self.repo)), 0)

    def test_staged_env_file_is_blocked_by_name(self) -> None:
        self.write(".env", "DEBUG=1\n")
        self.git("add", ".env")
        self.assertEqual([f.rule for f in s.scan_staged(str(self.repo))], ["sensitive-file"])

    def test_claude_hook_blocks_untracked_secret_in_repo_without_commits(self) -> None:
        self.write("config.py", f'password = "{PW}"\n')
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = s.claude_hook(self.hook_payload("git add . && git commit -m x"))
        self.assertEqual(code, 2)
        self.assertIn("config.py:1", err.getvalue())
        self.assertNotIn(PW, err.getvalue())

    def test_claude_hook_blocks_unstaged_change_to_tracked_file(self) -> None:
        self.write("app.py", 'print("hi")\n')
        self.git("add", "app.py")
        self.git("commit", "-q", "-m", "init")
        self.write("app.py", f'print("hi")\ntoken = "{GH}"\n')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(s.claude_hook(self.hook_payload("git commit -am update")), 2)

    def test_claude_hook_allows_non_commit_and_clean_commit(self) -> None:
        self.write("config.py", f'password = "{PW}"\n')
        self.assertEqual(s.claude_hook(self.hook_payload("git status")), 0)
        (self.repo / "config.py").write_text('password = os.environ["PW"]\n', encoding="utf-8")
        self.assertEqual(s.claude_hook(self.hook_payload("git commit -m x")), 0)

    def test_claude_hook_follows_cd_to_another_repo(self) -> None:
        self.write("config.py", f'password = "{PW}"\n')
        with tempfile.TemporaryDirectory() as elsewhere:
            command = f'cd "{self.repo.as_posix()}" && git add . && git commit -m x'
            payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": elsewhere})
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(s.claude_hook(payload), 2)

    def test_claude_hook_blocks_push_of_committed_secret(self) -> None:
        self.assertEqual(s.claude_hook(self.hook_payload("git push")), 0)  # no commits yet
        self.write("app.py", f'token = "{GH}"\n')
        self.git("add", "app.py")
        self.git("commit", "-q", "-m", "add")
        self.write("app.py", 'token = os.environ["T"]\n')
        self.git("commit", "-q", "-am", "remove")
        self.assertEqual(s.claude_hook(self.hook_payload("git commit -m x")), 0)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(s.claude_hook(self.hook_payload("git push origin HEAD")), 2)
        self.assertIn("app.py:1", err.getvalue())

    def test_utf16_file_is_scanned_in_tree_and_staged(self) -> None:
        # Windows PowerShell 5.1 writes UTF-16 with `>`; git shows such a file as binary.
        (self.repo / "conf.ps1").write_text(f'$password = "{PW}"\n', encoding="utf-16")
        self.assertEqual([(f.path, f.rule) for f in s.scan_tree(str(self.repo))], [("conf.ps1", "secret-assignment")])
        self.git("add", "conf.ps1")
        self.assertEqual([(f.path, f.rule) for f in s.scan_staged(str(self.repo))], [("conf.ps1", "secret-assignment")])

    def test_claude_hook_blocks_new_scan_exceptions_but_git_hook_allows_them(self) -> None:
        self.write("app.py", f'password = "{PW}"  # {s.ALLOW_PRAGMA}\n')
        self.git("add", "app.py")
        self.assertEqual(s.scan_staged(str(self.repo)), [])  # the user's own commit from a terminal passes
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(s.claude_hook(self.hook_payload("git commit -m x")), 2)
        self.assertIn(s.EXCEPTION_RULE, err.getvalue())
        self.git("commit", "-q", "-m", "user approved")
        self.assertEqual(s.claude_hook(self.hook_payload("git commit -m x")), 0)  # an old exception does not block
        self.write(s.IGNORE_FILE, "fixtures/*\n")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(s.claude_hook(self.hook_payload("git add . && git commit -m x")), 2)
        self.assertIn(s.IGNORE_FILE, err.getvalue())

    def test_push_check_covers_detached_head_and_tags(self) -> None:
        self.write("a.txt", "x\n")
        self.git("add", "a.txt")
        self.git("commit", "-q", "-m", "init")
        self.git("remote", "add", "origin", self.repo.as_uri())
        self.git("fetch", "-q", "origin")
        self.git("checkout", "-q", "--detach")
        self.write("app.py", f'token = "{GH}"\n')
        self.git("add", "app.py")
        self.git("commit", "-q", "-m", "detached")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(s.claude_hook(self.hook_payload("git push origin HEAD:main")), 2)
        self.git("tag", "v1")
        self.git("checkout", "-q", "-")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(s.claude_hook(self.hook_payload("git push --tags")), 2)

    def test_history_finds_secret_added_in_merge_resolution(self) -> None:
        self.write("app.py", "x = 1\n")
        self.git("add", "app.py")
        self.git("commit", "-q", "-m", "init")
        self.git("checkout", "-q", "-b", "side")
        self.write("app.py", "x = 2\n")
        self.git("commit", "-q", "-am", "side")
        self.git("checkout", "-q", "-")
        self.write("app.py", "x = 3\n")
        self.git("commit", "-q", "-am", "main")
        subprocess.run(["git", "merge", "side"], cwd=self.repo, capture_output=True)  # conflict: exit code 1
        self.write("app.py", f'x = 4\ntoken = "{GH}"\n')
        self.git("commit", "-q", "-am", "merge")
        self.assertEqual([(f.path, f.rule) for f in s.scan_history(str(self.repo))], [("app.py", "github-token")])

    def test_report_names_ignore_globs_and_skipped_files(self) -> None:
        self.write(".secretsignore", "fixtures/*\n")
        self.write("big.txt", "x" * (s.MAX_FILE_BYTES + 1))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(s.main(["--tree", str(self.repo)]), 0)
        self.assertIn("fixtures/*", out.getvalue())
        self.assertIn("big.txt", out.getvalue())

    def test_claude_hook_outside_git_repo(self) -> None:
        with tempfile.TemporaryDirectory() as plain:
            payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}, "cwd": plain})
            self.assertEqual(s.claude_hook(payload), 0)

    def test_history_finds_secret_removed_from_current_code(self) -> None:
        self.write("app.py", f'token = "{GH}"\n')
        self.git("add", "app.py")
        self.git("commit", "-q", "-m", "add")
        self.write("app.py", 'token = os.environ["T"]\n')
        self.git("commit", "-q", "-am", "remove")
        self.assertEqual(s.scan_tree(str(self.repo)), [])
        found = s.scan_history(str(self.repo))
        self.assertEqual([(f.path, f.rule) for f in found], [("app.py", "github-token")])
        self.assertEqual(len(found[0].commit), 8)

    def test_secretsignore_skips_matching_paths(self) -> None:
        self.write(".secretsignore", "# test data\nfixtures/*\n")
        self.write("fixtures/a.py", f'password = "{PW}"\n')
        self.assertEqual(s.scan_tree(str(self.repo)), [])

    def test_tree_scan_without_git(self) -> None:
        with tempfile.TemporaryDirectory() as plain:
            Path(plain, "node_modules").mkdir()
            Path(plain, "node_modules", "x.js").write_text(f'k = "{GH}"', encoding="utf-8")
            Path(plain, "main.ps1").write_text(f'$p = ConvertTo-SecureString "{PW}" -AsPlainText', encoding="utf-8")
            self.assertEqual([f.path for f in s.scan_tree(plain)], ["main.ps1"])

    def test_installer_installs_and_real_commit_is_blocked(self) -> None:
        code, _ = inst.install(str(self.repo))
        self.assertEqual(code, 0)
        hooks = self.repo / ".git" / "hooks"
        self.assertIn(inst.MARKER, (hooks / "pre-commit").read_text(encoding="utf-8"))
        self.assertTrue((hooks / inst.SCANNER_COPY).exists())
        self.write("app.py", f'token = "{GH}"\n')
        self.git("add", "app.py")
        result = subprocess.run(["git", "commit", "-m", "x"], cwd=self.repo, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"github-token", result.stderr)
        self.assertEqual(inst.install(str(self.repo))[0], 0)  # re-install updates its own hook

    def test_installer_refuses_foreign_hook(self) -> None:
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
        code, message = inst.install(str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("already exists", message)
        self.assertEqual(hook.read_text(encoding="utf-8"), "#!/bin/sh\necho mine\n")

    def test_installer_refuses_custom_hooks_path(self) -> None:
        self.git("config", "core.hooksPath", ".husky")
        code, message = inst.install(str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("core.hooksPath", message)
        self.assertFalse((self.repo / ".husky").exists())


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "git or bash is not installed")
class HookCommandTests(unittest.TestCase):
    """Runs the exact shell commands from hooks/hooks.json, the way Claude Code runs them."""

    def setUp(self) -> None:
        handlers = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
        self.commands = {h["matcher"]: h["hooks"][0]["command"] for h in handlers}
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_hook(self, matcher: str, command: str, path_env: str | None = None) -> subprocess.CompletedProcess[str]:
        payload = json.dumps({"tool_name": matcher, "tool_input": {"command": command}, "cwd": str(self.repo)})
        env = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(PLUGIN_ROOT)}
        if path_env is not None:
            env["PATH"] = path_env
        return subprocess.run(["bash", "-c", self.commands[matcher]], input=payload, capture_output=True, text=True, env=env)

    def test_both_handlers_block_commit_with_secret(self) -> None:
        (self.repo / "app.py").write_text(f'token = "{GH}"\n', encoding="utf-8")
        for matcher in ("Bash", "PowerShell"):
            with self.subTest(matcher=matcher):
                result = self.run_hook(matcher, "git add . && git commit -m x")
                self.assertEqual(result.returncode, 2)
                self.assertIn("github-token", result.stderr)
                self.assertNotIn(GH, result.stderr)

    def test_non_commit_exits_before_python(self) -> None:
        (self.repo / "app.py").write_text(f'token = "{GH}"\n', encoding="utf-8")
        for matcher in ("Bash", "PowerShell"):
            with self.subTest(matcher=matcher):
                # Empty PATH: if the filter did not exit early, Python could not start and the code would be 1.
                self.assertEqual(self.run_hook(matcher, "Get-ChildItem", path_env="").returncode, 0)

    def test_clean_commit_passes(self) -> None:
        (self.repo / "app.py").write_text("print(1)\n", encoding="utf-8")
        self.assertEqual(self.run_hook("Bash", "git commit -m x").returncode, 0)

    def test_missing_python_blocks(self) -> None:
        for command in ("git commit -m x", "git push"):
            with self.subTest(command=command):
                result = self.run_hook("Bash", command, path_env="")
                self.assertEqual(result.returncode, 2)
                self.assertIn("Python not found", result.stderr)


if __name__ == "__main__":
    unittest.main()

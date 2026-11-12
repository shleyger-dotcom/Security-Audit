#!/usr/bin/env python3
"""Secret scanner for the secure-code plugin. Standard library only, Python 3.10+.

Modes:
  --claude-hook     Claude Code PreToolUse hook. Reads the hook JSON from stdin and
                    blocks (exit 2) `git commit` when pending changes contain secrets
                    or new scan exceptions,
                    `git push` when unpushed commits contain secrets, and both when
                    the scan fails.
  --staged [REPO]   git pre-commit hook. Scans staged changes. Exit 1 on findings.
  --tree [PATH]     Scans every non-ignored file under PATH. Exit 1 on findings.
  --history [REPO]  Scans every commit on every branch. Exit 1 on findings.

False positive: put `secret-scan: allow` on the same line, or add a path glob
to `.secretsignore` in the repository (or scan) root.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Iterator, Sequence

GitRunner = Callable[[Sequence[str], str], str]

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ALLOW_PRAGMA = "secret-scan: allow"
EXCEPTION_RULE = "scan-exception-added"
IGNORE_FILE = ".secretsignore"
MAX_FILE_BYTES = 2_000_000
SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache", ".pytest_cache", ".tox"}
)
# Non-finding messages for the report: ignore globs in effect, files that the content scan skipped.
NOTES: list[str] = []
DIFF_OPTS = ("--no-color", "--no-ext-diff", "-U0", "--diff-filter=ACMR")

# A named group "value" marks the secret part of a match; without it the whole match is the secret.
TOKEN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-api-key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    (
        "webhook-url",
        re.compile(r"https://(?:hooks\.slack\.com/services|(?:discord|discordapp)\.com/api/webhooks)/[A-Za-z0-9/_-]{20,}"),
    ),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}")),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")),
    ("twilio-key", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("discord-bot-token", re.compile(r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}")),
    ("azure-storage-key", re.compile(r"(?i)\bAccountKey=(?P<value>[A-Za-z0-9+/]{86}==)")),
    ("docker-auth", re.compile(r"\"auth\"\s*:\s*\"(?P<value>[A-Za-z0-9+/]{20,}={0,2})\"")),
    ("npmrc-auth-token", re.compile(r"_authToken\s*=\s*(?P<value>[^\s'\"]+)")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("bearer-token", re.compile(r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9._~+/-]{20,}=*)")),
    ("wireguard-private-key", re.compile(r"(?i)\bPrivateKey\s*=\s*(?P<value>[A-Za-z0-9+/]{43}=)")),
    (
        "connection-string-password",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|ftp|smtps?|https?)"
            r"://[^\s:/@'\"]+:(?P<value>[^\s@'\"/]+)@"
        ),
    ),
    (
        "powershell-plaintext-password",
        re.compile(
            r"(?i)ConvertTo-SecureString\s+(?:-String\s+)?(?P<q>['\"])(?P<value>[^'\"]+)(?P=q)\s+-AsPlainText"
        ),
    ),
)

# Suffix match keeps `password_hash`, `token_url`, `bypass` out: the name must END with a secret word.
SECRET_NAME = (
    r"[A-Za-z0-9_.-]*?(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey"
    r"|access[_-]?key|private[_-]?key|client[_-]?secret"
    r"|(?:secret|encryption|signing|master|auth)[_-]?key|[_.-]pass)"
)
ASSIGN_RULE = (
    "secret-assignment",
    re.compile(
        rf"(?i)\b{SECRET_NAME}\b['\"]?(?:\s*:\s*[A-Za-z_][\w\[\], .|]*?)?\s*(?:=>|:=|=|:)\s*"
        r"(?P<q>['\"`])(?P<value>[^'\"`\s]{8,})(?P=q)"
    ),
)
# A literal fallback for a secret from the environment: the fallback is the hardcoded secret.
ENV_DEFAULT_RULES = (
    (
        "env-default-secret",
        re.compile(
            rf"(?i)(?:getenv|environ\.get|env\.get|config)\(\s*['\"]{SECRET_NAME}['\"]\s*,\s*(?:default\s*=\s*)?"
            r"(?P<q>['\"])(?P<value>[^'\"\s]{8,})(?P=q)"
        ),
    ),
    (
        "env-default-secret",
        re.compile(rf"(?i)\benv\.{SECRET_NAME}\s*(?:\|\||\?\?)\s*(?P<q>['\"`])(?P<value>[^'\"`\s]{{8,}})(?P=q)"),
    ),
)
# shortcut: C++ brace-init (`std::string token{"..."}`) is not detected; add a rule if it shows up in real code.
C_DEFINE_RULE = (
    "c-define-secret",
    re.compile(rf"(?i)#\s*define\s+{SECRET_NAME}\s+(?:[LuU]8?)?\"(?P<value>[^\"\s]{{8,}})\""),
)
# Unquoted `KEY=value` only in config files: in code an unquoted value is a variable or a call.
CONFIG_RULE = (
    "config-secret",
    re.compile(rf"(?i)^\s*(?:export\s+)?{SECRET_NAME}\s*[:=]\s*(?P<value>[^\s'\"#]{{8,}})\s*(?:#.*)?$"),
)
CONFIG_SUFFIXES = frozenset({".ini", ".cfg", ".conf", ".properties", ".toml", ".yaml", ".yml", ".env"})
CONFIG_NAMES = frozenset({".npmrc", ".pypirc", ".netrc", ".envrc"})

SENSITIVE_FILE_GLOBS = (
    ".env", ".env.*", "*.env", ".envrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.mobileprovision", "*.ovpn",
    "*.tfstate", "*.tfstate.backup", "credentials.json", ".netrc", ".pgpass", "*.kdbx",
    "*.sqlite", "*.sqlite3", "*.db", "*dump*.sql", "secrets.toml",
    ".git-credentials", "*.ppk", "*.tfvars", "*service-account*.json", "*service_account*.json",
    "kubeconfig", "*.kubeconfig", ".htpasswd", "credentials",
)
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")
PLACEHOLDER_HINTS = ("your", "example", "placeholder", "dummy", "redacted", "xxxx", "****", "....", "${", "{{", "%(")

COMMIT_LINE = re.compile(r"^commit ([0-9a-f]{40})$")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
BINARY_LINE = re.compile(r'^Binary files .* and "?b/(.+?)"? differ$', re.M)
# The separators and quotes before `git` cover a call by full path, for example `/usr/bin/git`.
GIT_CMD = re.compile(
    r"(?:^|[\s;&|(\"'/\\])git(?:\.exe)?[\"']?"
    r"(?P<opts>(?:\s+-C\s+(?:\"[^\"]*\"|'[^']*'|\S+)|\s+-c\s+\S+|\s+--[\w-]+(?:=\S+)?|\s+-[pP])*)"
    r"\s+(?P<sub>commit|push)\b"
)
CD_CMD = re.compile(r"(?i)(?:^|[\s;&|(])(?:cd|pushd|Set-Location|sl)\s+(\"[^\"]*\"|'[^']*'|[^\s;&|)]+)")
C_OPT = re.compile(r"-C\s+(\"[^\"]*\"|'[^']*'|\S+)")


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str
    masked: str
    commit: str = ""


def mask(value: str) -> str:
    return value[:4] + "***" if len(value) > 4 else "***"


def is_placeholder(value: str) -> bool:
    v = value.lower()
    return not v or v[0] in "$<{%" or len(set(v)) <= 2 or any(h in v for h in PLACEHOLDER_HINTS)


def is_config_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name.startswith(".env") or name in CONFIG_NAMES or PurePosixPath(name).suffix in CONFIG_SUFFIXES


def is_sensitive_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name.startswith(".env") and name.endswith(SAFE_ENV_SUFFIXES):
        return False
    return any(fnmatch.fnmatchcase(name, g) for g in SENSITIVE_FILE_GLOBS)


def scan_line(text: str, config: bool, strict: bool = False) -> list[tuple[str, str]]:
    """Return (rule, value) pairs. One value is reported once, by the most specific rule.

    strict: an allow pragma that hides a secret is reported as EXCEPTION_RULE instead of obeyed.
    """
    pragma = ALLOW_PRAGMA in text
    if pragma and not strict:
        return []
    rules = TOKEN_RULES + ENV_DEFAULT_RULES + (ASSIGN_RULE, C_DEFINE_RULE) + ((CONFIG_RULE,) if config else ())
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, pattern in rules:
        for m in pattern.finditer(text):
            value = m.group("value") if "value" in pattern.groupindex else m.group(0)
            if value in seen or any(value in s or s in value for s in seen) or is_placeholder(value):
                continue
            seen.add(value)
            hits.append((name, value))
    if pragma and hits:
        return [(EXCEPTION_RULE, "")]
    return hits


def scan_numbered(
    path: str, lines: Iterable[tuple[int, str]], commit: str = "", strict: bool = False
) -> list[Finding]:
    config = is_config_file(path)
    return [
        Finding(path, no, rule, mask(value), commit)
        for no, text in lines
        for rule, value in scan_line(text, config, strict)
    ]


def parse_diff(diff: str) -> Iterator[tuple[str, str, int, str]]:
    """Yield (commit, path, line_no, text) for every added line of a `-U0` unified diff or `git log -p`."""
    commit, path, line_no, in_header = "", None, 0, False
    for raw in diff.splitlines():
        m = COMMIT_LINE.match(raw)
        if m:
            commit, path, in_header = m.group(1)[:8], None, False
        elif raw.startswith("diff --git "):
            path, in_header = None, True
        elif raw.startswith("@@"):
            in_header = False
            hunk = HUNK.match(raw)
            line_no = int(hunk.group(1)) if hunk else 0
        elif in_header:
            if raw.startswith("+++ "):
                target = raw[4:].strip('"')
                path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
        elif path and raw.startswith("+"):
            yield commit, path, line_no, raw[1:]
            line_no += 1


def load_ignore(root: str) -> tuple[str, ...]:
    try:
        text = Path(root, IGNORE_FILE).read_text(encoding="utf-8")
    except OSError:
        return ()
    globs = tuple(s.strip() for s in text.splitlines() if s.strip() and not s.strip().startswith("#"))
    if globs:
        NOTES.append(f"{IGNORE_FILE} hides paths that match: {', '.join(globs)}")
    return globs


def is_ignored(path: str, globs: Sequence[str]) -> bool:
    p = path.replace("\\", "/")
    name = PurePosixPath(p).name
    return any(fnmatch.fnmatchcase(p, g) or fnmatch.fnmatchcase(name, g) for g in globs)


def read_text_lines(fs_path: Path) -> list[str] | None:
    try:
        if fs_path.stat().st_size > MAX_FILE_BYTES:
            NOTES.append(f"content not scanned (larger than {MAX_FILE_BYTES} bytes): {fs_path}")
            return None
        data = fs_path.read_bytes()
    except OSError:
        return None
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):  # UTF-16 BOM: Windows PowerShell 5.1 writes this with `>`
        return data.decode("utf-16", errors="replace").splitlines()
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace").splitlines()


def scan_diff_text(diff: str, ignore: Sequence[str], strict: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for commit, path, line_no, text in parse_diff(diff):
        if not is_ignored(path, ignore):
            findings += scan_numbered(path, [(line_no, text)], commit, strict)
    return findings


def scan_names(paths: Iterable[str], ignore: Sequence[str], commit: str = "") -> list[Finding]:
    return [
        Finding(p, 0, "sensitive-file", "-", commit)
        for p in paths
        if is_sensitive_file(p) and not is_ignored(p, ignore)
    ]


def scan_files(root: str, rel_paths: Sequence[str], ignore: Sequence[str], strict: bool = False) -> list[Finding]:
    findings = scan_names(rel_paths, ignore)
    for rel in rel_paths:
        if is_ignored(rel, ignore):
            continue
        lines = read_text_lines(Path(root, rel))
        if lines is not None:
            findings += scan_numbered(rel, enumerate(lines, 1), strict=strict)
    return findings


def run_git(args: Sequence[str], cwd: str) -> str:
    done = subprocess.run(["git", "-c", "core.quotepath=false", *args], cwd=cwd, capture_output=True, check=True)
    return done.stdout.decode("utf-8", errors="replace")


def git_ok(git: GitRunner, args: Sequence[str], cwd: str) -> bool:
    try:
        git(args, cwd)
        return True
    except (subprocess.CalledProcessError, OSError):
        return False


def split_z(out: str) -> list[str]:
    return [p for p in out.split("\0") if p]


def repo_root(git: GitRunner, path: str) -> str:
    return git(["rev-parse", "--show-toplevel"], path).strip()


def base_rev(git: GitRunner, repo: str) -> str:
    return "HEAD" if git_ok(git, ["rev-parse", "--verify", "-q", "HEAD"], repo) else EMPTY_TREE


def scan_index(
    git: GitRunner, top: str, base: str, ignore: Sequence[str], cached: bool, strict: bool = False
) -> list[Finding]:
    flag = ["--cached"] if cached else []
    diff = git(["diff", *flag, *DIFF_OPTS, base], top)
    names = split_z(git(["diff", *flag, "--name-only", "-z", "--diff-filter=ACMR", base], top))
    # shortcut: git shows UTF-16 files as binary, so the work-tree copy is read, not the staged blob.
    # History scans do not read such files at all; read blobs with `git cat-file` if that matters.
    binary = scan_files(top, BINARY_LINE.findall(diff), ignore, strict)
    return scan_names(names, ignore) + scan_diff_text(diff, ignore, strict) + binary


def scan_staged(repo: str, git: GitRunner = run_git) -> list[Finding]:
    top = repo_root(git, repo)
    return sorted(set(scan_index(git, top, base_rev(git, top), load_ignore(top), cached=True)))


def scan_pending(repo: str, git: GitRunner = run_git, strict: bool = False) -> list[Finding]:
    """Everything `git add` + `git commit` could include: staged, unstaged and untracked files.

    strict: new scan exceptions (an allow pragma on a secret, a changed ignore file) are findings.
    """
    top = repo_root(git, repo)
    base, ignore = base_rev(git, top), load_ignore(top)
    untracked = split_z(git(["ls-files", "--others", "--exclude-standard", "-z"], top))
    findings = (
        scan_index(git, top, base, ignore, cached=True, strict=strict)
        + scan_index(git, top, base, ignore, cached=False, strict=strict)
        + scan_files(top, untracked, ignore, strict)
    )
    if strict and git(["status", "--porcelain", "--", IGNORE_FILE], top).strip():
        findings.append(Finding(IGNORE_FILE, 0, EXCEPTION_RULE, "-"))
    return sorted(set(findings))


def walk_files(root: Path) -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath, name).relative_to(root).as_posix()


def scan_tree(target: str, git: GitRunner = run_git) -> list[Finding]:
    root = Path(target)
    if root.is_file():
        return sorted(set(scan_files(str(root.parent), [root.name], load_ignore(str(root.parent)))))
    if git_ok(git, ["rev-parse", "--is-inside-work-tree"], str(root)):
        rel = split_z(git(["ls-files", "-co", "--exclude-standard", "-z"], str(root)))
    else:
        rel = list(walk_files(root))
    return sorted(set(scan_files(str(root), rel, load_ignore(str(root)))))


def scan_commits(repo: str, revs: Sequence[str], git: GitRunner) -> list[Finding]:
    top = repo_root(git, repo)
    ignore = load_ignore(top)
    # --remerge-diff (git 2.36+): a merge commit shows the lines that its conflict resolution added.
    log = git(["log", "-p", "--remerge-diff", *DIFF_OPTS, "--format=commit %H", *revs], top)
    findings = scan_diff_text(log, ignore)
    commit = ""
    for line in git(["log", "--name-only", "--diff-filter=A", "--format=commit %H", *revs], top).splitlines():
        m = COMMIT_LINE.match(line)
        if m:
            commit = m.group(1)[:8]
        elif line.strip():
            findings += scan_names([line.strip()], ignore, commit)
    return sorted(set(findings))


def scan_history(repo: str, git: GitRunner = run_git) -> list[Finding]:
    return scan_commits(repo, ["--all"], git)


def scan_unpushed(repo: str, git: GitRunner = run_git) -> list[Finding]:
    """Commits that a `git push` could publish: on a local branch, a tag or HEAD, and on no remote-tracking branch."""
    head = ["HEAD"] if base_rev(git, repo) == "HEAD" else []  # `git log HEAD` fails in a repository without commits
    return scan_commits(repo, ["--branches", "--tags", *head, "--not", "--remotes"], git)


def guarded_git(command: str, cwd: str) -> list[tuple[str, str]]:
    """Return (subcommand, repo) for every `git commit` and `git push` in a shell command."""
    actions: list[tuple[str, str]] = []
    for m in GIT_CMD.finditer(command):
        # shortcut: the last `cd` before the git call wins; variables and Git Bash paths (`/c/...`) are not
        # resolved. The caller falls back to the hook cwd when the result is not a repository.
        base = cwd
        for target in CD_CMD.findall(command[: m.start()]):
            base = os.path.join(cwd, os.path.expanduser(target.strip("\"'")))
        c = C_OPT.search(m.group("opts"))
        actions.append((m.group("sub"), os.path.join(base, c.group(1).strip("\"'")) if c else base))
    return actions


def format_report(findings: Sequence[Finding], header: str, for_claude: bool = False) -> str:
    out = [f"secure-code: {header}{len(findings)} possible secret(s) found:"]
    for f in findings:
        where = (f"{f.commit}:" if f.commit else "") + f.path + (f":{f.line}" if f.line else "")
        out.append(f"  {where}  [{f.rule}]  {f.masked}")
    out += [f"  note: {n}" for n in dict.fromkeys(NOTES)]
    out += [
        "",
        "Fix: move the value to an environment variable or a .env file listed in .gitignore.",
        "If the secret was ever pushed or shared, revoke it and issue a new one. Deleting it from the code is not enough.",
        f"False positive: add the comment '{ALLOW_PRAGMA}' on that line, or a path glob to {IGNORE_FILE}.",
    ]
    if any(f.rule == EXCEPTION_RULE for f in findings):
        out.append(
            f"[{EXCEPTION_RULE}]: this commit adds a scan exception (an allow comment on a secret, or a changed "
            f"{IGNORE_FILE}). Claude Code cannot commit it. The user reviews it and commits from their own terminal."
        )
    if for_claude:
        out.append("Claude: do not add allow comments or ignore entries yourself. Show this list to the user and ask.")
    return "\n".join(out)


def claude_hook(payload_text: str, git: GitRunner = run_git) -> int:
    try:
        payload = json.loads(payload_text.lstrip("\ufeff"))
    except ValueError:
        return 0
    if not isinstance(payload, dict) or payload.get("tool_name") not in ("Bash", "PowerShell"):
        return 0
    tool_input = payload.get("tool_input")
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    cwd = str(payload.get("cwd") or os.getcwd())
    actions = guarded_git(str(command), cwd)
    if not actions:
        return 0
    # The command text is published too: a secret in `git commit -m "..."` lands in the history.
    # The allow pragma is removed first: a commit message must not switch the scan off.
    text = str(command).replace(ALLOW_PRAGMA, "")
    findings = [Finding("<git command text>", 0, rule, mask(value)) for rule, value in scan_line(text, False)]
    inside = ["rev-parse", "--is-inside-work-tree"]
    for sub, repo in actions:
        if not git_ok(git, inside, repo):
            if repo == cwd or not git_ok(git, inside, cwd):
                continue
            repo = cwd
        findings += scan_pending(repo, git, strict=True) if sub == "commit" else scan_unpushed(repo, git)
    if not findings:
        return 0
    print(format_report(sorted(set(findings)), "Command blocked. ", for_claude=True), file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None, stdin_text: str | None = None, git: GitRunner = run_git) -> int:
    parser = argparse.ArgumentParser(description="Secret scanner (secure-code plugin).")
    mode = parser.add_mutually_exclusive_group(required=True)
    for flag in ("--claude-hook", "--staged", "--tree", "--history"):
        mode.add_argument(flag, action="store_true")
    parser.add_argument("target", nargs="?", default=".")
    args = parser.parse_args(argv)
    try:
        if args.claude_hook:
            text = stdin_text if stdin_text is not None else sys.stdin.buffer.read().decode("utf-8", "replace")
            return claude_hook(text, git)
        scan = scan_staged if args.staged else scan_tree if args.tree else scan_history
        findings = scan(os.path.abspath(args.target), git)
    except (subprocess.CalledProcessError, OSError) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        blocked = " Command blocked: the changes were not scanned." if args.claude_hook else ""
        print(
            f"secure-code: secret scan failed: {exc} {detail.decode('utf-8', 'replace').strip()}{blocked}",
            file=sys.stderr,
        )
        return 2 if args.claude_hook else 1  # fail closed: Claude Code runs the command on exit 1
    if findings:
        stream = sys.stderr if args.staged else sys.stdout
        print(format_report(findings, "Commit blocked. " if args.staged else ""), file=stream)
        return 1
    if not args.staged:
        print("\n".join(["secure-code: no secrets found.", *(f"  note: {n}" for n in dict.fromkeys(NOTES))]))
    return 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())

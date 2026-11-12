#!/usr/bin/env python3
"""Install the secure-code secret scan as a git pre-commit hook in one repository.

Usage: python install_git_hook.py [REPO]

The scanner is copied into the hooks folder, so the hook keeps working after
plugin updates or removal. Re-run this script to update it. The script never
overwrites a pre-commit hook that it did not create.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from scan_secrets import GitRunner, run_git

SCANNER = Path(__file__).resolve().with_name("scan_secrets.py")
SCANNER_COPY = "secure_code_scan_secrets.py"
MARKER = "# secure-code secret scan"
PRE_COMMIT = f"""#!/bin/sh
{MARKER}: installed by the secure-code plugin. Re-run install_git_hook.py to update.
dir=$(dirname "$0")
for p in python python3 py; do
  if "$p" -c "" >/dev/null 2>&1; then
    exec "$p" "$dir/{SCANNER_COPY}" --staged
  fi
done
echo "secure-code: Python not found, cannot scan for secrets. Commit blocked." >&2
exit 1
"""


def manual_hint(top: str) -> str:
    return f'Add this line to your existing pre-commit hook instead:\n  python "{SCANNER}" --staged "{top}"'


def install(repo: str, git: GitRunner = run_git, scanner: Path = SCANNER) -> tuple[int, str]:
    top = git(["rev-parse", "--show-toplevel"], repo).strip()
    try:
        hooks_cfg = git(["config", "--get", "core.hooksPath"], top).strip()
    except subprocess.CalledProcessError:
        hooks_cfg = ""
    if hooks_cfg:
        return 1, f"core.hooksPath is set to '{hooks_cfg}' (husky, pre-commit or similar). Nothing changed.\n{manual_hint(top)}"
    hooks_dir = Path(top, git(["rev-parse", "--git-path", "hooks"], top).strip())
    hook = hooks_dir / "pre-commit"
    if hook.exists() and MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
        return 1, f"A pre-commit hook already exists: {hook}. Nothing changed.\n{manual_hint(top)}"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(scanner, hooks_dir / SCANNER_COPY)
    hook.write_text(PRE_COMMIT, encoding="utf-8", newline="\n")  # LF: sh fails on CRLF
    hook.chmod(0o755)
    return 0, f"Installed pre-commit secret scan: {hook}"


def main() -> int:
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    try:
        code, message = install(str(Path(repo).resolve()))
    except (subprocess.CalledProcessError, OSError) as exc:
        code, message = 1, f"Install failed (is this a git repository?): {exc}"
    print(message, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())

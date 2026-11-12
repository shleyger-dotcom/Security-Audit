---
description: Security audit of your code (whole project, a path, or uncommitted changes), or install the git pre-commit secret scan
argument-hint: "[path | --diff | install-hook]"
disable-model-invocation: true
---

Use the `secure-code` skill from this plugin. Follow its audit procedure and its hard rules.

Arguments: `$ARGUMENTS`

- No arguments: audit the whole current working directory.
- A file or folder path: audit only that target.
- `--diff`: audit only uncommitted work: `git diff HEAD` plus untracked files.
- `install-hook`: do not audit. Run `python "<skill base directory>/scripts/install_git_hook.py"` in the current git repository and show the output to the user. If the script refuses, explain the reason. Do not edit git hooks by hand.

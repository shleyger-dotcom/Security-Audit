# security-audit-rs

A Claude Code plugin that audits your own code for security problems and stops commits that contain secrets.

Created by Shleyger Ram.

## What it contains

| Part | What it does |
|---|---|
| Skill `secure-code` | Audit procedure, severity levels, false-positive filter, report format, and rules for writing secure code. References for Python, JavaScript/TypeScript, Java/Kotlin, C#/.NET, Go, Rust, PHP, Ruby, C/C++ (memory safety, integer overflow, format strings, build hardening), mobile apps (Android, iOS, React Native, Flutter), browser extensions, HTML/CSS and config files (Dockerfile, docker-compose, GitHub Actions, `.env`), cloud and IaC (AWS, GCP, Azure, Kubernetes, Terraform, Ansible), PowerShell, shell scripts, and AI/LLM apps (agents, RAG, MCP, coding-agent files). The checklist maps to OWASP Top 10:2025 and OWASP API Security Top 10:2023. |
| Command `/security-audit` | Starts an audit, or installs the git pre-commit hook. |
| Claude Code hook | Before Claude runs `git commit` (Bash or PowerShell tool), it scans staged, unstaged and untracked files and the command text. Before `git push`, it scans the commits that are on no remote yet (branches, tags and HEAD). If it finds a secret, a new scan exception, or if the scan cannot run, it blocks the command. |
| Git pre-commit hook | Scans every commit in one repository, including your manual commits from the terminal or VS Code. You install it per repository. |

The secret scanner uses only the Python standard library. It finds private keys, AWS/GitHub/GitLab/Anthropic/OpenAI/Google/Slack/Stripe/Telegram/Hugging Face/npm/PyPI/SendGrid/Twilio/Discord tokens, Azure storage keys, Docker registry auth, JWTs, literal `Bearer` tokens, passwords in connection strings and URLs, hardcoded passwords and keys in code and config files (names such as `password`, `api_key`, `SECRET_KEY`, `ENCRYPTION_KEY`, `DB_PASS`; including C `#define`), literal fallbacks for environment secrets (`os.environ.get("API_KEY", "...")`, `process.env.API_KEY || "..."`), plain-text passwords in PowerShell, and sensitive file names (`.env`, `id_rsa`, `*.pem`, `*.ppk`, `*.tfstate`, `*.tfvars`, `.git-credentials`, `kubeconfig`, `*.db`, …). It reads UTF-8 and UTF-16 files. It shows only the first 4 characters of a secret.

## What the plugin checks

The plugin has two kinds of checks. A script does the first kind, and the result is always the same. Claude does the second kind when it follows the skill, so the result depends on the model.

### Checks by a script

| Check | When | What it finds |
|---|---|---|
| Secret scan of files | Audit, `git commit` | Keys, tokens and passwords in the current files (see the list above) |
| Secret scan of history | Audit (all history), `git push` (commits that are on no remote yet) | Secrets in old commits, also when the current file is clean |
| Sensitive file names | Audit, `git commit` | `.env`, private keys, `*.tfstate`, database files and similar |
| New scan exceptions | `git commit` from Claude | A new `secret-scan: allow` comment or a change of `.secretsignore` |

### Checks by Claude during an audit

Claude first makes a map of the code: entry points, trust boundaries, assets, STRIDE threats and one abuse case for each feature. Then it follows untrusted data from each entry point to each dangerous operation. It also searches for hidden Unicode characters and internal addresses, and runs the external scanners that are already installed (Semgrep, Bandit, gitleaks, OSV-Scanner, Trivy and others).

The checklist has 13 sections:

| Section | Examples of checks |
|---|---|
| A. Access control | Authentication on each endpoint, object ownership (IDOR), CSRF, CORS, SSRF, path traversal, archive extraction, tenant isolation |
| B. Injection | SQL, NoSQL, OS commands, `eval`, templates, XSS, XXE, deserialization, ReDoS, CSV formulas, second-order injection |
| C. Authentication and sessions | Password hashing, rate limits, reset tokens, cookies, JWT, OAuth, SAML, webhook signatures, default accounts |
| D. Cryptography | Random generators, weak algorithms, TLS verification, key storage |
| E. Data exposure and errors | Response fields, stack traces, debug mode, secrets in logs, caches, fail-closed behavior |
| F. Business logic | Race conditions, idempotency, value ranges, prices from the client, skipped steps, money types |
| G. Files | Upload type, size and name, storage location, temporary files, delete/move/overwrite of a path that comes from data |
| H. Resource limits | Body size, timeouts, pagination, GraphQL depth, WebSocket limits |
| I. Supply chain | Lockfile, one package manager, known vulnerabilities, typosquatting, install scripts, pinned CI actions, registry signatures, hidden characters |
| J. Logging and alerting | Security events in logs, log protection, alerts |
| K. Infrastructure | Database user rights, key scopes, debug routes, open ports, backups, secret rotation, subdomain takeover |
| L. APIs and third parties | Third-party data, abuse of business flows, API inventory, Host header, request smuggling, gRPC, email, clickjacking |
| M. Personal data and privacy | Data classes, purpose, personal data in analytics, retention, export and deletion, consent, data processing agreements |

Each language and platform in the first table has its own reference with the dangerous functions and the safe replacements for that stack.

Claude keeps a finding only when it can name the source of the data, the code path, the effect and the reachability in production. The report gives each finding a severity, a confidence level, a CWE number, the attack, the fix and a test. Items that the code cannot answer (MFA, backups, network rules) are in the report as questions.

### Checks by Claude while it writes code

When Claude writes code that handles untrusted data, the skill gives it rules for safe code and a list of changes that need your agreement first. See "Secure code while Claude writes" below.

## Requirements

- Claude Code
- Python 3.10 or newer on `PATH` (`python`, `python3` or `py`)
- Git 2.36 or newer (on Windows: Git for Windows, which includes Git Bash for the hooks)

## Install

Run these commands inside Claude Code:

```
/plugin marketplace add shleyger-dotcom/Security-Audit
/plugin install security-audit-rs@security-audit-rs
```

To install from a local copy, give the folder path to the first command: `/plugin marketplace add C:\path\to\security-audit-rs`.

Restart Claude Code after the install.

To try the plugin without installing it, start Claude Code from a terminal:

```
claude --plugin-dir "C:\path\to\security-audit-rs"
```

## Usage

| Command | Result |
|---|---|
| `/security-audit` | Audits the whole current folder |
| `/security-audit src/api` | Audits one file or folder |
| `/security-audit --diff` | Audits only uncommitted changes |
| `/security-audit install-hook` | Installs the git pre-commit hook in the current repository |

You can also ask in normal words, for example "check this code for vulnerabilities". The skill then starts by itself.

The audit is read-only. Claude shows a report first and changes code only after you agree.

### Secure code while Claude writes

The skill is not only for audits. It also has rules for writing code, so that the code is safe from the start.

What you must start, and what starts by itself:

| Part | Starts by itself? | Guaranteed? |
|---|---|---|
| Secret scan before `git commit` and `git push` from Claude | Yes | Yes. A script does it. |
| Rules for writing code | Yes, when Claude sees that the task touches untrusted data | No. The model decides if the task matches. |
| Full audit | No. Run `/security-audit` or ask in normal words. | — |

Claude loads the writing rules when the task is about user input, authentication, sessions, files, payments, personal data, external URLs, shell commands or LLM calls. Example: for "add a login form" Claude loads the skill. For "add a button that changes the theme" it does not, and that is correct.

The model can miss a task that does not look like a security task. Example: "add an endpoint that exports a report" gives access to data of other users, but the words do not show it. To make the rules more reliable:

1. Name the skill in your request: "use secure-code".
2. Run `/security-audit --diff` before a commit. It checks only the uncommitted changes.
3. Add this line to your `CLAUDE.md` (the project file, or `~/.claude/CLAUDE.md` for all projects):

   ```
   Before you write or change code that handles user input, authentication, sessions, files, payments, personal data, external URLs, shell commands or LLM calls, always load the secure-code skill and follow its writing rules.
   ```

Use steps 2 and 3 together: step 3 makes safe code more likely, and step 2 finds the problems that remain.

With the rules loaded, Claude:

- validates input at the boundary with a schema, and uses only the validated value;
- uses parameterized queries, argument lists for processes, and the auto-escaping of the framework;
- checks authorization for each object, with the identity from the session;
- reads secrets from the environment and writes placeholders in examples;
- treats LLM output as untrusted input;
- denies access when a security check fails with an error;
- checks the root, the depth and the ownership of a path before it deletes, moves or overwrites it;
- writes one abuse case for each new feature and makes it a test;
- asks you before it changes authentication, CORS, rate limits or permissions, and before it adds an upload handler, a new external service or a new category of personal data.

### Secret scanner from the command line

```
python skills/secure-code/scripts/scan_secrets.py --tree .        # current files
python skills/secure-code/scripts/scan_secrets.py --history .     # all git history
python skills/secure-code/scripts/scan_secrets.py --staged .      # staged changes
```

Exit code 0 means no findings. Exit code 1 means findings or an error.

### False positives

- Add the comment `secret-scan: allow` on the line.
- Or create a `.secretsignore` file in the repository root, one glob per line, for example `tests/fixtures/*`.

Claude is told not to add these exceptions by itself, and the Claude Code hook enforces it: a commit from Claude that adds an allow comment on a secret, or that changes `.secretsignore`, is blocked with `[scan-exception-added]`. Review the exception and commit it yourself from a terminal. The git pre-commit hook accepts your own exceptions.

### Git pre-commit hook

`/security-audit install-hook` copies the scanner to `.git/hooks/secure_code_scan_secrets.py` and creates `.git/hooks/pre-commit`. The installer refuses, and changes nothing, if:

- the repository already has a pre-commit hook from another tool, or
- `core.hooksPath` is set (husky, pre-commit framework).

In those cases it prints a line that you can add to your existing hook.

To remove the hook, delete `.git/hooks/pre-commit` and `.git/hooks/secure_code_scan_secrets.py`.

## Limits

- The scanner matches patterns. It does not find every secret format, and it can report false positives.
- The scanner has no entropy check: a random secret without a known prefix or a secret-like variable name is not found. Use gitleaks or TruffleHog for that.
- The scanner does not look for internal IP addresses or personal data. The audit searches for internal addresses separately; personal data is a manual checklist item.
- The Claude Code hook scans the folder where the session runs, `git -C <path>` and `cd <path> && git ...`, also when git is called by its full path. It does not resolve shell variables in the path. It does not see git aliases (`git ci`), other tools that commit (`gh`, IDE buttons) or scripts that call git. The git pre-commit hook covers those.
- An existing `.secretsignore` is obeyed. A broad glob in it hides files from every scan; the report lists the active globs only when it prints.
- UTF-16 files are read from the work tree. The history scan (`--history`, push check) does not read them, because git stores them as binary.
- The history scan reads conflict resolutions of merge commits with `git log --remerge-diff`. On large histories this is slower.
- The Claude Code hook blocks `git commit` and `git push` when Python is missing or the scan fails.
- The push check reads commits on local branches that are on no remote-tracking branch. In a repository without a remote, this is the whole history.
- Files larger than 2 MB and binary files are skipped by the content scan. Their names are still checked. The report lists skipped large files and the active `.secretsignore` globs.
- Languages without a reference (for example Swift on the server, Scala, Elixir) get the general checklist only.
- The audit reads code. It does not test a running system: no dynamic scan (DAST), no fuzzing, no check of the real cloud account, DNS or server. Those items appear in the report as questions.
- Apart from secrets, nothing is enforced by a hook. The audit quality depends on the model that follows the skill.
- The audit is a review by a language model. It does not replace a professional penetration test.

## Tests

```
python -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).

## Author

shleyger-dotcom

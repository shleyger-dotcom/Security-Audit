# Scanners

## Rules

1. Use a tool only if it is already installed. Check with `command -v <tool>` (Bash) or `Get-Command <tool>` (PowerShell).
2. Do not install tools. List missing useful tools under "Not run" with the install command, and let the user decide.
3. Do not run project install scripts, tests or builds during an audit (see the hard rules in SKILL.md).
4. Scanner output can contain secrets. Mask them before you quote the output.
5. Each scanner result is a lead. Verify it with step 5 of the audit procedure before you report it.

## Bundled (always available, Python 3.10+)

| Purpose | Command |
|---|---|
| Secrets in current files | `python "<skill-dir>/scripts/scan_secrets.py" --tree "<path>"` |
| Secrets in all git history | `python "<skill-dir>/scripts/scan_secrets.py" --history "<repo>"` |

## External tools (only if installed)

| Tool | License | Stack | Command |
|---|---|---|---|
| Semgrep CE | engine LGPL-2.1; registry rules under the Semgrep Rules License | all | `semgrep scan --config p/default --metrics=off "<path>"` |
| Bandit | Apache-2.0 | Python | `bandit -r "<path>" -q` |
| gitleaks | MIT | secrets | `gitleaks dir --redact "<path>"` and `gitleaks git --redact "<repo>"` (versions before 8.19: `gitleaks detect --redact`) |
| TruffleHog | AGPL-3.0 | secrets | `trufflehog filesystem "<path>"` |
| OSV-Scanner | Apache-2.0 | dependencies (lockfiles, all ecosystems) | `osv-scanner scan source -r "<path>"` (v1: `osv-scanner -r "<path>"`) |
| pip-audit | Apache-2.0 | Python dependencies | `pip-audit` (audits the active environment). With `-r requirements.txt` it can install packages into a temporary environment, and that runs their build code: ask first |
| npm audit | (part of npm) | JS dependencies | `npm audit` — reads the lockfile and does not run install scripts. pnpm: `pnpm audit`; Yarn 2+: `yarn npm audit -A -R` |
| Trivy | Apache-2.0 | dependencies, secrets, Dockerfile, IaC | `trivy fs --scanners vuln,secret,misconfig "<path>"` |
| hadolint | GPL-3.0 | Dockerfile | `hadolint Dockerfile` |
| zizmor | MIT | GitHub Actions | `zizmor .github/workflows` |
| Cppcheck | GPL-3.0 | C/C++ | `cppcheck --enable=warning,style,portability --inconclusive -q "<path>"` |
| clang-tidy | Apache-2.0 with LLVM exception | C/C++ | `clang-tidy -p <build-dir> <files> -checks='-*,clang-analyzer-*,bugprone-*,cert-*'` (needs `compile_commands.json`; without it the results are weak) |
| Flawfinder | GPL-2.0+ | C/C++ | `flawfinder --minlevel=2 "<path>"` — finds risky calls by name; many false positives |
| ShellCheck | GPL-3.0 | shell scripts | `shellcheck <files>` |
| PSScriptAnalyzer | MIT | PowerShell | `Invoke-ScriptAnalyzer -Path "<path>" -Recurse -Severity Warning,Error` |
| gosec | Apache-2.0 | Go | `gosec ./...` (run in the module folder; it can download modules) |
| govulncheck | BSD-3-Clause | Go dependencies | `govulncheck ./...` — reports only vulnerabilities that the code can reach |
| cargo-audit | Apache-2.0 or MIT | Rust dependencies | `cargo audit` — reads `Cargo.lock`, does not build |
| composer audit | (part of Composer, MIT) | PHP dependencies | `composer audit --locked` — reads `composer.lock` |
| bundler-audit | GPL-3.0 | Ruby dependencies | `bundle-audit check` — reads `Gemfile.lock`; `--update` downloads the advisory database |
| Brakeman | Brakeman Public Use License (not open source; "Commercial Uses", as the license defines them, need a paid license) | Ruby on Rails | `brakeman -q "<path>"` — static, does not run the app |
| dotnet | (part of the .NET SDK, MIT) | .NET dependencies | `dotnet list package --vulnerable --include-transitive` — needs a restored project; ask before `dotnet restore` |
| Checkov | Apache-2.0 | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM/Bicep | `checkov -d "<path>" --quiet --compact` |

Java and Kotlin have no extra tool here: Semgrep covers the code, and OSV-Scanner reads `pom.xml` and Gradle lockfiles. Mobile apps and browser extensions: Semgrep, then manual review with `mobile.md` or `browser-extensions.md`.

License notes: you only run these tools; you do not distribute or change them. The GPL and AGPL obligations apply to distribution or modification of the tool itself, not to your scanned code. The Semgrep Rules License limits the use of registry rules in competing commercial products. Brakeman is free only for uses that its license does not define as commercial: tell the user to read the definition before use at work.

## Dependency triage

1. Critical or high, and the vulnerable code is reachable at runtime, build, test or deploy → fix now (update, patch or replace).
2. Critical or high, and not reachable (confirmed) → fix soon. Not a release blocker.
3. Moderate in production code → next release. Dev-only → backlog.
4. No fix available → workaround, replace the package, or document the risk with a review date.
5. Never run `npm audit fix --force` (or an equivalent) automatically: it can install breaking major versions.
6. Record each deferred finding with the reason and a review date.

## Supply-chain checks that an audit tool does not do

An audit tool compares versions with published advisories. It does not find a new malicious package, a typosquat or an unsafe install script. Check these by reading:

1. Package manager: the `packageManager` field (if present), the lockfile and the CI install command name the same manager. Two lockfiles in one project folder are a finding.
2. Install-script policy: look for the committed list of packages that can run install scripts (for example `ignore-scripts=true` in `.npmrc`, the allowlist of pnpm, `enableScripts: false` in `.yarnrc.yml`). No policy, or an allow-all setting, is a finding.
3. Lockfile diff (`--diff` mode): each changed entry belongs to a manifest change. Look for a changed `resolved` URL or registry host, and for a changed integrity hash with the same version.
4. Registry signatures: `npm audit signatures` verifies signatures and provenance of the installed packages. It needs an existing `node_modules` folder: do not install packages only for this check. If the folder is absent, list the command under "Not run".

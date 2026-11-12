# Shell scripts (Bash, sh, zsh): dangerous patterns and safe replacements

Applies to `*.sh` files, scripts without an extension that start with `#!/bin/sh` or `#!/usr/bin/env bash`, `Makefile` recipes, Dockerfile `RUN` lines and CI `run:` blocks.

## Code and command execution

| Dangerous with input | Why | Safe |
|---|---|---|
| `eval "$input"`, `bash -c "$input"`, `sh -c "... $input"` | runs any command | call the program directly with arguments; a `case` allowlist for the action name |
| `source "$file"`, `. "$file"` on a file that others can write | runs the file as code | parse `KEY=value` lines; check the owner and the permissions first |
| `` `$input` ``, `$($input)` | command substitution | a fixed command with `"$input"` as an argument |
| `$var` without quotes | word splitting and glob expansion: a space makes two arguments, `*` becomes a list of files | `"$var"`; arrays for lists: `"${args[@]}"` |
| `rm -rf $DIR/` | empty `DIR` deletes `/` | `rm -rf -- "${DIR:?}/"` |
| `cmd $file` where the name starts with `-` | the name is read as an option | `cmd -- "$file"`, or `./"$file"` |
| `[ $a = $b ]` | empty or spaced values break the test | `[[ "$a" == "$b" ]]` or `[ "$a" = "$b" ]` |
| `xargs`, `find -exec sh -c "... {}"` on file names from others | names with spaces, quotes or newlines | `find ... -print0 \| xargs -0`; `find -exec cmd {} +` |
| `printf "$input"` | format string | `printf '%s\n' "$input"` |

- Arithmetic contexts evaluate text: `$(( input ))`, `[[ $input -eq 1 ]]` and `${arr[$input]}` can run a command hidden in `input`. Check that the value is a number first: `[[ $input =~ ^[0-9]+$ ]]`.
- Start scripts with `set -euo pipefail`. Without it a failed step is ignored and the script continues with wrong data.

## Download and execute

- `curl ... | sh`, `wget -O- ... | bash` run remote code without a check, and a broken connection can run half of a script.
- Safe: download to a file, check `sha256sum -c` against a published hash or a signature (`gpg --verify`, `cosign verify-blob`), then run.
- `curl -k`, `curl --insecure`, `wget --no-check-certificate` disable TLS checks.
- `http://` download URLs: use `https://`.

## Secrets

- A secret on the command line is visible to other users in `ps` and stays in the shell history: `mysql -pSECRET`, `curl -u user:pass`, `--token=...`. Use environment variables, a file with mode `600`, or stdin (`--password-stdin`).
- `set -x` prints every command, also commands that contain secrets. Turn it off around them: `set +x`.
- `echo "$TOKEN"` and `env` or `printenv` in CI logs.
- `export PASSWORD=literal` in a script is a hardcoded secret.

## Files and privileges

- Temporary files: `mktemp` and `mktemp -d`, never a fixed name such as `/tmp/app.tmp` (symlink attack, CWE-377). Remove them with `trap 'rm -rf -- "$tmp"' EXIT`.
- `chmod 777`, `chmod -R a+w`, `umask 000` → the smallest mode that works. Secret files: `600`.
- `sudo` inside a script: only for the single command that needs it. No `NOPASSWD: ALL` in sudoers files.
- A script that runs as root must not execute files, or read config, from a folder that a normal user can write. Use absolute paths for commands, or set `PATH` at the top of the script.
- `cd "$dir"` without a check: if it fails, the next commands run in the wrong folder. Use `cd "$dir" || exit 1`.
- `tar xf` on an untrusted archive can write outside the target folder on old tar versions and can restore setuid bits. Extract into a new empty folder with `--no-same-owner --no-same-permissions`.

## Static analysis

- `shellcheck <file>` (GPL-3.0). Relevant checks: SC2086 (unquoted variable), SC2046 (unquoted command substitution), SC2115 (`rm -rf "$var/"` with a possibly empty variable), SC2294 (`eval` with an array).

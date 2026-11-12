# PowerShell: dangerous patterns and safe replacements

## Code and command execution

| Dangerous with input | Safe |
|---|---|
| `Invoke-Expression` / `iex` | call the command directly with parameters |
| `[scriptblock]::Create($input)`, `& $input`, `. $input` | a fixed command; `ValidateSet` for the command name |
| `Start-Process cmd -ArgumentList "/c $input"`, `cmd /c "... $input"` | `Start-Process prog -ArgumentList @($arg1, $arg2)` without `cmd` |
| `Add-Type -TypeDefinition $input` | static code only |
| `Invoke-Sqlcmd -Query "... $input"` | `System.Data.SqlClient.SqlCommand` with `Parameters.AddWithValue` |

- Validate parameters: `[ValidateSet()]`, `[ValidatePattern()]`, `[ValidateRange()]`, `[ValidateScript()]`.

## Download and execute

- `iwr https://... | iex` or `irm ... | iex` runs remote code without a check.
- Safe: download to a file, check `Get-FileHash` against a published hash, check `Get-AuthenticodeSignature`, then run.
- Instructions that require `-ExecutionPolicy Bypass` or `Set-ExecutionPolicy Unrestricted`: explain the reason, and limit the scope (`-Scope Process`).

## Credentials

- `ConvertTo-SecureString "<literal>" -AsPlainText -Force` with a literal string is a hardcoded password.
- `$password = "..."` or `-Password "..."` in a script → `Get-Credential`, the `Microsoft.PowerShell.SecretManagement` module, or Windows Credential Manager.
- `Export-Clixml` with a credential is protected by DPAPI only on Windows, and only for that user on that machine.
- SecureString is not encryption on Linux and macOS.
- Parameters for secrets use `[PSCredential]` or `[SecureString]`, not `[string]`.

## Logging and output

- `Start-Transcript` records all output, also secrets that the script prints.
- `Write-Host $token`, `Write-Verbose "pwd=$pwd"` → do not print secrets.
- Script block logging (event 4104) records script text, also literal secrets.

## TLS and remote access

- `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }` and `-SkipCertificateCheck` disable TLS checks.
- `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"`, CredSSP, `-Authentication Basic` over HTTP → avoid.

## Files and paths

- Use `-LiteralPath`, not `-Path`, for paths from input: `-Path` treats `[ ] * ?` as wildcards.
- `Remove-Item -Recurse -Force` on a path built from a variable: if the variable is empty, the path can become the parent or the drive root. Check that the variable is not empty, resolve it with `Resolve-Path`, check that it is inside the expected root, then delete.
- `Join-Path $base $userInput`: check the result with `Resolve-Path` and `StartsWith($base)`.
- Temporary files: `[System.IO.Path]::GetTempFileName()` or `New-TemporaryFile`, not fixed names in `$env:TEMP`.

## Privileges and persistence

- `#Requires -RunAsAdministrator` only when needed. Explain why the script needs admin rights.
- A script that creates scheduled tasks, services, Run registry keys or firewall rules: list each of them in the report as a persistence change.
- Do not turn off Windows Defender, the firewall or UAC as a "fix".

## Static analysis

- `Invoke-ScriptAnalyzer -Path . -Recurse` (module PSScriptAnalyzer). Relevant rules: `PSAvoidUsingInvokeExpression`, `PSAvoidUsingPlainTextForPassword`, `PSAvoidUsingConvertToSecureStringWithPlainText`, `PSUsePSCredentialType`, `PSAvoidUsingUsernameAndPasswordParams`.

# C# and .NET (ASP.NET Core): dangerous sinks and safe replacements

## Deserialization and XML

| Dangerous on untrusted data | Why | Safe |
|---|---|---|
| `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `LosFormatter`, `ObjectStateFormatter` | remote code execution (CWE-502) | `System.Text.Json` with fixed types |
| Json.NET `TypeNameHandling` other than `None` | the input selects the type | `TypeNameHandling.None`; a custom `SerializationBinder` allowlist if types are required |
| `JavaScriptSerializer` with `SimpleTypeResolver` | the input selects the type | no resolver |
| `XmlSerializer` or `DataContractSerializer` with a type taken from input | the input selects the type | fixed types |
| `XmlDocument`, `XmlTextReader`, `XPathDocument` on .NET Framework before 4.5.2; any reader with `DtdProcessing.Parse` | XXE (CWE-611) | `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }` |

## Injection

- SQL: `new SqlCommand("... " + x)`, Dapper `Query("... " + x)` → parameters (`@id`).
- Entity Framework: `FromSqlRaw($"...{x}")`, `ExecuteSqlRaw` with concatenation or interpolation → `FromSqlInterpolated` / `FromSql`, or LINQ.
- OS commands: `Process.Start("cmd", "/c " + x)`, `UseShellExecute = true` with input → `ProcessStartInfo` with `ArgumentList.Add(arg)` and `UseShellExecute = false`.
- Code: `CSharpScript.EvaluateAsync(input)`, `Assembly.Load(bytes)` from input, `Type.GetType(input)` followed by `Activator.CreateInstance`.
- LDAP filters and XPath built by concatenation → encode the value.

## Files and paths

- `Path.Combine(base, user)` returns `user` alone when `user` is rooted → `var p = Path.GetFullPath(Path.Combine(baseDir, user)); if (!p.StartsWith(baseDir + Path.DirectorySeparatorChar)) throw ...`.
- `IFormFile.FileName` comes from the client: use `Path.GetRandomFileName()` for storage.
- `ZipFile.ExtractToDirectory` on an untrusted archive: check each entry path on .NET Framework, and limit the total size on every version.
- `PhysicalFile(userPath, ...)`, `File.ReadAllText(userPath)` → the check above.

## ASP.NET Core

- Authorization: a controller or endpoint without `[Authorize]` or `RequireAuthorization()`. Prefer a fallback policy that requires an authenticated user, then mark public routes with `[AllowAnonymous]`.
- Resource ownership: `[Authorize]` checks the user, not the object. Query with the user ID from `User`, or use `IAuthorizationService`.
- CSRF: cookie authentication needs `[ValidateAntiForgeryToken]` or `AutoValidateAntiforgeryToken`. `[IgnoreAntiforgeryToken]` on a state-changing action is a finding.
- Over-posting: an EF entity bound from the request → a DTO, or `[Bind]` with listed fields.
- XSS: `Html.Raw(x)`, `new HtmlString(x)`, Blazor `(MarkupString)x` with user data.
- Open redirect: `Redirect(url)` → `LocalRedirect(url)` or `Url.IsLocalUrl(url)`.
- CORS: `AllowAnyOrigin()` with credentials, or `SetIsOriginAllowed(_ => true)`.
- `UseDeveloperExceptionPage()` outside the Development environment. `ASPNETCORE_ENVIRONMENT=Development` in production.
- Missing `UseHttpsRedirection()` and `UseHsts()`. Cookies without `HttpOnly`, `SecurePolicy = Always`, `SameSite`.
- Request limits: `[RequestSizeLimit]`, Kestrel `MaxRequestBodySize`, `FormOptions.MultipartBodyLengthLimit`.
- Secrets in `appsettings.json` → user secrets in development; environment or Key Vault in production.
- Legacy `web.config`: `<customErrors mode="Off">`, `debug="true"`, `validateRequest="false"`, a literal `<machineKey>`, `enableViewStateMac="false"`.

## Crypto and randomness

- `System.Random` for tokens → `RandomNumberGenerator.GetBytes(32)`.
- `MD5`, `SHA1`, `DES`, `TripleDES`, `CipherMode.ECB` → `AesGcm`; SHA-256 or better for hashes.
- Password hashing: `PasswordHasher<TUser>` (ASP.NET Core Identity), or `Rfc2898DeriveBytes.Pbkdf2` with SHA-256 and ≥ 600,000 iterations. A single hash is a finding.
- `==` or `SequenceEqual` for tokens and MACs → `CryptographicOperations.FixedTimeEquals`.
- TLS checks off: `ServerCertificateCustomValidationCallback = (...) => true`, `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`, `ServicePointManager.ServerCertificateValidationCallback`.
- JWT: `TokenValidationParameters` with `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime` or `ValidateIssuerSigningKey` set to `false`, or `RequireSignedTokens = false`.

## Other

- `new Regex(pattern)` on input without a timeout → pass `matchTimeout`, or use `RegexOptions.NonBacktracking` (.NET 7+).
- `HttpClient` with a user URL → SSRF (see checklist A). Set `Timeout`.
- `unsafe` blocks, `stackalloc` with a size from input, `Marshal.Copy`, `Span<T>` from raw pointers, `[DllImport]` with a relative library name: see `c-cpp.md`.
- Logging input with string interpolation: use structured logging (`logger.LogInformation("user {Name}", name)`).

## NuGet

- Commit `packages.lock.json` and restore with `--locked-mode` in CI.
- `nuget.config` with more than one source needs `<packageSourceMapping>` (dependency confusion).
- `dotnet list package --vulnerable --include-transitive` needs a restored project. Ask before you run `dotnet restore`.
- MSBuild targets in a project or package run code at build time. Do not build an untrusted project outside a sandbox.

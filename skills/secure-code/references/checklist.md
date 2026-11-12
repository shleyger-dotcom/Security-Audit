# Security checklist (language-independent)

Mark each section as: checked / not applicable / cannot verify from code. Items marked **(ask)** usually cannot be verified from code: put them in "Cannot verify from code — questions".

Mapped to OWASP Top 10:2025 (A01–A10), OWASP API Security Top 10:2023 and CWE.

## A. Access control (A01)

- [ ] Every protected endpoint checks authentication on the server.
- [ ] Every access to an object by ID checks that this user owns it or has permission (IDOR, CWE-639). Check read, update, delete and export separately.
- [ ] Admin functions check the role on the server (CWE-285). Hiding a button in the UI is not access control.
- [ ] Role, user ID, price, or "is_admin" never come from client fields, hidden inputs, headers or unverified JWT payloads (CWE-602).
- [ ] Mass assignment: the code writes only allowlisted fields from the request body (CWE-915). Example attack: `{"role": "admin"}` in a profile update.
- [ ] CSRF: state-changing requests that use cookie sessions need `SameSite=Lax/Strict` plus a CSRF token or an origin check (CWE-352). No state change through GET.
- [ ] CORS: no `*` and no reflected origin together with credentials.
- [ ] Open redirect: redirect targets are relative paths or allowlisted hosts (CWE-601).
- [ ] SSRF: server-side fetches of user-influenced URLs allow only listed schemes and hosts, block private, loopback and link-local addresses (`169.254.169.254` = cloud metadata) for IPv4 and IPv6, and do not follow redirects (CWE-918). The check resolves all DNS records of the host and rejects the request if one of them is a blocked address. DNS rebinding: pin the resolved IP for high-risk features.
- [ ] Path traversal: a file path built from input is resolved and then checked to stay inside an allowed root (CWE-22). Example attack: `../../.env`.
- [ ] Archive extraction checks every entry path (zip slip, CWE-22) and total size (zip bomb, CWE-409).
- [ ] Multi-tenant data: every query filters by tenant on the server.

## B. Injection (A05)

- [ ] SQL: parameterized queries only (CWE-89). Table names, column names and `ORDER BY` come from an allowlist, because parameters cannot replace identifiers.
- [ ] NoSQL: query objects are not built from raw JSON input (CWE-943). Example attack: `{"password": {"$ne": null}}`.
- [ ] OS commands: argument list, no shell, no string concatenation (CWE-78).
- [ ] Code injection: no `eval`, `exec`, `new Function`, `Invoke-Expression` on input (CWE-94).
- [ ] Template injection: templates never come from input (SSTI, CWE-1336).
- [ ] XSS: output encoding for the right context — HTML body, attribute, JavaScript, URL (CWE-79). URLs from input allow only `http:`/`https:` (block `javascript:`).
- [ ] HTTP header and log injection: remove CR/LF from input before it goes to headers or logs (CWE-113, CWE-117).
- [ ] XML: external entities disabled (XXE, CWE-611).
- [ ] Deserialization: no native deserializers (pickle, Java serialization, `node-serialize`, unsafe YAML) on untrusted data (CWE-502).
- [ ] Regex on input: no catastrophic backtracking patterns, or a length limit or timeout (ReDoS, CWE-1333).
- [ ] CSV/Excel export: cells that start with `= + - @` are escaped (formula injection, CWE-1236).
- [ ] LDAP, XPath, email headers: input is escaped for that syntax.
- [ ] Dynamic SQL inside the database: stored procedures and functions that build a statement from text (`EXEC(@sql)`, `EXECUTE IMMEDIATE`, `PREPARE` from a concatenated string) use bound parameters (`sp_executesql`, `USING`). PostgreSQL `SECURITY DEFINER` functions set `search_path`.
- [ ] HTTP parameter pollution: a parameter that occurs twice has the same value in the validation step and in the step that uses it (CWE-235).
- [ ] Second-order injection: data that the application stored earlier (database rows, file names, queue messages, profile fields) is still untrusted when it reaches a sink. The same parameterization and encoding apply.

## C. Authentication and sessions (A07)

- [ ] Password hashing: Argon2id (min. 19 MiB memory, 2 iterations), bcrypt (cost ≥ 10; input is cut at 72 bytes), scrypt, or PBKDF2-HMAC-SHA256 with ≥ 600,000 iterations. Never plaintext, MD5, SHA-1 or a single SHA-256.
- [ ] Rate limit on login, registration, password reset and MFA code entry. With more than one instance, the counter is in a shared store (Redis), not in memory.
- [ ] Account lockout or growing delay after repeated failures, with a notification to the user.
- [ ] Same error message for "no such user" and "wrong password", and same response time (user enumeration, CWE-204).
- [ ] Password reset token: ≥ 128 bits from a CSPRNG, single use, expires in ≤ 1 hour, stored as a hash. The reset link uses the host from config, not the `Host` header (CWE-640).
- [ ] New session ID after login and after privilege change (session fixation, CWE-384). Logout ends the session on the server.
- [ ] Session cookie: `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`, limited lifetime. Prefer the `__Host-` prefix.
- [ ] Auth tokens are not in `localStorage` or `sessionStorage`.
- [ ] JWT: signature verified with a fixed algorithm list (reject `none`, block RS256→HS256 confusion), `exp`, `iss`, `aud` checked, no secrets in the payload, short lifetime, a way to revoke.
- [ ] OAuth/OIDC: `state` and PKCE, exact match of `redirect_uri`, ID token validated.
- [ ] Token, HMAC and API key comparison takes constant time (CWE-208).
- [ ] Password rules: a minimum length of at least 8 characters (longer without MFA), a maximum of at least 64, no forced character classes, and a check against lists of breached passwords (NIST SP 800-63B).
- [ ] A change of password, email address or MFA settings needs the current password or a new login. A password change or reset ends all other sessions of that user. The old email address gets a notification.
- [ ] No default or test accounts (`admin:admin`, `test:test`) in production code, seed data or migrations (CWE-1392).
- [ ] Inbound webhooks (Stripe, GitHub, Telegram, …): the server verifies the signature of the raw request body with a constant-time comparison before any processing, and rejects old timestamps and repeated event IDs (replay, CWE-345, CWE-294).
- [ ] User names and email addresses are normalized (Unicode NFKC, case folding) before the uniqueness check and before each comparison. Without this, a look-alike name can take over an account (CWE-176).
- [ ] SAML and other SSO: a maintained library validates the signature of the assertion itself, and checks audience, recipient, `NotOnOrAfter` and `InResponseTo`. Homemade XML signature checks are a finding (signature wrapping, CWE-347).
- [ ] MFA for admin and sensitive accounts **(ask)**.

## D. Cryptography and randomness (A04)

- [ ] Tokens, IDs that must be unguessable, and salts come from a CSPRNG (CWE-338).
- [ ] No MD5 or SHA-1 for security purposes (CWE-327). No ECB mode. Unique IV or nonce for each encryption. Prefer AEAD: AES-GCM or ChaCha20-Poly1305.
- [ ] No homemade crypto algorithms or protocols.
- [ ] TLS certificate verification is on for all outbound connections (CWE-295).
- [ ] Keys come from the environment or a key manager, never from code.

## E. Data exposure and error handling (A02, A10)

- [ ] Responses contain only allowlisted fields. No password hashes, reset tokens or internal IDs (CWE-200).
- [ ] Production errors are generic. Stack traces, SQL text and file paths go to server logs only (CWE-209).
- [ ] Debug mode is off in production.
- [ ] Logs do not contain passwords, tokens, `Authorization` headers, full card numbers or unnecessary personal data (CWE-532).
- [ ] Private pages send `Cache-Control: no-store`.
- [ ] A CDN or shared cache does not store private responses. Check web cache deception (a private page requested as `/account/x.css`) and cache poisoning (a request header that changes the response but is not part of the cache key).
- [ ] Internal IP addresses and private host names are not in client responses, frontend code or a public repository.
- [ ] No source maps, `.git` folder, `.env` file or directory listing on the public web server.
- [ ] Fail closed: an exception inside an authorization or validation check denies the request (CWE-636). No empty `except`/`catch` around security checks.
- [ ] A failed multi-step operation rolls back. No half-done state (money withdrawn, order not created).
- [ ] Personal data: see section M.

## F. Business logic and concurrency (A06)

- [ ] Race conditions: check-then-act on balance, stock, coupons or votes runs in one transaction with a row lock or a unique constraint (CWE-362).
- [ ] Payments and other non-repeatable actions use idempotency keys.
- [ ] Quantities, amounts and dates are range-checked: no negative, zero or huge values where they make no sense.
- [ ] The server calculates prices, discounts and totals. It never trusts them from the client.
- [ ] Multi-step flows (checkout, registration, password reset) cannot skip a step.
- [ ] Money uses integers (cents) or decimal types, never float.

## G. Files

- [ ] Upload: extension allowlist, MIME type allowlist and magic-byte check. The client `Content-Type` and the file name prove nothing.
- [ ] Upload size limit on the server.
- [ ] The server saves an upload under a random name (for example UUID4), never under the name from the user.
- [ ] Uploads are stored outside the web root, without execute permission, or in object storage.
- [ ] SVG and HTML uploads are served with `Content-Disposition: attachment` or from a separate domain (stored XSS).
- [ ] Image processing has pixel limits (decompression bomb).
- [ ] Temporary files are created with secure APIs (CWE-377). Secret files have restrictive permissions.
- [ ] Delete, move and overwrite of a path that comes from data (request, job payload, config value, database row, command line of another process, LLM output). A check of the path format is not enough. Before the operation the code does all three checks (CWE-22, CWE-59, CWE-73):
  1. It resolves symlinks, then checks that the result is inside an allowlisted root.
  2. It checks that the result is at least one level below that root. The root itself is never a target.
  3. It reads evidence that the target belongs to this user, job or application (a database record, the file owner, a marker that the application wrote).

  On a failed check the code logs the rejected path and stops. It does not fall back to a default or wider path. Limits: an attacker who can write files inside the root can copy a marker, and the target can change between the check and the operation (TOCTOU, CWE-367). For high-risk targets, operate on an open directory handle or run as a user with minimal rights.

## H. Resource limits

- [ ] Request body size limit, JSON depth limit.
- [ ] Timeouts on all outbound HTTP, database and LLM calls.
- [ ] Pagination with a maximum page size.
- [ ] GraphQL: depth and complexity limits; introspection off in production.
- [ ] WebSocket: authentication on connect, `Origin` check, message size limit.
- [ ] No unbounded loops, recursion or memory growth controlled by input.

## I. Supply chain (A03)

- [ ] A lockfile is committed. CI installs from the lockfile only (`npm ci`, `pip install --require-hashes`, `uv sync --locked`).
- [ ] Dependencies were checked with an audit tool, and reachable critical/high findings are fixed.
- [ ] Each new package exists, is the intended one, and is maintained: check name spelling (typosquatting), age, downloads, repository. AI assistants sometimes suggest package names that do not exist; attackers register such names (slopsquatting).
- [ ] Install scripts of dependencies are not run blindly (see `tools.md`). The list of packages that can run install scripts is short, reviewed and committed. An allow-all setting is a finding.
- [ ] One package manager for each project folder. Two lockfiles in the same folder (`package-lock.json` with `yarn.lock` or `pnpm-lock.yaml`), or a `packageManager` field, lockfile and CI command that do not agree, are a finding: the reviewed lockfile is possibly not the installed one.
- [ ] A change of the lockfile or of the install-script list is reviewed together with the dependency change that caused it. A lockfile change without a manifest change needs an explanation.
- [ ] Registry signatures and provenance are verified where the ecosystem supports it (see `tools.md`). A missing signature is a reason to look closer, not a proof of an attack.
- [ ] CI actions are pinned to a full commit SHA. CDN scripts have `integrity` (SRI).
- [ ] Unused dependencies are removed.
- [ ] Dependency confusion: private package names cannot be taken from a public registry. npm: a scope (`@org/name`) bound to the private registry. pip: `--index-url`, not `--extra-index-url`.
- [ ] Integrity of downloads (A08, CWE-494): the code verifies a checksum or signature of downloaded binaries, models, plugins and updates before it uses them. Auto-update verifies a signature, not only TLS.
- [ ] Hidden characters: no bidirectional control characters (U+202A–U+202E, U+2066–U+2069) and no Unicode tag characters (U+E0000–U+E007F) in source, config or prompt files. They make code or instructions that a reviewer does not see (Trojan Source, hidden prompt injection).

## J. Logging and alerting (A09)

- [ ] The server logs security events: failed and successful logins, password and MFA changes, permission changes, admin actions, bulk exports.
- [ ] Logs cannot be changed by the application user. Logs have a retention period.
- [ ] Alerts for spikes of failed logins and abnormal bulk exports **(ask)**.

## K. Infrastructure and operations (A02)

- [ ] The application database user has minimal rights. Never `root`, `postgres`, `sa` or an admin account. Read-only services use read-only users.
- [ ] Each service and API key has its own minimal scope.
- [ ] No forgotten test endpoints, debug routes or old API versions in production.
- [ ] `Server` and `X-Powered-By` headers do not show versions.
- [ ] Database and admin ports are reachable only from the backend network **(ask)**.
- [ ] Admin panels are on a separate network or behind VPN/SSO **(ask)**.
- [ ] Backups are encrypted, stored apart from the main servers, and a restore was tested **(ask)**.
- [ ] Secrets that were ever committed or shared are revoked and replaced **(ask)**. The order is: revoke and replace first, then clean the git history. A secret that reached a remote is compromised, and a history rewrite does not change that.
- [ ] Subdomain takeover: no DNS record (CNAME, ALIAS) points to a cloud resource that was deleted (bucket, app service, pages site). Check DNS records in IaC files; otherwise **(ask)**. Session cookies are not scoped to a parent domain that has untrusted subdomains.
- [ ] Email domain has SPF, DKIM and DMARC **(ask)**.

## L. APIs, protocols and third parties

Mapped to the OWASP API Security Top 10:2023 where it adds to the sections above.

- [ ] Third-party data (API10): responses from partner APIs, payloads of webhooks and scraped pages are validated like user input before they reach a sink. Calls have timeouts, and redirects are not followed blindly.
- [ ] Sensitive business flows (API6): registration, purchase of limited stock, coupon use, sending SMS or email, password reset and invitations have limits for each user and each IP address. Flows where abuse costs money have bot protection (CAPTCHA or similar). Example attack: a script requests thousands of SMS codes to premium numbers.
- [ ] API inventory (API9): no old API versions, undocumented routes or staging hosts with production data. Swagger UI, GraphQL playground and admin tools are not public in production.
- [ ] Host header: links, redirects and cache keys use the host name from config. The framework has an allowlist of host names (`ALLOWED_HOSTS`, `config.hosts`, `server_name`). `X-Forwarded-*` headers are trusted only from the known proxy.
- [ ] HTTP request smuggling (CWE-444): the application does not parse raw HTTP itself. The proxy and the backend are current versions, and the proxy rejects requests with both `Content-Length` and `Transfer-Encoding`. From code you can check the config files; the rest is **(ask)**.
- [ ] gRPC: an authentication interceptor covers every service and method. TLS is on. Maximum message size and deadlines are set. Server reflection is off in production. Protobuf types do not check ranges or formats: validate fields in code.
- [ ] Email: input does not reach recipient lists, subjects or headers without validation. HTML email templates escape user data.
- [ ] Clickjacking: pages with actions send `frame-ancestors` (see `web-and-config.md`).

## M. Personal data and privacy

Sections A–L ask "can an attacker read the data?" This section asks "must the application hold the data, and for how long?" Mapped to GDPR and CCPA principles and CWE-359.

- [ ] Each stored field has a class: not personal, personal (name, email address, phone, IP address, device ID), or sensitive (health, finance, biometrics, exact location, government ID, data of children). The schema or a data map shows the class. Sensitive fields are encrypted at rest and have a smaller group of readers.
- [ ] Each personal field has a stated purpose. A field that no feature reads is a finding candidate (data minimization).
- [ ] No personal data in telemetry, analytics events, error reports or URLs (query strings go to logs and `Referer` headers). Use an internal ID, not an email address or a name.
- [ ] Each store of personal data has a retention limit, and a job or TTL that deletes the data. The limit also covers backups, caches, search indexes and analytics copies.
- [ ] Export and deletion work for one user from end to end. Deletion removes or anonymizes the data. A `deleted = true` flag that keeps the personal data forever is a finding.
- [ ] One user ID finds all personal data of that user. Data copied into free text or into other systems without that ID cannot be deleted on request.
- [ ] Consent: collection that needs consent, and each transfer to a third party (analytics, advertising, LLM provider), happens only after consent. The server stores who agreed, when, and to which text version. A withdrawal stops the processing.
- [ ] Each third party that receives personal data has a data processing agreement **(ask)**.
- [ ] Region rules (storage location, consent model, age limits) come from configuration, not from constants in code.
- [ ] A leak of personal data starts a legal notification deadline (GDPR: 72 hours to the regulator). An incident procedure with an owner exists **(ask)**.

# JavaScript / TypeScript: dangerous sinks and safe replacements

## Browser: DOM XSS

| Dangerous with untrusted data | Safe |
|---|---|
| `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` | `textContent`; `DOMPurify.sanitize()` if HTML is required |
| jQuery `.html()`, `$(userString)`, `.append(userString)` | `.text()` |
| React `dangerouslySetInnerHTML` | normal JSX `{value}` (escaped); DOMPurify if HTML is required |
| Vue `v-html`, Svelte `{@html}`, Angular `bypassSecurityTrust*` | normal binding |
| `href`, `src`, `action`, `formaction` with a user URL | allow only `http:` and `https:` schemes; block `javascript:` and `data:` |
| `location = user`, `location.href = user`, `window.open(user)` | relative paths or an allowlist (open redirect, DOM XSS) |
| `eval`, `new Function`, `setTimeout(string)`, `setInterval(string)` | functions, `JSON.parse` |

Other browser checks:
- `window.addEventListener("message", ...)` without a check of `event.origin`.
- `postMessage(data, "*")` with private data.
- Auth tokens in `localStorage` or `sessionStorage`.
- Any API key in frontend code is public. This includes `NEXT_PUBLIC_*`, `VITE_*` and `REACT_APP_*` variables.

## Node.js: processes, files, code

- `child_process.exec`, `execSync`, or `spawn(..., { shell: true })` with input → `execFile` or `spawn(cmd, [args])` without shell.
- `path.join(base, user)` → resolve, then check: `const p = path.resolve(base, user); if (!p.startsWith(path.resolve(base) + path.sep)) throw ...`.
- `fs.readFile` / `res.sendFile` with a user path → the same check; `res.sendFile(name, { root })`.
- The `vm` module is not a security sandbox.
- `node-serialize`, `serialize-javascript` output passed to `eval` → JSON.

## Prototype pollution (CWE-1321)

- `obj[userKey] = value`, recursive merge or deep-extend of JSON input, `lodash.merge`/`_.set` with user paths on old versions.
- Example attack: `{"__proto__": {"isAdmin": true}}`.
- Safe: `Map`, `Object.create(null)`, a key allowlist, block `__proto__`, `constructor` and `prototype`.

## Databases

- SQL: template literals in `query()`, `knex.raw(string)`, `sequelize.query(string)` → placeholders (`$1`, `?`) or `replacements` / bind parameters. Prisma `$queryRawUnsafe` → `$queryRaw` tagged template.
- MongoDB: `find({ user: req.body.user })` where the value can be an object such as `{"$ne": null}` → validate the type with a schema; Mongoose `sanitizeFilter: true`; never `$where` with input.

## Express

- No `helmet()` (security headers). `x-powered-by` is on: `app.disable("x-powered-by")`.
- `express.json()` without `limit`.
- `cors({ origin: true, credentials: true })` reflects any origin.
- An error handler that sends `err.stack` or `err.message` to the client.
- `app.set("trust proxy", true)` without a real proxy: the client can fake the IP with `X-Forwarded-For`, and the rate limit fails.
- `express-rate-limit` with the default in-memory store and more than one instance.
- Cookie and session options: `httpOnly`, `secure`, `sameSite`, `maxAge`.

## Next.js and other meta-frameworks

- Middleware alone is not authorization. CVE-2025-29927 allowed a bypass with the `x-middleware-subrequest` header. Check auth again in each route handler, server action and data fetch.
- Server Actions and API routes are public HTTP endpoints. Each needs auth and input validation.
- Secrets in `NEXT_PUBLIC_*` go to the browser.
- Source maps in production (`productionBrowserSourceMaps`).

## Auth and crypto

- `jsonwebtoken`: `jwt.decode()` used instead of `jwt.verify()`; `verify()` without `{ algorithms: [...] }`.
- `Math.random()` for tokens → `crypto.randomBytes(32)`, `crypto.randomUUID()`.
- `===` for token comparison → `crypto.timingSafeEqual` (buffers of equal length).
- `crypto.createCipher` (no IV, removed in Node 22) → `createCipheriv("aes-256-gcm", key, iv)`.
- Password hashing: `bcrypt`, `argon2`, or `crypto.scrypt`; never `createHash("sha256")` alone.
- `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized: false`, `https.Agent({ rejectUnauthorized: false })`.

## Validation and types

- TypeScript types and `as` casts do not validate data at runtime. Validate request bodies with a schema (zod, valibot, ajv).
- Regex on input: nested quantifiers such as `(a+)+$` → ReDoS. Limit the length or use a safe pattern.

## SSRF

- `fetch`, `axios`, `got` with a user URL. Note: axios and fetch follow redirects by default. See checklist A.

## npm supply chain

- `package-lock.json` (or the pnpm/yarn lockfile) is committed. CI uses `npm ci`.
- Run `npm audit` (it reads the lockfile and does not run install scripts).
- Dependency install scripts: install with `--ignore-scripts` first, then allow only the reviewed packages.
- Review new packages: name spelling, age, maintainers, weekly downloads.
- `npx some-package` downloads and runs code.

## Electron

- `nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false`, `shell.openExternal(userUrl)` without a scheme check.

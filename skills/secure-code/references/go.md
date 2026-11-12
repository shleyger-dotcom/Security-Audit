# Go: dangerous patterns and safe replacements

## Injection

- OS commands: `exec.Command("sh", "-c", input)`, `exec.Command("bash", "-c", ...)` → `exec.Command("prog", arg1, arg2)`. Put `--` before arguments from input: a value that starts with `-` is read as an option.
- SQL: `db.Query(fmt.Sprintf("... %s", x))`, `db.Exec("... " + x)` → placeholders (`$1`, `?`).
- GORM: `db.Where(fmt.Sprintf(...))`, `db.Raw(str)`, `db.Order(input)`, `db.Table(input)` → `db.Where("name = ?", x)`; an allowlist for column and table names.
- Templates: `text/template` for HTML output does not escape → `html/template`.
- `template.HTML(x)`, `template.JS(x)`, `template.URL(x)` with user data turn escaping off.
- Go has no `eval`, but plugins (`plugin.Open`), `go run` and `yaegi` on input run code.

## Files and paths

- `filepath.Join(base, user)` cleans the path but does not keep it inside `base` → `filepath.IsLocal(user)` (Go 1.20+), or `os.OpenRoot(base)` (Go 1.24+), or check with `filepath.Rel`.
- `http.ServeFile(w, r, userPath)` → `http.FileServer(http.Dir(root))`.
- `archive/zip` and `archive/tar`: check each entry name with `filepath.IsLocal`, and limit the total size.
- `os.CreateTemp`, not a fixed name in `/tmp`. `os.WriteFile(name, data, 0600)` for secret files, not `0644` or `0777`.

## HTTP servers and clients

- `http.ListenAndServe(addr, h)` has no timeouts (Slowloris) → `&http.Server{ReadHeaderTimeout: ..., ReadTimeout: ..., WriteTimeout: ..., IdleTimeout: ...}`.
- `io.ReadAll(r.Body)` without a limit → `http.MaxBytesReader(w, r.Body, max)`.
- `http.Get`, `http.DefaultClient` have no timeout → `&http.Client{Timeout: ...}`.
- User URL in a client call → SSRF. The client follows up to 10 redirects: set `CheckRedirect`, and block private addresses in the dialer `Control` function (this also stops DNS rebinding).
- `tls.Config{InsecureSkipVerify: true}` disables TLS checks. Set `MinVersion: tls.VersionTLS12`.
- `import _ "net/http/pprof"` and `expvar` register debug handlers on the default mux: do not serve it on a public port.
- Gin: `gin.Default()` trusts all proxies → `SetTrustedProxies`. `c.ShouldBindJSON(&dbModel)` → bind to a struct with only the allowed fields (mass assignment).
- CORS middleware with `AllowAllOrigins` and credentials.

## Crypto and randomness

- `math/rand` for tokens → `crypto/rand` (`rand.Read`, `rand.Text` in Go 1.24+).
- `md5`, `sha1`, `des`, `rc4`; AES with `cipher.NewCBCEncrypter` and no MAC → `cipher.NewGCM` with a new nonce for each message.
- Passwords: `golang.org/x/crypto/bcrypt` or `argon2`, not a single hash.
- `==` or `bytes.Equal` for tokens and MACs → `subtle.ConstantTimeCompare`, `hmac.Equal`.
- JWT (`golang-jwt`): the key function must check the type of `token.Method`. `ParseUnverified` must not be used for authentication. Pass `jwt.WithValidMethods`.

## Errors, integers and concurrency

- An ignored error on a security check (`ok, _ := verify(...)`, `_ = tx.Commit()`) is a finding candidate.
- `strconv.Atoi` followed by a cast to `int32`/`int16`/`uint` can overflow (CWE-190) → `strconv.ParseInt(s, 10, 32)`.
- An index or slice bound from input causes a panic → check the range. A panic in a goroutine without `recover` stops the whole process (denial of service).
- A map written from more than one goroutine crashes the process → `sync.Mutex` or `sync.Map`. `go test -race` finds data races; it runs project code, so ask first.
- One goroutine for each request without a limit, and unbuffered work without a `context` deadline → resource exhaustion.
- `unsafe`, `cgo`, `reflect` on input, `//go:linkname`: see `c-cpp.md` for memory rules.

## Modules

- `go.sum` is committed. CI uses `-mod=readonly`.
- `GOINSECURE`, `GONOSUMDB`, `GOSUMDB=off` and the deprecated `go get -insecure` turn checks off: allow them only for named private modules (`GOPRIVATE`).
- `replace` directives that point to a fork or a local path: review them.
- `//go:generate` lines and `go run pkg@latest` run code: read them before you run `go generate`.
- `govulncheck ./...` reports only vulnerabilities that the code can reach.

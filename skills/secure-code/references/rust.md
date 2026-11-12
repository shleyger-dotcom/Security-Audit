# Rust: dangerous patterns and safe replacements

Safe Rust prevents memory corruption. It does not prevent injection, logic errors, panics or denial of service.

## `unsafe`

- Review every `unsafe` block, `unsafe fn` and `unsafe impl`. Each needs a `// SAFETY:` comment that states why the invariants hold. A missing or wrong reason is a finding candidate.
- High-risk calls: `std::mem::transmute`, `slice::from_raw_parts`, `get_unchecked`, `Vec::set_len`, `String::from_utf8_unchecked`, `MaybeUninit::assume_init`, raw pointer dereference, `static mut`, `unsafe impl Send/Sync`.
- A length, index or pointer that comes from input and reaches `unsafe` code without a check is a memory-safety bug.
- FFI (`extern "C"`, `bindgen`, `#[no_mangle]`): the C side follows `c-cpp.md`. Check string conversions (`CStr`, `CString`), ownership, and who frees the memory.

## Panics (denial of service)

- On input, these panic: `unwrap`, `expect`, `v[i]`, `&s[a..b]` (also when the index is inside a UTF-8 character), division by zero, `RefCell` double borrow, `unreachable!`.
- Safe: `get(i)`, `s.get(a..b)`, `?` with an error type, `checked_div`.
- A panic in one request handler must not stop the server. Check the framework behavior and `panic = "abort"` in `Cargo.toml`.

## Integers

- Arithmetic overflow wraps silently in release builds (CWE-190) → `checked_add`, `checked_mul`, `saturating_*`, or `overflow-checks = true` in `[profile.release]`.
- `as` casts cut the value (`u64 as u32`, `i64 as usize`) → `u32::try_from(x)?`.

## Injection

- OS commands: `Command::new("sh").arg("-c").arg(format!(...))` → `Command::new("prog").arg(a).arg(b)`.
- Windows: arguments for `.bat` and `.cmd` files are not escaped safely before Rust 1.77.2 (CVE-2024-24576).
- SQL: `sqlx::query(&format!(...))`, `diesel::sql_query(format!(...))`, `rusqlite` with `format!` → `sqlx::query!("... $1", x)`, `.bind(x)`, `params![x]`.
- HTML: `|safe` in Askama and Tera, `PreEscaped` in Maud, `Html(format!(...))` in axum with user data.

## Files and paths

- `base.join(user)` returns `user` alone when `user` is absolute, and keeps `..` → `let p = base.join(user).canonicalize()?; if !p.starts_with(&base) { ... }`.
- `tar` and `zip` crates: use the current version and its safe extract API; check entry names and total size.
- `tempfile` crate for temporary files, not fixed names.

## Web services (axum, actix-web, rocket)

- Body size limits (`DefaultBodyLimit`, `PayloadConfig`) and timeouts (`tower_http::timeout::TimeoutLayer`). Hyper has no request timeout by default.
- Authentication as an extractor or middleware on every protected route. A route added outside the protected router is a finding candidate.
- `CorsLayer::permissive()` or `very_permissive()` in production.
- Deserialization with `serde` on untrusted data: limit size and depth. `bincode` needs a size limit (`with_limit`).
- `reqwest` with a user URL → SSRF (see checklist A). `danger_accept_invalid_certs(true)` and `danger_accept_invalid_hostnames(true)` disable TLS checks.

## Crypto and randomness

- `rand::thread_rng()` / `rand::rng()` and `OsRng` are suitable for secrets. `SmallRng`, `fastrand`, `oorandom` and a fixed seed are not.
- `==` on secrets, tokens and MACs → `subtle::ConstantTimeEq`, or the `verify` function of the MAC crate.
- Passwords: `argon2`, `scrypt` or `bcrypt` crates. Wipe keys with `zeroize`.
- Use reviewed crates (`ring`, `aws-lc-rs`, RustCrypto). No homemade algorithms.

## Async and resources

- Blocking calls (`std::fs`, `std::thread::sleep`, heavy CPU work) inside async tasks stop the executor → `spawn_blocking`.
- `std::sync::Mutex` held across `.await` can deadlock.
- `mpsc::unbounded_channel` and `Vec::with_capacity(n)` with `n` from input → bounded channels and a size limit.
- The `regex` crate runs in linear time. `fancy-regex` and `pcre2` can backtrack (ReDoS).

## Cargo supply chain

- `Cargo.lock` is committed for binaries. CI builds with `--locked`.
- `build.rs` and procedural macros run code at build time, also in dependencies. Do not build an untrusted project outside a sandbox.
- Git dependencies are pinned with `rev = "<commit>"`. Review `[patch]` and `[replace]` sections.
- `cargo audit` reads `Cargo.lock` and does not build. `cargo deny` and `cargo vet` add policy checks.

# C and C++: dangerous patterns and safe replacements

In C and C++, a single bounds error can give remote code execution. Check every read of external data (network, files, arguments, environment, IPC) for size and type before use.

## Unsafe string and buffer functions (CWE-120, CWE-787)

| Dangerous | Problem | Safe |
|---|---|---|
| `gets` | no length limit (removed in C11) | `fgets(buf, sizeof buf, stdin)` |
| `strcpy`, `strcat`, `wcscpy`, `wcscat` | no destination size | `snprintf(dst, sizeof dst, "%s", src)`; `strlcpy`/`strlcat` where available; `std::string` |
| `sprintf`, `vsprintf` | no destination size | `snprintf`, `vsnprintf`; check the return value for truncation |
| `scanf("%s")`, `sscanf("%s")` | no width | `"%63s"` with a 64-byte buffer; `fgets` + parsing |
| `strncpy` | does not always add `\0` | `snprintf`, or set `dst[n-1] = '\0'` after the call |
| `strtok` | not reentrant, changes input | `strtok_r` / `strtok_s` |
| `memcpy`, `memmove`, `read`, `recv` with a length from input | overflow | check `len <= sizeof dst` (and the remaining buffer) before the call |
| `alloca`, VLA with a size from input | stack overflow | heap allocation with a size limit |

- Off-by-one: a buffer for a string of `n` characters needs `n + 1` bytes.
- Indexes from input: check `0 <= i && i < size` before every access. A signed index can be negative.
- C++: `operator[]` on `std::vector`, `std::array` and `std::string` does not check bounds. At trust boundaries use `.at()` or an explicit check. Prefer `std::span` with a known size over pointer + length.

## Integer problems (CWE-190, CWE-191, CWE-681)

- Size calculations: `malloc(count * size)` can overflow and allocate a small buffer. Use `calloc(count, size)`, or check `count > SIZE_MAX / size` first.
- Additions: `if (offset + len > total)` can overflow. Use `if (len > total || offset > total - len)`, `__builtin_add_overflow`, or C23 `ckd_add`.
- Signed/unsigned mix: a negative `int` becomes a huge `size_t` in `memcpy`. Compile with `-Wsign-compare -Wconversion`.
- Truncation: `size_t` → `int` or `uint16_t` length fields from network packets.
- Signed overflow is undefined behavior. The compiler can remove a check such as `if (x + 1 < x)`.

## Memory lifetime (CWE-416, CWE-415, CWE-401, CWE-476)

- Use after free and double free: set the pointer to `NULL` after `free`; make the owner of each allocation clear.
- Check every `malloc`/`calloc`/`realloc` result for `NULL`. `p = realloc(p, n)` loses the old block on failure: use a temporary pointer.
- C++: raw `new`/`delete` → `std::unique_ptr`, `std::make_unique`, `std::vector`, `std::string` (RAII).
- C++ dangling references: returning a reference or pointer to a local; `std::string_view` or `std::span` to a temporary; iterators after `push_back`/`erase`; lambdas that capture locals by reference and run later.
- Uninitialized memory (CWE-457): initialize structs (`= {0}`, `memset`). Struct padding can leak stack data when the program writes the struct to a socket or file.

## Format strings (CWE-134)

- `printf(user)`, `fprintf(f, user)`, `syslog(LOG_INFO, user)`, `snprintf(buf, n, user)` → `printf("%s", user)`. Example attack: `%n` writes to memory, `%x` reads the stack.
- Compile with `-Wformat=2 -Werror=format-security`.
- C++20 `std::format` checks format strings at compile time.

## Processes and the operating system

- `system`, `popen`, `std::system` with input → `execve` / `posix_spawn` with an argument array (no shell).
- Windows `CreateProcess`: pass the full program path in `lpApplicationName`, and quote paths with spaces (unquoted path, CWE-428). Avoid `ShellExecute` with input.
- Windows DLL loading: `LoadLibrary("name.dll")` searches the current folder (DLL hijacking, CWE-427). Use a full path, `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_SYSTEM32`, and `SetDefaultDllDirectories`.
- setuid/setgid programs: do not trust `PATH`, `LD_PRELOAD`, `IFS` or any `getenv` value. Drop privileges in order (`setgroups`, `setgid`, then `setuid`) and check each return value.

## Files and race conditions

- `access()` then `open()` is a race (TOCTOU, CWE-367). Open first, then check with `fstat` on the file descriptor. Use `O_NOFOLLOW`, and `O_CREAT | O_EXCL` for new files.
- Paths from input: `realpath()` (Windows: `GetFinalPathNameByHandle`), then check that the result is inside the allowed root.
- `tmpnam`, `tempnam`, `mktemp` → `mkstemp` (POSIX) or `GetTempFileName` + exclusive create (Windows).
- Threads: shared data needs a mutex or atomics (data race = undefined behavior). Signal handlers call only async-signal-safe functions.

## Randomness and cryptography

- `rand()`, `srand(time(NULL))`, `std::mt19937`, `std::minstd_rand` are not for tokens, keys or nonces. Use `getrandom()` (Linux), `arc4random_buf` (BSD/macOS), `BCryptGenRandom` (Windows), or libsodium `randombytes_buf`. `std::random_device` is not guaranteed to be secure on every platform.
- Use high-level libraries: libsodium, or OpenSSL EVP APIs. No homemade crypto.
- Check every return value of crypto calls.
- Compare MACs and tokens with `CRYPTO_memcmp` or `sodium_memcmp`, not `memcmp` (timing attack).
- Wipe secrets after use with `explicit_bzero`, `SecureZeroMemory` or `sodium_memzero`. A plain `memset` before `free` can be removed by the optimizer.

## TLS and network

- OpenSSL: `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)`, load trusted CAs, and check the host name (`SSL_set1_host`).
- libcurl: never `CURLOPT_SSL_VERIFYPEER 0` or `CURLOPT_SSL_VERIFYHOST 0`.
- Network parsers: never trust length fields in packets. Check each length against the bytes that were really received.

## SQL

- `sqlite3_exec` with a query built by `sprintf` → `sqlite3_prepare_v2` + `sqlite3_bind_*`. The same applies to other database client libraries: use prepared statements.

## C++ specific

- `reinterpret_cast` and C-style casts between unrelated types → type confusion.
- `std::regex` on input: slow, and recursion can overflow the stack. Limit the input length.
- A destructor must not throw. Exceptions that cross a C API boundary crash the program.
- `assert` is removed when `NDEBUG` is set (release builds). Do not use it for security checks.

## Build hardening

Check `CMakeLists.txt`, `Makefile`, `meson.build` or `.vcxproj` for these flags.

GCC / Clang (release builds):
```
-O2 -Wall -Wextra -Wformat=2 -Wformat-security -Wconversion -Wsign-compare
-D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection
-fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
-fcf-protection=full          # x86-64 only
```
`_FORTIFY_SOURCE` works only with optimization (`-O1` or higher). Version 3 needs GCC 12+ or Clang 16+; otherwise use `2`.

MSVC: `/W4 /sdl /GS /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA`.

Debug and test builds: `-fsanitize=address,undefined` (AddressSanitizer + UBSan); `-fsanitize=thread` for multithreaded code. Building and running sanitizers runs project code: ask the user first.

## Dependencies

- Vendored libraries (copied source of zlib, libpng, libjpeg, OpenSSL, cJSON, …): find their version and check it for known CVEs. Vendored copies get no automatic updates.
- vcpkg (`vcpkg.json`) and Conan (`conanfile.txt`, `conan.lock`): pin versions; OSV-Scanner reads Conan lockfiles.

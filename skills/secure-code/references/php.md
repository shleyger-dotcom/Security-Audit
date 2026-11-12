# PHP (Laravel, Symfony, WordPress): dangerous sinks and safe replacements

## Code execution and deserialization

| Dangerous with input | Why | Safe |
|---|---|---|
| `eval`, `assert($string)` (PHP 7), `create_function`, `preg_replace` with `/e` (PHP 5) | runs any code | fixed code; `preg_replace_callback` |
| `include`, `require`, `include_once`, `require_once` with a path from input | local or remote file inclusion (CWE-98) | an allowlist map from a key to a fixed file |
| `call_user_func($input)`, `$input()`, `new $input`, `$$name`, `extract($_REQUEST)`, `parse_str($s)` without a target | the input selects the function, class or variable | an allowlist |
| `unserialize($input)` | object injection (CWE-502) | `json_decode`; or `unserialize($s, ['allowed_classes' => false])` |
| File functions on a `phar://` path from input (PHP 7) | reading the metadata deserializes it | reject stream wrappers in paths |

## Injection

- OS commands: `system`, `exec`, `shell_exec`, `passthru`, `popen`, backticks → `proc_open` with an array command (PHP 7.4+), or `escapeshellarg` on every argument.
- `mail()`: the fifth parameter and header values from input → a mail library; remove CR/LF.
- SQL: `mysqli_query($db, "... $x")`, `$pdo->query("... $x")` → prepared statements with bound values. Set `PDO::ATTR_EMULATE_PREPARES => false`.
- Laravel: `DB::raw`, `whereRaw`, `orderByRaw`, `selectRaw`, `DB::select` with concatenation → bindings (`whereRaw('a = ?', [$x])`); an allowlist for column names.
- Doctrine: DQL or `createNativeQuery` with concatenation → `setParameter`.
- XSS: `echo $x` → `htmlspecialchars($x, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`. Blade `{!! $x !!}` and Twig `|raw` or `autoescape false` turn escaping off.
- XXE: the `LIBXML_NOENT` and `LIBXML_DTDLOAD` flags enable entity loading. Do not pass them for untrusted XML.

## Comparison, hashing and randomness

- `==` on hashes and tokens: `"0e123" == "0e456"` is true (type juggling, CWE-697) → `===`, and `hash_equals` for secrets.
- `in_array($x, $list)` and `array_search` without the strict flag; `strcmp($input, $secret) == 0` when `$input` is an array.
- `md5`, `sha1`, `crypt` for passwords → `password_hash($p, PASSWORD_ARGON2ID)` or `PASSWORD_DEFAULT`, and `password_verify`.
- `rand`, `mt_rand`, `uniqid`, `lcg_value` for tokens → `random_bytes(32)`, `random_int`.
- `openssl_encrypt` with ECB or a fixed IV → `sodium_crypto_secretbox` or AES-GCM with a new nonce.

## Files and uploads

- `move_uploaded_file` into the web root with the client name: an upload named `x.php`, `x.phtml`, `x.phar` or `.htaccess` gives code execution. Store outside the web root under a random name.
- `$_FILES[...]['type']` and `['name']` come from the client.
- `file_get_contents($url)`, `fopen($url)`, `curl` with a user URL → SSRF; also `file://` and `php://filter` wrappers. Allow only `http` and `https`, and see checklist A.
- Paths: `realpath($base . '/' . $user)`, then check that the result starts with `$base . DIRECTORY_SEPARATOR`.
- `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)` or `CURLOPT_SSL_VERIFYHOST` set to `0` disables TLS checks.

## Sessions and configuration

- `session_regenerate_id(true)` after login.
- `session.cookie_httponly=1`, `session.cookie_secure=1`, `session.cookie_samesite=Lax`, `session.use_strict_mode=1`.
- `php.ini` in production: `display_errors=Off`, `expose_php=Off`, `allow_url_include=Off`, `open_basedir` set.
- `phpinfo()` pages, `.git`, `composer.json`, `vendor/` and backup files reachable from the web.

## Frameworks

**Laravel**
- `APP_DEBUG=true` in production shows environment variables in error pages.
- A leaked `APP_KEY` lets an attacker forge encrypted cookies. Rotate the key after any leak.
- Mass assignment: `$guarded = []` or `Model::unguard()` together with `create($request->all())` → `$fillable` and `$request->validated()`.
- Routes without the `auth` middleware; missing `$this->authorize(...)` or policy check for an object.
- Paths in `VerifyCsrfToken::$except` (or `validateCsrfTokens(except: ...)`) that change state.

**Symfony**
- `APP_ENV=dev` or the profiler (`/_profiler`) in production.
- `access_control` rules that do not cover a route; missing `#[IsGranted]` or voter check for an object.

**WordPress (plugins and themes)**
- SQL: `$wpdb->query("... $x")` → `$wpdb->prepare`.
- Every action checks a capability (`current_user_can`) and a nonce (`check_admin_referer`, `wp_verify_nonce`). A nonce is not an authorization check.
- REST routes: `'permission_callback' => '__return_true'` on a route that reads or changes private data.
- Output: `esc_html`, `esc_attr`, `esc_url`, `wp_kses`. Input: `sanitize_text_field`, `absint`.
- AJAX actions registered with `wp_ajax_nopriv_` are public.

## Composer

- `composer.lock` is committed. CI runs `composer install` (not `update`).
- `composer audit` reads the lockfile.
- Composer scripts and plugins run code on install. Use `--no-scripts --no-plugins` for a first look at an untrusted project, and review `allow-plugins`.

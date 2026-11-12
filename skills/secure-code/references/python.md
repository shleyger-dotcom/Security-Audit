# Python: dangerous sinks and safe replacements

Search for each sink, then trace whether untrusted data reaches it.

## Code execution and deserialization

| Dangerous | Why | Safe |
|---|---|---|
| `eval`, `exec`, `compile` on input | runs any code | `ast.literal_eval` for literals; explicit parsing |
| `pickle`, `cPickle`, `shelve`, `marshal`, `dill`, `joblib.load` on untrusted data | loading runs code | JSON; for models, `safetensors` |
| `yaml.load(..., Loader=yaml.Loader / FullLoader / UnsafeLoader)`, `yaml.unsafe_load` | creates any object | `yaml.safe_load` |
| `torch.load(path)` on downloaded files | pickle inside | `torch.load(path, weights_only=True)` (default since PyTorch 2.6 — still set it explicitly) |
| `xml.etree`, `xml.dom.minidom`, `xml.sax`, `lxml` on untrusted XML | XXE, entity expansion | `defusedxml`; for lxml `XMLParser(resolve_entities=False, no_network=True)` |
| `jsonpickle.decode` on input | creates any object | `json.loads` |
| `assert` as a security check | removed with `python -O` | `if not ok: raise PermissionError` |

## Processes

- `os.system`, `os.popen`, `subprocess.*(..., shell=True)`, `commands.getoutput` with input → `subprocess.run(["prog", arg], shell=False, check=True, timeout=...)`.
- If a shell is unavoidable: `shlex.quote` every argument. On Windows `shlex.quote` does not protect `cmd.exe`.
- An argument that starts with `-` can be read as an option: put `--` before user arguments.

## SQL

- Dangerous: f-strings, `%`, `.format()`, `+` inside `cursor.execute(...)`.
- Safe: `cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))` (psycopg, MySQL) or `?` (sqlite3).
- SQLAlchemy: `text("... WHERE id = :id")` with `{"id": x}`. Never `text(f"...")`.
- Django: `.raw()`, `.extra()`, `RawSQL`, `cursor.execute` only with params. Identifiers from an allowlist.

## Files and paths

- `os.path.join(base, user)` and `Path(base) / user`: if `user` is absolute, `base` is discarded.
- Safe check: `p = (base / user).resolve()` then `p.is_relative_to(base.resolve())`.
- `open(user_path)`, `send_file(user_path)` (Flask) → `send_from_directory(dir, name)`.
- `tarfile.extractall()` → `extractall(path, filter="data")` (Python 3.12+; earlier versions: check each member).
- `zipfile`: check each `ZipInfo.filename` with the resolve check above, and check the total size.
- `tempfile.mktemp` → `tempfile.mkstemp` or `NamedTemporaryFile`.

## Web frameworks

**Flask**
- `app.run(debug=True)` or `FLASK_DEBUG=1` in production: the Werkzeug debugger gives remote code execution.
- `SECRET_KEY` in code → environment.
- No built-in CSRF protection: use Flask-WTF `CSRFProtect` for cookie sessions.
- `render_template_string(user_input)` → SSTI. `Markup(user)` and `|safe` disable escaping.

**Django**
- `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, `SECRET_KEY` in `settings.py` in production.
- `mark_safe`, `|safe`, `{% autoescape off %}` with user data.
- `@csrf_exempt` on views that change state.
- `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS` not set.
- `ModelForm` with `fields = "__all__"` → mass assignment.
- Querysets without an owner filter: `Order.objects.get(id=pk)` → `get(id=pk, user=request.user)`.

**FastAPI / Starlette**
- A route without `Depends(get_current_user)` (or equivalent) on protected data.
- `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`.
- Pydantic input model without `model_config = ConfigDict(extra="forbid")` when the model maps to a database row (mass assignment).
- No `response_model`: the ORM object can return extra fields (password hash).
- `jwt.decode(token, options={"verify_signature": False})` or no `algorithms=[...]` list.

**Jinja2**
- `Environment(autoescape=False)` (the default for a bare `Environment`) → `autoescape=select_autoescape()`.

## HTTP clients

- `requests` has no default timeout: always pass `timeout=`.
- `verify=False` disables TLS checks.
- `requests` and `httpx` can follow redirects to internal addresses → SSRF. Check the final URL or turn redirects off.

## Crypto and randomness

- `random` module for tokens, passwords, OTP → `secrets.token_urlsafe(32)`, `secrets.randbelow`.
- `==` for token or HMAC comparison → `hmac.compare_digest`.
- `hashlib.md5/sha1/sha256(password)` → `argon2-cffi`, `bcrypt`, or `hashlib.scrypt`.
- PyCryptodome `AES.MODE_ECB`, fixed IV → `AES.MODE_GCM` with a new nonce each time; or `cryptography.fernet`.

## Other

- `logging` with raw input (`logger.info(f"user {name}")`): CR/LF in `name` creates fake log lines.
- `re` with a user-supplied pattern or nested quantifiers such as `(a+)+` → length limit, or the `regex` module with `timeout`.
- `input()` and `argparse` in a local tool are trusted by design. In a hosted tool they are not.
- `requirements.txt` without exact pins → pin versions; use `pip install --require-hashes` or `uv.lock`/`poetry.lock`.

## Jupyter notebooks (`.ipynb`)

- Cell outputs often contain keys, tokens and personal data. Clear outputs before commit (`jupyter nbconvert --clear-output`).
- `%env KEY=...` and `os.environ["KEY"] = "..."` with a literal value is a hardcoded secret.
- `!pip install package` without a version.

## Streamlit and Gradio

- `st.markdown(text, unsafe_allow_html=True)` or `st.components.v1.html` with user or LLM text → XSS.
- `.streamlit/secrets.toml` must be in `.gitignore`.
- Gradio `share=True` publishes the app on a public URL.

For LLM-specific Python libraries (LangChain, LlamaIndex, Hugging Face), see `ai-llm.md`.

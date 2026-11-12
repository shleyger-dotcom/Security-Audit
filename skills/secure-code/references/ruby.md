# Ruby and Rails: dangerous sinks and safe replacements

## Code and command execution

| Dangerous with input | Why | Safe |
|---|---|---|
| `eval`, `instance_eval`, `class_eval`, `binding.eval` | runs any code | fixed code |
| `send(params[:m])`, `public_send`, `constantize`, `const_get` on input | the input selects the method or class | an allowlist |
| `Kernel#open(input)`, `IO.read(input)`, `URI.open(input)` | a value that starts with a pipe character runs a command | `File.open`; an HTTP client for URLs |
| `system("cmd #{x}")`, backticks, `%x()`, `exec`, `IO.popen(string)` | shell injection | `system("cmd", arg1, arg2)`; `Open3.capture3("cmd", arg)` |
| `Marshal.load`, `YAML.load` (Psych before 4), `YAML.unsafe_load`, `Oj.load` in object mode, `JSON.load`, `JSON.parse(x, create_additions: true)` | creates any object (CWE-502) | `JSON.parse`; `YAML.safe_load` |
| `ERB.new(input).result`, `render inline: input` | template injection | fixed templates |

## SQL (ActiveRecord)

- Dangerous: `where("name = '#{x}'")`, `find_by_sql`, `order(params[:sort])`, `reorder`, `pluck(input)`, `select(input)`, `joins(input)`, `group`, `having`, `from`, `lock(input)`, `Arel.sql(input)`.
- Safe: `where(name: x)`, `where("name = ?", x)`; an allowlist for column names and sort directions.
- `where(id: params[:id])` when the parameter can be a hash or an array: require a scalar with strong parameters.

## Rails

- Mass assignment: `params.permit!`, or `permit(...)` that includes `role`, `admin`, `user_id` → permit only the fields that this user may set.
- Object access: `Order.find(params[:id])` → `current_user.orders.find(params[:id])`. Missing `authorize` (Pundit) or `load_and_authorize_resource` (CanCanCan).
- `skip_before_action :authenticate_user!` and `skip_before_action :verify_authenticity_token` on actions that change state.
- XSS: `html_safe`, `raw`, `<%==`, Haml `!=`, `content_tag` with unescaped content. `link_to "x", user_url` with a `javascript:` URL.
- `render params[:template]`, `render file: input` → file disclosure.
- `redirect_to params[:url]` → a relative path or an allowlist. Do not set `allow_other_host: true` for input.
- `send_file params[:path]`, `File.read(input)` → resolve, then check that the path is inside the allowed root.
- Production config: `config.force_ssl = true`, `config.consider_all_requests_local = false`, `config.hosts` set, `web-console` only in the development group.
- `config.filter_parameters` contains passwords, tokens and keys, so they stay out of logs.
- Secrets: `config/master.key`, `config/credentials/*.key`, `secret_key_base`, passwords in `config/database.yml` are not in git. A leaked `secret_key_base` lets an attacker forge session cookies.
- Uploads (Active Storage, CarrierWave, Shrine): content type allowlist, size limit, and no user-supplied path.

## Regular expressions

- `^` and `$` match at each line in Ruby. A validation such as `/^[a-z]+$/` accepts `"ok\n<script>"` → use `\A` and `\z`.
- Nested quantifiers on input → ReDoS. Ruby 3.2+ supports `Regexp.timeout`.

## Crypto and randomness

- `rand`, `Random.rand`, `Array#sample` for tokens → `SecureRandom.hex(32)`, `SecureRandom.urlsafe_base64`.
- `==` on tokens and MACs → `ActiveSupport::SecurityUtils.secure_compare`, `Rack::Utils.secure_compare`.
- `Digest::MD5`, `Digest::SHA1`, `Digest::SHA256` for passwords → `has_secure_password` (bcrypt), Devise, or `argon2`.
- `OpenSSL::SSL::VERIFY_NONE`, `verify_ssl: false`, `ssl_verify_mode` set to none disable TLS checks.
- `OpenSSL::Cipher.new("aes-256-ecb")` or a fixed IV → `aes-256-gcm` with a random IV, or `ActiveSupport::MessageEncryptor`.

## HTTP clients

- `Net::HTTP`, `Faraday`, `HTTParty`, `RestClient` with a user URL → SSRF (see checklist A). Set open and read timeouts.

## Gems

- `Gemfile.lock` is committed. CI uses `bundle install --frozen` (or `BUNDLE_FROZEN=true`).
- Each private gem is inside a `source "https://private" do ... end` block (dependency confusion).
- Git gems are pinned with `ref:`.
- Gem install can run native extension builds (`extconf.rb`). Do not run `bundle install` on an untrusted project outside a sandbox.
- `bundle-audit check` reads the lockfile. Brakeman is a static scanner for Rails (see `tools.md` for its license).

# HTML/CSS, HTTP headers and configuration files

## HTML and CSS

- Any key, token or password in HTML, inline scripts or CSS is public.
- Third-party scripts and styles from a CDN have `integrity="sha384-..."` and `crossorigin="anonymous"` (SRI).
- Forms with passwords or personal data submit only over HTTPS.
- `<iframe>` with untrusted content has a `sandbox` attribute. Pages that must not be framed send `frame-ancestors 'none'` (clickjacking).
- `target="_blank"` links to other sites have `rel="noopener noreferrer"`.
- Do not allow user-controlled CSS: attribute selectors with `url()` can leak page data.
- HTML comments do not contain internal URLs, credentials or TODO notes about security gaps.
- A strict CSP needs no inline `<script>` and no `on*=` attributes. Move scripts into files or use nonces.

## HTTP security headers

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
```

- `X-Frame-Options: DENY` is the legacy version of `frame-ancestors`. Keep it for old browsers.
- `X-XSS-Protection` is obsolete. Set it to `0` or leave it out.
- Session cookie: `Set-Cookie: __Host-session=...; Path=/; Secure; HttpOnly; SameSite=Lax`.

## `.env` and secret files

- `.gitignore` contains: `.env`, `.env.*`, `!.env.example`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `.streamlit/secrets.toml`, `*.tfstate*`.
- `.env.example` contains only placeholders such as `API_KEY=<API_KEY>`.
- `.npmrc`, `.pypirc`, `.netrc`, `.docker/config.json` with tokens are not committed.
- Secrets that went into git are revoked. Deleting the file in a new commit is not enough: the history keeps the secret.

## Dockerfile

- `USER` with a non-root user before `CMD`/`ENTRYPOINT`.
- No secrets in `ENV`, `ARG` or `COPY`. Image layers keep them, even after a later `RUN rm`. Use BuildKit: `RUN --mount=type=secret,id=npm_token ...`.
- Base image pinned by tag and digest (`python:3.12-slim@sha256:...`), not `latest`.
- `.dockerignore` contains `.git`, `.env`, `node_modules`, `*.pem`.
- No `curl ... | sh` without a checksum check. Prefer `COPY` over `ADD` with a remote URL.
- Multi-stage build: build tools and source code are not in the final image.

## docker-compose

- `ports: "5432:5432"` opens the database on all host interfaces. Use `127.0.0.1:5432:5432`, or no `ports` and an internal network.
- `privileged: true`, `network_mode: host`, `cap_add: [SYS_ADMIN]` → avoid.
- Mounting `/var/run/docker.sock` gives root on the host.
- Passwords directly in `environment:` → `env_file` (not committed) or `secrets:`.

## GitHub Actions

- `pull_request_target` or `workflow_run` together with a checkout of the PR code: code from a fork runs with your secrets.
- `${{ github.event.issue.title }}`, `${{ github.event.pull_request.body }}`, `${{ github.head_ref }}` directly inside `run:` → script injection. Pass the value through `env:` and use `"$VAR"`.
- Third-party actions pinned to a full commit SHA, not to `@v1` or `@main`.
- Top-level `permissions: contents: read`. Give more rights only to the jobs that need them.
- Secrets are not printed and are not passed to steps that run untrusted code.
- Self-hosted runners are not used for public repositories.
- Use OIDC instead of long-lived cloud keys where possible.

## Kubernetes and Terraform (basic)

For IAM policies, cloud resources, RBAC and Ansible, load `cloud-iac.md`.

- Pods: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, no `privileged: true`, resource limits set.
- Secrets are not in plain manifests or Helm values in git. Use sealed secrets or an external secret store.
- Terraform: no public buckets, no `0.0.0.0/0` on database or SSH ports, encryption on. `terraform.tfstate` contains secrets: keep it in an encrypted remote backend.

## Web servers (nginx, Apache, IIS)

- Directory listing off (`autoindex off`, `Options -Indexes`).
- Version headers off (`server_tokens off`, `ServerTokens Prod`).
- Block access to `/.git`, `/.env`, backup files (`*.bak`, `*.old`, `*.swp`).
- Redirect HTTP to HTTPS. TLS 1.2+ only.

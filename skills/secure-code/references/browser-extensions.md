# Browser extensions (Chrome, Edge, Firefox; Manifest V3)

An extension runs with more rights than a web page. A bug in it can give a web page access to every site that the extension can read. JavaScript rules from `javascript.md` also apply.

## `manifest.json`

- `permissions` and `host_permissions` are minimal. Wide values need a reason: `<all_urls>`, `*://*/*`, `tabs`, `cookies`, `history`, `webRequest`, `debugger`, `nativeMessaging`, `scripting`, `clipboardRead`, `downloads`.
- Prefer `activeTab` and `optional_permissions` (asked at the time of use) over permanent host access.
- `content_security_policy` must not add `unsafe-eval` or remote script sources. Manifest V3 forbids remote code: no scripts from a CDN, no `eval`, no `new Function`.
- `web_accessible_resources` with `"matches": ["<all_urls>"]`: every site can load these files. Do not list HTML pages that perform actions (clickjacking), and list as few files as possible.
- `externally_connectable` with wide `matches` lets those sites send messages to the extension.
- Manifest V2 (`"manifest_version": 2`, background pages) is end-of-life in Chrome: report it.

## Messages

- A content script runs inside a page that the attacker can control. Treat every message from a content script as untrusted input.
- `chrome.runtime.onMessage`: check `sender.id`, and `sender.origin` or `sender.url` where the action depends on the site. Validate the message with a schema.
- A message must not carry a URL to fetch, code to run, or a tab URL to open without an allowlist. A service worker fetch ignores the page CORS rules for hosts in `host_permissions`: a generic "fetch this URL for me" handler gives a web page that power.
- `onMessageExternal` and `onConnectExternal`: check the sender extension ID or origin.
- `window.addEventListener("message", ...)` in a content script: check `event.source === window` and `event.origin`, and still treat the data as untrusted. Do not send secrets with `window.postMessage`.
- `chrome.scripting.executeScript` uses `files` or a fixed `func`, never code built from a message.

## DOM and data from pages

- Text read from a page and written with `innerHTML` in a popup, options page or side panel is XSS in a privileged context → `textContent`.
- A content script that injects HTML into the page with `innerHTML` and page data is XSS in that page.
- Do not copy page data into `chrome.tabs.update({url})`, `chrome.downloads.download` or `chrome.tabs.create` without a scheme check (`javascript:`, `data:`, `file:`).

## Storage and secrets

- Any key in the extension package is public.
- `chrome.storage.local` and `chrome.storage.sync` are not encrypted. `sync` copies data to the user account: no tokens there.
- Content scripts can read `chrome.storage.local` by default. Keep tokens in `chrome.storage.session` (memory only, not exposed to content scripts unless `setAccessLevel` changes this).
- OAuth: `chrome.identity.launchWebAuthFlow` with PKCE. No client secret in the extension.

## Network and headers

- `declarativeNetRequest` or `webRequest` rules that remove `Content-Security-Policy`, `X-Frame-Options` or CORS headers from sites weaken those sites for the user: finding.
- `chrome.cookies` access to sites that the feature does not need.
- `chrome.debugger` attaches to tabs with full control: needs a strong reason.

## Native messaging

- The native host manifest lists exact extension IDs in `allowed_origins` (Firefox: `allowed_extensions`). No wildcards.
- The native host runs with the rights of the user. It validates every message, and it does not run commands or open paths from a message without an allowlist.

## Privacy and release

- Collect only the browsing data that the feature needs. Do not send full URLs, page content or history to a server without a clear user choice. Store review rejects undisclosed collection.
- All code is bundled in the package. Dependencies are pinned, and the build is reproducible from the repository.
- The developer account for the store uses MFA **(ask)**. A stolen account gives the attacker an update channel to every user.

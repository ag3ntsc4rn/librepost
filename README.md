# librepost

[![CI](https://github.com/ag3ntsc4rn/librepost/actions/workflows/ci.yml/badge.svg)](https://github.com/ag3ntsc4rn/librepost/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/librepost-app?cacheSeconds=3600)](https://pypi.org/project/librepost-app/)
[![Python](https://img.shields.io/pypi/pyversions/librepost-app?cacheSeconds=3600)](https://pypi.org/project/librepost-app/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/ag3ntsc4rn/librepost/blob/main/LICENSE)

**A free, local-first API client.** Your requests are plain `.http` files in your git repo.
Your secrets stay in your OS keychain. No account, no cloud, no telemetry, and nothing
installed anywhere except the package itself.

```bash
uvx librepost-app ui      # or: uv tool install librepost-app && librepost ui
```

That opens a Postman-style UI in your browser, served from your own machine. (On PyPI the
package is `librepost-app`; once installed, the command is `librepost`.)

## Why

API clients have become cloud platforms: sign-ins, team workspaces, sync, and desktop apps
that change your system without asking (see [postman-app-support#14370](https://github.com/postmanlabs/postman-app-support/issues/14370)).
librepost goes the other way:

- **Requests are files.** One folder, plain text, diffable in pull requests. The format is
  the `.http` format used by the JetBrains HTTP Client and the VS Code REST Client, so your
  collection also works in those tools.
- **Secrets are references.** Write `{{secret:keychain/github-token}}`; the value is read from
  the keychain only when a request is sent, and is masked everywhere on screen.
- **Leaks are caught.** `librepost check` (also a pre-commit hook) flags tokens and literal
  credentials before they reach git.
- **It stays in its lane.** librepost reads and writes `.http` files in the folder you point it
  at, and nothing else. No auto-updates, no plugins, no background services.

## Install

The package is `librepost-app` on PyPI; the command it installs is `librepost`.

| Method | Install | Upgrade |
|---|---|---|
| [uv](https://docs.astral.sh/uv/) (recommended) | `uv tool install librepost-app` | `uv tool upgrade librepost-app` |
| uvx (no install) | `uvx librepost-app ui` | always runs the latest release |
| [pipx](https://pipx.pypa.io) | `pipx install librepost-app` | `pipx upgrade librepost-app` |
| pip | `pip install librepost-app` | `pip install -U librepost-app` |

On macOS with Homebrew Python and on recent Linux distributions, a global `pip install`
stops with an "externally-managed-environment" error. Use uv or pipx, or install into a
virtual environment:

```bash
python3 -m venv ~/.venvs/librepost
~/.venvs/librepost/bin/pip install librepost-app
~/.venvs/librepost/bin/librepost ui
```

On Windows, if `librepost` isn't found after `py -m pip install librepost-app`, Python's
Scripts folder isn't on your PATH; `py -m librepost ui` works either way.

librepost never updates itself. You upgrade when you choose to.

## Quick start

```bash
librepost init my-api        # example env file + requests; gitignores the private env file
cd my-api
librepost ui                 # opens http://127.0.0.1:8765/?token=...
```

Or from the terminal:

```bash
librepost run requests/example.http --name post-example --env dev -v
```

## Requests

```http
@apiVersion = v2

# @name create-user
POST {{baseUrl}}/{{apiVersion}}/users
Content-Type: application/json
Authorization: Bearer {{token}}

{"name": "Ada", "requestId": "{{$uuid}}"}

###

# @name list-users
GET {{baseUrl}}/{{apiVersion}}/users?page=1
```

- Requests are separated by `###`; `# @name` gives one a name.
- `@name = value` lines define file variables.
- Built-in values: `{{$uuid}}`, `{{$timestamp}}`, `{{$isoTimestamp}}`, `{{$randomInt}}`.
- Response handler scripts (`> {% ... %}`) are kept intact when you save, but are not run.

## Environments

Same format as the JetBrains HTTP Client:

| File | Commit it? | Holds |
|---|---|---|
| `http-client.env.json` | yes | shared, non-secret values per environment |
| `http-client.private.env.json` | **no** (gitignored by `librepost init`) | per-machine overrides |

```json
{
  "$shared": {"apiVersion": "v2"},
  "dev":  {"baseUrl": "https://dev.example.com", "token": "{{secret:keychain/dev-token}}"},
  "prod": {"baseUrl": "https://api.example.com", "token": "{{secret:keychain/prod-token}}"}
}
```

## Secrets

| Reference | Value comes from |
|---|---|
| `{{secret:keychain/<name>}}` | the OS keychain: macOS Keychain, Windows Credential Manager, or Secret Service (GNOME Keyring, KWallet) on Linux |
| `{{secret:env/<NAME>}}` | an environment variable, handy in CI and on headless machines |

```bash
librepost secret set dev-token      # prompts without echoing
librepost secret delete dev-token
```

Secret values are masked (`••••••`) in the request preview, response headers and response
body (APIs often echo credentials back), and in error messages.

## Leak check

```bash
librepost check              # exit code 1 if anything looks like a secret
```

It looks for known token formats (GitHub, AWS, Slack, Stripe, Google, OpenAI, Anthropic, JWTs,
private keys), literal values in `Authorization`, `Cookie` and API-key headers, literal
passwords and tokens in `http-client.env.json`, and a private env file that isn't gitignored.

As a [pre-commit](https://pre-commit.com) hook:

```yaml
- repo: https://github.com/ag3ntsc4rn/librepost
  rev: v0.1.0
  hooks:
    - id: librepost-check
```

## How the local UI is protected

A local web server that sends HTTP requests for you would be an open door into your network
for any website you visit, if it weren't locked down. librepost:

- listens on `127.0.0.1` only, never on your network;
- requires the random token printed at startup; the token is swapped for an `HttpOnly`,
  `SameSite=Strict` cookie scoped to that port;
- rejects any `Host` header other than `127.0.0.1:<port>`/`localhost:<port>`, which blocks
  DNS rebinding;
- rejects state-changing requests without a same-origin `Origin` header and htmx's request
  header, so other sites can't make it send requests;
- sends a strict Content-Security-Policy (no inline or third-party scripts), shows response
  bodies only as escaped text, and marks every response `Cache-Control: no-store`.

Found a hole? Please report it privately; see [SECURITY.md](SECURITY.md).

## Requirements

Python 3.11+ (uv fetches one for you if needed) and a web browser. Git is optional.

## Roadmap

- Import from Postman collections, curl commands and HAR files
- A native window (`pip install librepost-app[desktop]`)
- Git status and commit from the UI
- Client certificates (mTLS), proxy settings, request history and response diffs
- More secret providers: 1Password CLI, HashiCorp Vault, `pass`

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). The bundled [htmx](https://htmx.org) is under the
[Zero-Clause BSD](src/librepost/static/vendor/htmx-LICENSE.txt) licence.

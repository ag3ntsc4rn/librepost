# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Desktop window**: `librepost ui --window` opens the UI in its own window, using the
  system's web view through pywebview (install `librepost-app[desktop]`). Browser extensions
  can't see the page, nothing is kept after it closes, and closing it stops librepost. On
  macOS the Dock shows librepost's name and icon. Without the extra, `--window` explains how
  to install it.

## [0.7.0] - 2026-11-04

### Added

- **History**: requests sent from the UI are listed with status, timing and check results.
  Open one to see its response again, or open a copy in the editor to send it again. Stored
  outside the workspace (per-user app data), owner-only, secrets masked, newest 200 per
  workspace. `librepost ui --no-history` turns it off.
- **Git status**: the top bar shows the branch, changed-file count and ahead/behind; changed
  request files get a letter in the sidebar; **Changes** shows each file's diff against the
  last commit. Read-only, with git's fsmonitor and external diff tools disabled.

### Fixed

- The editor's status notice (for example "Created users.http") wasn't shown.

## [0.6.0] - 2026-11-03

### Added

- **Client certificates (mTLS), extra CA certificates, host verification and proxies**, per
  environment, in the JetBrains HTTP Client `SSLConfiguration` format plus
  `certificatePassphrase`, `caCertificate` and `ProxyConfiguration`. Used by the UI,
  `librepost run` and `librepost test`. Proxy passwords and key passphrases can be secret
  references and are masked.
- These settings are read only from `http-client.private.env.json`; in the shared file they're
  ignored with a warning, so a cloned repository can't redirect your traffic or weaken TLS.
- A **Connection** form on the Environments screen. Saving checks that the files load, and a
  new key passphrase goes into the keychain.
- HTTPS responses show the TLS version and the server certificate's subject and issuer, or
  warn when it wasn't verified; `librepost run -v` also prints the cipher and expiry.

## [0.5.0] - 2026-11-03

### Added

- **Checks and chaining** without scripts: `# @capture name = …`, `# @capture-secret` and
  `# @expect …` lines above a request. Captured values are available to later requests as
  `{{name}}`; secret captures, and captures named like credentials, are masked everywhere,
  including in the response they came from. Subjects: `status`, `duration`, `body`,
  `header Name`, JSON paths (`$.a.b[0]`, `.length`) and `regex "…"`.
- A **Checks** tab in the editor, and ✓/✗ results plus captured values under each response,
  with a button to clear captured values.
- `librepost run` prints check results and exits with status 1 when a check fails.
- `librepost test`: run every request in folders or files in order, carrying captured values
  along; a ✓/✗ line per request, a summary, `--bail`, and `--junit report.xml` for CI. Exits
  with status 1 on any failure. Secrets and captured credentials never reach the output or
  the report.
- The Postman importer converts common test-script statements into `@capture` and `@expect`
  lines (`pm.environment.set(…, pm.response.json()…)`, `pm.response.to.have.status`,
  `pm.expect(…).to.eql/include/be.below/exist/have.property…`, headers, response time),
  including collection- and folder-level scripts. Only the rest is reported as skipped.
- Placeholders in check lines are filled in, so `@expect $.id == {{userId}}` works.

## [0.4.0] - 2026-11-03

### Added

- **New request** button: a blank editor you can send straight away, without picking a file
  first. Choose where it goes when you save (existing files are suggested; a new name creates
  the file), and the response stays on screen.
- A **+** next to each file in the sidebar adds a request to that file.

## [0.3.1] - 2026-11-03

### Fixed

- Secrets added in the UI or with `librepost secret set` now appear on the Secrets screen even
  when nothing refers to them yet, under "Not used in this workspace". OS keychains can't list
  their entries, so librepost keeps an index of the names it stored (never the values) in one
  extra keychain entry. Secrets stored with 0.3.0 or earlier show up once they're referenced
  or set again.

### Added

- `librepost secret list` prints the names of stored secrets.

## [0.3.0] - 2026-11-03

### Added

- **Environments** screen: edit variables per environment (and `$shared`), choose whether each
  is shared (committed) or private (this machine), tick 🔒 to move a value into the keychain,
  and add or delete environments. Credential-looking values can't be saved as shared, the
  private file is created readable only by you, and a warning (with a fix) appears if it
  isn't gitignored.
- **Secrets** screen: every `{{secret:...}}` reference in the workspace, where it's used and
  whether it's set; set, replace or delete keychain values. Values are never shown.

## [0.2.0] - 2026-11-03

### Added

- `librepost import`: Postman collections (v2.0/v2.1) and environment/globals exports, HAR
  files, and curl commands (including browsers' "Copy as cURL"). Literal credentials are
  replaced with keychain references; `--save-secrets` stores the values found. Imports never
  overwrite existing files or environment values. `--dry-run` previews.
- `Authorization: Basic user password` (the JetBrains form) is base64-encoded at send time,
  so the password can be a secret reference.
- Multipart bodies are sent with CRLF line breaks.
- **Import…** in the UI: paste curl commands or Postman/HAR JSON, or upload a file. Found
  credentials are saved to the keychain unless you untick the box, and the pasted text is
  cleared after a successful import.

### Changed

- The leak check no longer flags prose placeholders such as "Your API key".

## [0.1.0] - 2026-11-03

First release. On PyPI the package is `librepost-app`, because PyPI doesn't allow the name
`librepost`; the command is `librepost` (`librepost-app` also works).

### Added

- Local web UI (`librepost ui`): browse the `.http` files in a folder, edit requests, send
  them, and read the response body, headers and the request as sent. Served on 127.0.0.1
  only, behind a per-session token, Host and Origin checks, and a strict CSP.
- `.http` file support compatible with the JetBrains HTTP Client and VS Code REST Client:
  `###` separators, `# @name`, file variables, multi-line query strings. Response handler
  scripts are kept on save but not run.
- Environments in `http-client.env.json` and the gitignored `http-client.private.env.json`,
  including `$shared` values.
- Secret references, `{{secret:keychain/<name>}}` and `{{secret:env/<NAME>}}`, resolved only
  when a request is sent and masked everywhere on screen. `librepost secret set/delete`.
- `librepost run` to send a request from the terminal, with `--env`, `--name`, `--fail`.
- `librepost check` and a pre-commit hook that flag literal credentials and a private env file
  that isn't gitignored.
- `librepost init` to create an example workspace.

[Unreleased]: https://github.com/ag3ntsc4rn/librepost/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/ag3ntsc4rn/librepost/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ag3ntsc4rn/librepost/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ag3ntsc4rn/librepost/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ag3ntsc4rn/librepost/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/ag3ntsc4rn/librepost/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ag3ntsc4rn/librepost/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ag3ntsc4rn/librepost/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ag3ntsc4rn/librepost/releases/tag/v0.1.0

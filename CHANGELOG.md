# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ag3ntsc4rn/librepost/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ag3ntsc4rn/librepost/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ag3ntsc4rn/librepost/releases/tag/v0.1.0

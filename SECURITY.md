# Security policy

## Reporting a vulnerability

**Please do not open public issues, discussions or pull requests for security vulnerabilities.**

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/ag3ntsc4rn/librepost/security/advisories/new)
(Security tab → "Report a vulnerability").

Please include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version or commit.

This is a volunteer-maintained project. You can expect an acknowledgement within 7 days. Fixes
will be coordinated with you before public disclosure, and reporters are credited in the
advisory unless they prefer otherwise.

## Supported versions

librepost is alpha. Only the latest release receives security fixes.

## Scope

These are in scope:

- **Reaching the local UI from elsewhere:** any way for a website, another user on the machine
  or another host to read from the UI or make it send requests (CSRF, DNS rebinding, token
  leaks, CORS mistakes, cookie confusion between instances).
- **Secret exposure:** a secret value shown unmasked, written to a file, logged, or sent
  somewhere other than the request it was referenced in.
- **File access outside the workspace:** reading or writing files outside the folder librepost
  was started in (path traversal, symlinks).
- **Script execution:** markup or script from an HTTP response, a `.http` file or an
  environment file running in the UI.
- **Leak-check bypasses** for credential formats it claims to detect.

Out of scope: requests you send yourself doing what you asked, and attacks that need an
attacker already running code as your user.

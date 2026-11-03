# Contributing to librepost

Thanks for your interest! Opening an issue before starting larger work is the best way to
avoid wasted effort. Bug reports from real API collections, `.http` files that don't parse
the way your other tools do, and importers are especially welcome.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
git clone https://github.com/ag3ntsc4rn/librepost.git
cd librepost
uv sync                       # creates .venv with the package and dev tools
uv run pre-commit install     # runs lint, format, type checks and a secrets scan on commit
```

Day-to-day commands:

```bash
uv run pytest                 # tests
uv run ruff check --fix       # lint
uv run ruff format            # format
uv run mypy                   # type check (strict)
uv run librepost ui        # try the UI against the current folder
uv run librepost check .   # dogfood the leak check
uv build                      # build sdist and wheel into dist/
```

CI runs the same checks on every pull request, on Python 3.11 to 3.14 and on Linux, macOS
and Windows.

## Where things live

- `httpfile.py` parses and writes `.http` files. Saving must never lose content: anything
  librepost doesn't understand is kept verbatim (see `comments` and `trailer`).
- `template.py`, `environments.py`, `secretstore.py` fill in `{{...}}` placeholders.
- `runner.py` sends requests; `workspace.py` is the only code that touches files.
- `server.py` and `templates/` are the UI (Starlette, Jinja and htmx, no build step).
- `leakcheck.py` is `librepost check`.

## UI rules

The UI is a local web server, so it is security-sensitive:

1. **Keep the CSP strict.** No inline `<script>`, `style=` attributes, `hx-on` handlers or
   third-party assets. Put JavaScript in `static/app.js` and styles in `static/app.css`.
2. **Never mark anything `|safe`.** Response bodies and file contents are untrusted.
3. **File paths from the browser go through `Workspace.path()`**, which refuses anything
   outside the workspace.
4. **Mask secrets** with `Renderer.mask()` in anything shown on screen.
5. New endpoints need tests in `tests/test_server.py`, including the token and Origin checks.

Use `example.invalid` hosts in tests and never commit working credentials.

## Branches and commits

- Branch from `main` and name it `<type>/<short-description>`, e.g. `feat/postman-import`,
  `fix/crlf-bodies`.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org):
  `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, `build:`. Use `!` or a
  `BREAKING CHANGE:` footer for breaking changes. Changes to the `.http` or environment
  file handling count as user-visible changes.
- Keep pull requests small and focused. PR titles also follow Conventional Commits, since a
  squash merge uses the title as the commit message on `main`.
- Add an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

## Signing off your commits

librepost uses the [Developer Certificate of Origin](https://developercertificate.org)
(DCO) instead of a contributor licence agreement. By adding a `Signed-off-by` line to a
commit you certify that you wrote it, or otherwise have the right to submit it, under the
project's licence (MIT). `git commit -s` adds the line from your git name and email:

```
Signed-off-by: Your Name <you@example.com>
```

Every commit in a pull request needs one; a check on pull requests says which are missing.
To add it to commits you already made, run `git rebase --signoff main` and force-push the
branch.

## Releasing (maintainers)

1. Bump `version` in `pyproject.toml` and `__version__` in `src/librepost/__init__.py`,
   and move the `Unreleased` changelog entries under the new version, in a
   `chore(release): X.Y.Z` pull request.
2. After it merges, tag `main` with `vX.Y.Z` and push the tag. The tag also versions the
   pre-commit hook (`rev: vX.Y.Z`). The release workflow checks
   that the tag matches the version, runs the tests, builds, and publishes to PyPI with
   Trusted Publishing once the `pypi` environment deployment is approved.

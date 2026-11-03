## What and why

<!-- What does this change, and why? Link related issues with "Closes #123". -->

## How was it tested?

<!-- Commands run, new tests, manual checks in the UI. -->

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org) (a squash merge uses it as the commit message)
- [ ] Tests added or updated, and `uv run pytest` passes
- [ ] `uv run ruff check`, `uv run ruff format --check` and `uv run mypy` pass
- [ ] `CHANGELOG.md` updated under "Unreleased" for user-visible changes
- [ ] UI changes keep the CSP intact (no inline scripts or styles, no third-party assets)
- [ ] Every commit is signed off (`git commit -s`), certifying the [DCO](https://developercertificate.org); see CONTRIBUTING.md

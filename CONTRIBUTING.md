# Contributing to WiCrackAgent

First off, thank you for considering a contribution — this project gets better
with every PR.

## Code of conduct

Read and follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Be excellent to
each other.

## Legal & safety rules (non-negotiable)

- Never submit capture files, handshakes, or passwords from networks you do
  not own. Test fixtures must use synthetic/lab data only.
- Every feature must keep the **authorized-use framing** intact (DISCLAIMER,
  report notices, CLI banner).
- No features whose *primary purpose* is attacking third-party infrastructure.

## Development setup

```bash
git clone https://github.com/ch-farhan107/WiCrackAgent.git
cd WiCrackAgent
make dev            # creates .venv, installs package + dev tools
make test           # pytest suite
make lint           # ruff check + format check
make type           # mypy
```

## Branching & commits

- Branch from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`.
- **Conventional Commits**: `feat(web): add job retry endpoint`.
- One logical change per PR. Keep PRs reviewable (< ~500 lines if possible).

## Standards

| Area | Standard |
|------|----------|
| Formatting | `ruff format` (line length 100) |
| Lint | `ruff check` must pass with zero findings |
| Types | `mypy wicrack` must pass |
| Tests | Every bug fix / feature ships with a test |
| Docs | Public behavior changes update `docs/` and `CHANGELOG.md` |

## Release process (maintainers)

1. Update `CHANGELOG.md`.
2. Bump `__version__` in `wicrack/__init__.py` (SemVer).
3. Tag `vX.Y.Z` and push — CI builds and publishes the GitHub Release.

## Reporting vulnerabilities

See [`SECURITY.md`](SECURITY.md). Please do not open public issues for
security problems.

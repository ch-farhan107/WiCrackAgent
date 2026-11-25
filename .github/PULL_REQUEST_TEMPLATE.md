# Pull request checklist

- [ ] Conventional commit title (`feat|fix|docs|test|chore(scope): ...`)
- [ ] `make lint` passes (ruff check + format)
- [ ] `make type` passes (mypy)
- [ ] `make test` passes; new logic has tests
- [ ] Docs / CHANGELOG updated for user-visible changes
- [ ] No real captures, credentials, or client data included
- [ ] Authorized-use framing preserved (no removal of legal notices)

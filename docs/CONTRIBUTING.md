# Contributing

Fork the repo and open a pull request against `main`. A maintainer reviews before merge. The `status` check must pass (`test` and `build`, except `docs:` which skips those jobs).

## Commit messages

Releases are cut from [conventional commit](https://www.conventionalcommits.org/) messages that land on `main` (the PR title, if you squash-merge):

| Prefix | test / build | Release |
| --- | --- | --- |
| `fix:` | run | patch |
| `feat:` | run | minor |
| `feat!:` or `BREAKING CHANGE:` | run | major |
| `ci:`, `refactor:` | run | skipped |
| `docs:` | skipped | skipped |
| `chore:`, `test:` | run | no publish (semantic-release no-op) |

Release notes go in [CHANGELOG.md](../CHANGELOG.md) and GitHub Releases (`feat` / `fix` / breaking only). Squash-merge if you want `(#PR)` in the entry.

## Development

Work in the Dev Container (see the README). Parser tests do not need TAP:

```bash
cargo test
```

The terminal lab:

```bash
cargo run
```

# Contributing

Fork the repo and open a pull request against `main`. CI (`test` and `build`) must pass. A maintainer reviews before merge.

## Commit messages

Releases are cut from [conventional commit](https://www.conventionalcommits.org/) messages that land on `main` (the PR title, if you squash-merge):

| Prefix | Effect |
| --- | --- |
| `fix:` | patch release |
| `feat:` | minor release |
| `feat!:` or `BREAKING CHANGE:` | major release |
| `docs:`, `chore:`, `refactor:`, `test:`, `ci:` | no release |

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

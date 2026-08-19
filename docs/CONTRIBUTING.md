# Contributing

Fork the repo and open a pull request against `main`. A maintainer reviews before merge. The `status` check must pass (`test` and `build`, except `docs:` which skips those jobs).

## Commit messages

Releases are cut from [conventional commit](https://www.conventionalcommits.org/) messages that land on `main` (the PR title, if you squash-merge):

| Prefix | test / build | Release |
| --- | --- | --- |
| `fix:` | run | patch |
| `feat:` | run | minor |
| `feat!:` or `BREAKING CHANGE:` | run | major |
| `ci:`, `refactor:`, `chore:`, `test:` | run | no bump from these; the release job still runs so pending `feat`/`fix` can publish |
| `docs:` | skipped | skipped |

PRs build `linux/amd64` only. Pushes to `main` also build `linux/arm64` on a native ARM runner. A published release still pushes both architectures.

Release notes go on GitHub Releases (`feat` / `fix` / breaking only). After a release, CI opens a `docs:` PR that only updates [CHANGELOG.md](CHANGELOG.md); merge that PR to keep the file in sync. Squash-merge feature PRs if you want `(#PR)` in the entry.

## Development

Work in the Dev Container (see the README). Parser tests do not need TAP:

```bash
cargo test
```

The terminal lab:

```bash
cargo run
```

# Contributing

Fork the repo and open a pull request against `main`. A maintainer reviews before merge. The `status` check must pass. `docs:` still runs `test` and `build` so required checks are not skipped; those jobs only echo and succeed.

## Commit messages

Releases are cut from [conventional commit](https://www.conventionalcommits.org/) messages that land on `main` (the PR title, if you squash-merge):

| Prefix | test / build | Release |
| --- | --- | --- |
| `fix:` | run | patch |
| `feat:` | run | minor |
| `feat!:` or `BREAKING CHANGE:` | run | major |
| `ci:`, `refactor:`, `chore:`, `test:` | run | no bump from these; the release job still runs so pending `feat`/`fix` can publish |
| `docs:` | no-op success | skipped |

PRs build `linux/amd64` only. Pushes to `main` also build `linux/arm64` on a native ARM runner, tagged `ghcr.io/<repo>:sha-<gitsha>-amd64` and `-arm64`. A GitHub Release retags those two images as `:<version>` and `:latest` (`docker buildx imagetools create`); it does not compile the image again. Host CLI binaries (Apple Silicon macOS and Linux) are built natively and uploaded to that Release, along with `scripts/install.sh`.

Release notes go on GitHub Releases (`feat` / `fix` / breaking only). After a release, CI opens a `docs:` PR that only updates [CHANGELOG.md](CHANGELOG.md) and marks the required checks green (Actions cannot start a second workflow with `GITHUB_TOKEN`). Merge that PR to keep the file in sync. Squash-merge feature PRs if you want `(#PR)` in the entry.

## Comments

minitcp is a teaching tool, so the protocol code carries the teaching. Everything else gets ordinary doc comments.

- `src/proto/`, `src/stack/handle.rs`, and the wire formats in `src/interface/` — explain the format, the field, and why a packet looks the way it does. Prose and diagrams belong here.
- Everywhere else (`src/cli/`, `src/sys/`, `src/tui/`, `src/log/`, `src/release/`) — a one-line `///` saying what the item is. Add a second sentence only when the code would otherwise be "corrected" back: a locale pin, a signal sent through `docker exec`, an error we deliberately swallow.
- Module headers are a couple of lines, plus a map of child modules where there are any.
- Tests are documented by their names. A comment in a test body means the assertion encodes a rule the name cannot carry.

If a comment restates the line under it, delete it.

## Development

Work in the Dev Container (see the README). Parser tests do not need TAP:

```bash
cargo test
```

The terminal lab:

```bash
cargo run
```

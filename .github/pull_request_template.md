## Summary

<!-- What does this change, and why? -->

## Checklist

- [ ] Conventional commit prefix on the PR title (and on commits, if you are not squashing): `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `ci:`, …
- [ ] `feat` / `fix` / `feat!` cut a release when merged. `ci:` / `refactor:` / `chore:` do not bump on their own; the release job still runs so earlier feat/fix on `main` can publish. `docs:` skips CI jobs.
- [ ] `status` is expected to pass (`test` and `build`, unless this is `docs:`).

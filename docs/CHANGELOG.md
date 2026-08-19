# [1.3.0](https://github.com/dfoshidero/minitcp/compare/v1.2.1...v1.3.0) (2026-08-19)


### Bug Fixes

* fail cleanly instead of panicking or swallowing TAP and Docker errors ([#8](https://github.com/dfoshidero/minitcp/issues/8)) ([4f4df0b](https://github.com/dfoshidero/minitcp/commit/4f4df0bf29f4babf5a6771b7ef4396a0bf7b04d8))
* report runtime failures as minitcp errors instead of panics ([3bbf100](https://github.com/dfoshidero/minitcp/commit/3bbf10091c0a6cb219c1138ef0cad08bbfa5c021))
* restore the TUI and stop children on SIGTERM/SIGHUP ([47366c6](https://github.com/dfoshidero/minitcp/commit/47366c682f5c2697ed528ead2c976dd6cf83d8e4))
* retry flaky Docker, TAP, and install I/O ([c3e90b5](https://github.com/dfoshidero/minitcp/commit/c3e90b5f092c0afe5db9a151ee55850e27946b7e))
* surface TAP, Docker, and subprocess failures instead of swallowing them ([aaf2d57](https://github.com/dfoshidero/minitcp/commit/aaf2d571ef0664c885f5f378fb7962b8cd1f076e))


### Features

* add --version and document 0/1/2 exit codes ([e11fac6](https://github.com/dfoshidero/minitcp/commit/e11fac6c4b8f229899d5f52049cbf4901474ae15))

## [1.2.1](https://github.com/dfoshidero/minitcp/compare/v1.2.0...v1.2.1) (2026-08-19)


### Bug Fixes

* run TAP sidecar as root and wait until :7946 is listening ([d5b42cc](https://github.com/dfoshidero/minitcp/commit/d5b42cca906e57d3593114aa63aa8062ee00c6c0))

# [1.2.0](https://github.com/dfoshidero/minitcp/compare/v1.1.2...v1.2.0) (2026-08-19)


### Features

* group the CLI by stack, TAP, identity, and pcap ([d18018a](https://github.com/dfoshidero/minitcp/commit/d18018a8fd243d06c3c6c3858056147614d61957))
* one-line install, TAP sidecar, and update nag ([b664bd1](https://github.com/dfoshidero/minitcp/commit/b664bd19619a5aeca45c25c7b78d1c306036e60f))

## [1.1.2](https://github.com/dfoshidero/minitcp/compare/v1.1.1...v1.1.2) (2026-08-19)


### Bug Fixes

* style --help with a bold title and commands ([199b457](https://github.com/dfoshidero/minitcp/commit/199b4579448c97129caef8fa6da81568fe7b6ff7))

## [1.1.1](https://github.com/dfoshidero/minitcp/compare/v1.1.0...v1.1.1) (2026-08-19)


### Bug Fixes

* print help after the Docker lab shell starts ([69460f3](https://github.com/dfoshidero/minitcp/commit/69460f30b8ba33957f6506fd7a70066156a1d8d4))
* print command-specific CLI errors ([34a1373](https://github.com/dfoshidero/minitcp/commit/34a13733df650f3124ce23b0d19e9f85f4355c98))


### Features

* add CLI config, help, and minitcp.toml ([148e1a3](https://github.com/dfoshidero/minitcp/commit/148e1a3bd2c19068a175b74625f0c69b58b5b2de))
* add drop, count, and ICMP lab knobs ([1f003a6](https://github.com/dfoshidero/minitcp/commit/1f003a6803b92fcc94335b0c033bf0635faa30e1))
* add pcap replay, write, and hex frames ([465f365](https://github.com/dfoshidero/minitcp/commit/465f3657145aeb0d0bce4a2ea5e0840fdaf8aac4))
* apply TAP identity from config ([f56ffbd](https://github.com/dfoshidero/minitcp/commit/f56ffbd3491530b68297ac0bdc589662b6d2eb2f))

## [1.0.2](https://github.com/dfoshidero/minitcp/compare/v1.0.1...v1.0.2) (2026-08-19)


### Bug Fixes

* drop Docker users into a shell after help ([f8b9bbb](https://github.com/dfoshidero/minitcp/commit/f8b9bbb6b464bf95407943ce895a721a4fb6c09c))

## [1.0.1](https://github.com/dfoshidero/minitcp/compare/v1.0.0...v1.0.1) (2026-08-19)


### Bug Fixes

* publish linux/amd64 and linux/arm64 images ([380a625](https://github.com/dfoshidero/minitcp/commit/380a625a1e3bb3fe7e855a764b969ad67c559162))

# Changelog

All notable changes to this project are documented here. This file is generated on each release.

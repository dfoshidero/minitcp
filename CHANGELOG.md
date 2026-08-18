# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/dfoshidero/minitcp/compare/v0.1.0...v0.1.1) - 2026-08-18

### Fixed

- put snap tools on PATH so minitcp finds ip and tcpdump
- create tap0 from the snap without sudo

### Other

- use git tags as version baseline for release-plz
- release v0.1.0

## [0.1.0](https://github.com/dfoshidero/minitcp/releases/tag/v0.1.0) - 2026-08-17

### Added

- add quiet and verbose stack logs
- reply to ICMP echo requests
- default minitcp to the terminal lab
- add ratatui terminal lab frontend
- add tap0 setup script
- dispatch IPv4 packets by protocol
- parse and serialize IPv4 packets
- add Internet checksum helper
- reply to ARP requests on tap0
- add ARP request parser
- parse Ethernet II frames from TAP
- add TAP interface and read loop

### Fixed

- explain missing tap0 on cargo run
- annotate the ARP target IP parse
- expose MacAddress bytes for ARP replies
- quote TUN path and return Result from main

### Other

- let release-plz tag packages that are not on crates.io
- clarify which commit types cut a release
- do not use secrets in workflow if conditions
- add snap package and conventional-commit releases
- document ICMP echo and the stack log
- rename the lab frontend to tui
- move wire formats into proto/
- document the minitcp terminal lab
- install minitcp in the Dev Container
- extract TAP loop into stack module
- update in-line comments and add glossary
- clarify field offsets and bit operations
- document tap0 setup script
- document IPv4 parse and dispatch
- document ARP neighbour replies
- describe Ethernet parsing and OSI placement
- ignore local cargo and editor files
- document TAP setup and usage
- bootstrap Dev Container and Cargo project

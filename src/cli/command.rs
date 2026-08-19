//! What the user asked minitcp to do.
//!
//! Exactly one `Command` comes out of parsing; every other flag is context for
//! it. The setters (`TapSetIface`, …) are commands, not flags, because they do
//! not configure this run — they write minitcp.toml and configure the next.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::proto::ethernet::MacAddress;

use super::flags::Scope;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelpTopic {
    Full,
    Tap,
    Identity,
    Pcap,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Run,
    Stack,
    Version,
    Replay(PathBuf),
    Pcap(PathBuf),
    Help(HelpTopic),
    Bridge,
    TapUp,
    TapDown,
    TapShow,
    TapSetIface(String),
    TapSetAddr(Ipv4Addr),
    TapSetTun(PathBuf),
    IdentityShow,
    IdentitySetAddr(Ipv4Addr),
    IdentitySetMac(MacAddress),
}

impl Command {
    /// Which family of flags this command reads.
    pub(super) fn scope(&self) -> Scope {
        match self {
            Command::Run | Command::Stack | Command::Replay(_) => Scope::Stack,
            Command::Bridge => Scope::Bridge,
            Command::TapUp | Command::TapDown | Command::TapShow => Scope::Tap,
            Command::IdentityShow => Scope::Identity,
            Command::Pcap(_) => Scope::Pcap,
            Command::TapSetIface(_)
            | Command::TapSetAddr(_)
            | Command::TapSetTun(_)
            | Command::IdentitySetAddr(_)
            | Command::IdentitySetMac(_)
            | Command::Help(_)
            | Command::Version => Scope::Config,
        }
    }

    /// How to name this command back to the user, as they would type it.
    pub(super) fn label(&self) -> &'static str {
        match self {
            Command::Run => "run",
            Command::Stack => "stack",
            Command::Version => "--version",
            Command::Replay(_) => "replay",
            Command::Pcap(_) => "pcap",
            Command::Help(_) => "--help",
            Command::Bridge => "bridge",
            Command::TapUp => "tap up",
            Command::TapDown => "tap down",
            Command::TapShow => "tap",
            Command::TapSetIface(_) => "tap iface",
            Command::TapSetAddr(_) => "tap addr",
            Command::TapSetTun(_) => "tap tun",
            Command::IdentityShow => "identity",
            Command::IdentitySetAddr(_) => "identity addr",
            Command::IdentitySetMac(_) => "identity mac",
        }
    }
}

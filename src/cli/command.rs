// What the user asked minitcp to do.
//
// Exactly one `Command` comes out of parsing, and every other flag is context
// for it. The setters (`TapSetIface`, `IdentitySetAddr`, …) are commands rather
// than flags because they do not configure this run — they write minitcp.toml
// and configure the next one.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::proto::ethernet::MacAddress;

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

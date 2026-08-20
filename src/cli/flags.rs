//! Turning one flag and its text into a value.
//!
//! `FLAGS` is the single list of every flag minitcp accepts; walking argv,
//! `--help` and error messages all read it, so a new flag is one entry rather
//! than four edits in four files. `apply_flag` below turns one of them into a
//! `Partial` field, using parsers shared with minitcp.toml so `--addr 10.0.0.3`
//! and `addr = "10.0.0.3"` cannot drift apart.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::proto::ethernet::MacAddress;

use super::error::{ParseError, missing_value};
use super::options::{DropKind, Partial};
use super::usage::flag_usage;

/// One flag, described once.
pub(super) struct Flag {
    /// The long name, as typed.
    pub name: &'static str,
    /// The short alias, if it has one.
    pub short: Option<&'static str>,
    /// What the value is called in help. `None` means the flag is on/off, and
    /// is also how argv walking knows not to eat the next word.
    pub metavar: Option<&'static str>,
    /// The one line of help shown after the name.
    pub help: &'static str,
    /// The commands that read this flag. Naming it anywhere else is a typo
    /// worth saying out loud, since the flag would otherwise do nothing.
    pub scopes: &'static [Scope],
}

/// The commands a flag can matter to, grouped by what they read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// `run`, `stack`, `replay FILE` — anything that moves frames.
    Stack,
    /// `bridge`.
    Bridge,
    /// `tap up`, `tap down`, `tap` .
    Tap,
    /// `identity`.
    Identity,
    /// `pcap FILE`, which reads nothing but the file.
    Pcap,
    /// The setters, which only write minitcp.toml.
    Config,
}

/// Every command, so `--config` can say it applies to all of them.
const ANY: &[Scope] = &[
    Scope::Stack,
    Scope::Bridge,
    Scope::Tap,
    Scope::Identity,
    Scope::Pcap,
    Scope::Config,
];
const STACK: &[Scope] = &[Scope::Stack];

pub(super) const FLAGS: &[Flag] = &[
    Flag {
        name: "--iface",
        short: None,
        metavar: Some("NAME"),
        help: "which TAP (default: tap0)",
        scopes: &[Scope::Stack, Scope::Bridge, Scope::Tap],
    },
    Flag {
        name: "--addr",
        short: None,
        metavar: Some("IP"),
        help: "MiniTCP's IPv4 (default: 10.0.0.2)",
        scopes: &[Scope::Stack, Scope::Identity],
    },
    Flag {
        name: "--mac",
        short: None,
        metavar: Some("MAC"),
        help: "MiniTCP's MAC (default: 02:00:00:00:00:02)",
        scopes: &[Scope::Stack, Scope::Identity],
    },
    Flag {
        name: "--linux-addr",
        short: None,
        metavar: Some("IP"),
        help: "Linux's IPv4 on that TAP (default: same street, .1)",
        scopes: &[Scope::Tap],
    },
    Flag {
        name: "--tun",
        short: None,
        metavar: Some("PATH"),
        help: "tun device (default: /dev/net/tun)",
        scopes: &[Scope::Stack, Scope::Bridge, Scope::Tap],
    },
    Flag {
        name: "--fwd",
        short: None,
        metavar: Some("HOST:PORT"),
        help: "talk to the TAP sidecar over TCP (default: 127.0.0.1:7946)",
        scopes: STACK,
    },
    Flag {
        name: "--listen",
        short: None,
        metavar: Some("ADDR"),
        help: "bridge listen address (default: 127.0.0.1:7946)",
        scopes: &[Scope::Bridge],
    },
    Flag {
        name: "--write",
        short: None,
        metavar: Some("FILE"),
        help: "also save frames to a pcap",
        scopes: STACK,
    },
    Flag {
        name: "--config",
        short: None,
        metavar: Some("FILE"),
        help: "TOML instead of ./minitcp.toml",
        scopes: ANY,
    },
    Flag {
        name: "--drop",
        short: None,
        metavar: Some("arp|icmp|ip"),
        help: "ignore that kind of frame (comma-ok: arp,icmp)",
        scopes: STACK,
    },
    Flag {
        name: "--drop-pct",
        short: None,
        metavar: Some("N"),
        help: "drop N percent of frames at random (0-100)",
        scopes: STACK,
    },
    Flag {
        name: "--ttl",
        short: None,
        metavar: Some("N"),
        help: "hop count on MiniTCP's IPv4 replies (default: 64)",
        scopes: STACK,
    },
    Flag {
        name: "--id",
        short: None,
        metavar: Some("N"),
        help: "ICMP echo id on replies (default: copy from request)",
        scopes: STACK,
    },
    Flag {
        name: "--count",
        short: Some("-c"),
        metavar: Some("N"),
        help: "stop after N frames (stack/replay)",
        scopes: STACK,
    },
    Flag {
        name: "--quiet",
        short: Some("-q"),
        metavar: None,
        help: "one line per exchange",
        scopes: STACK,
    },
    Flag {
        name: "--hex",
        short: None,
        metavar: None,
        help: "read frames as hex on stdin",
        scopes: STACK,
    },
    Flag {
        name: "--once",
        short: None,
        metavar: None,
        help: "stop after one frame (same as --count 1)",
        scopes: STACK,
    },
    Flag {
        name: "--offline",
        short: None,
        metavar: None,
        help: "don't check GitHub for a newer minitcp",
        scopes: ANY,
    },
];

/// Find a flag by either of its spellings.
pub(super) fn lookup(flag: &str) -> Option<&'static Flag> {
    FLAGS
        .iter()
        .find(|f| f.name == flag || f.short == Some(flag))
}

/// The long spelling of whatever the user typed, so everything downstream sees
/// one name per flag.
pub(super) fn canonical(flag: &str) -> &str {
    lookup(flag).map_or(flag, |f| f.name)
}

/// Does this flag reach the given command? Unknown flags are somebody else's
/// error, so they pass.
pub(super) fn applies(flag: &str, scope: Scope) -> bool {
    lookup(flag).is_none_or(|f| f.scopes.contains(&scope))
}

/// Does this flag consume the word after it? Argv walking needs to know before
/// it knows what the flag means.
pub(super) fn takes_value(flag: &str) -> bool {
    lookup(flag).is_some_and(|f| f.metavar.is_some())
}

pub(super) fn apply_flag(
    partial: &mut Partial,
    flag: &str,
    value: Option<&str>,
) -> Result<(), ParseError> {
    let need = || value.ok_or_else(|| missing_value(flag));
    match flag {
        "--quiet" => partial.quiet = Some(true),
        "--hex" => partial.hex = Some(true),
        "--offline" => partial.offline = Some(true),
        "--once" => partial.count = Some(1),
        "--fwd" => partial.fwd = Some(need()?.to_string()),
        "--listen" => partial.listen = Some(need()?.to_string()),
        "--iface" => partial.iface = Some(need()?.to_string()),
        "--addr" => partial.addr = Some(parse_ipv4(need()?)?),
        "--mac" => partial.mac = Some(parse_mac(need()?)?),
        "--linux-addr" => partial.linux_addr = Some(parse_ipv4(need()?)?),
        "--tun" => partial.tun = Some(PathBuf::from(need()?)),
        "--write" => partial.write = Some(PathBuf::from(need()?)),
        "--config" => partial.config = Some(PathBuf::from(need()?)),
        "--drop" => partial.drop = Some(parse_drop_list(need()?)?),
        "--drop-pct" => set_drop_pct(partial, parse_count(need()?)?)?,
        "--ttl" => set_ttl(partial, parse_count(need()?)?)?,
        "--id" => set_icmp_id(partial, parse_count(need()?)?)?,
        "--count" => partial.count = Some(parse_count(need()?)?),
        other => return Err(ParseError::msg(format!("unknown flag '{other}'"))),
    }
    Ok(())
}

/// Reject a number outside the range the protocol field can hold, naming the
/// flag so the message reads the same whether it came from argv or the file.
fn in_range(n: u64, max: u64, flag: &str) -> Result<u64, ParseError> {
    if n > max {
        return Err(ParseError::with_usage(
            format!("{} must be 0-{max}", flag.trim_start_matches('-')),
            flag_usage(flag),
        ));
    }
    Ok(n)
}

// The bounded numbers live here rather than at each caller so `--ttl 300` and
// `ttl = 300` cannot end up disagreeing about what is allowed.

pub(super) fn set_drop_pct(partial: &mut Partial, n: u64) -> Result<(), ParseError> {
    partial.drop_pct = Some(in_range(n, 100, "--drop-pct")? as u8);
    Ok(())
}

pub(super) fn set_ttl(partial: &mut Partial, n: u64) -> Result<(), ParseError> {
    partial.ttl = Some(in_range(n, 255, "--ttl")? as u8);
    Ok(())
}

pub(super) fn set_icmp_id(partial: &mut Partial, n: u64) -> Result<(), ParseError> {
    partial.icmp_id = Some(in_range(n, u16::MAX as u64, "--id")? as u16);
    Ok(())
}

pub(super) fn parse_count(s: &str) -> Result<u64, ParseError> {
    s.parse()
        .map_err(|_| ParseError::msg(format!("invalid number: {s}")))
}

pub fn parse_mac(s: &str) -> Result<MacAddress, ParseError> {
    let sep = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return Err(ParseError::msg(format!("invalid MAC: {s}")));
    };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 6 {
        return Err(ParseError::msg(format!("invalid MAC: {s}")));
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|_| ParseError::msg(format!("invalid MAC: {s}")))?;
        if part.len() != 2 {
            return Err(ParseError::msg(format!("invalid MAC: {s}")));
        }
    }
    Ok(MacAddress(bytes))
}

pub(crate) fn parse_ipv4(s: &str) -> Result<Ipv4Addr, ParseError> {
    s.parse()
        .map_err(|_| ParseError::msg(format!("invalid IPv4 address: {s}")))
}

pub(crate) fn parse_drop_list(s: &str) -> Result<Vec<DropKind>, ParseError> {
    let mut out = Vec::new();
    for part in s.split(',') {
        if part.trim().is_empty() {
            continue;
        }
        let kind = DropKind::parse(part)?;
        if !out.contains(&kind) {
            out.push(kind);
        }
    }
    if out.is_empty() {
        return Err(missing_value("--drop"));
    }
    Ok(out)
}

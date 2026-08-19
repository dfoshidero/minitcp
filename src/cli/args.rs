use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::proto::ethernet::MacAddress;

use super::config::{Command, DropKind, HelpTopic, Partial};
use super::error::{
    ParseError, USAGE_COMMANDS, USAGE_IDENTITY, USAGE_PCAP, USAGE_REPLAY, USAGE_TAP, flag_usage,
    missing_value,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    None,
    Tap,
    Identity,
    Pcap,
}

pub fn parse_mac(s: &str) -> Result<MacAddress, String> {
    let sep = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return Err(format!("invalid MAC: {s}"));
    };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 6 {
        return Err(format!("invalid MAC: {s}"));
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).map_err(|_| format!("invalid MAC: {s}"))?;
        if part.len() != 2 {
            return Err(format!("invalid MAC: {s}"));
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

fn take_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, ParseError> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| missing_value(flag))
}

fn split_eq(arg: &str) -> Option<(&str, &str)> {
    arg.split_once('=')
}

fn peek(args: &[String], i: usize) -> Option<&str> {
    args.get(i + 1).map(String::as_str)
}

fn is_help(s: &str) -> bool {
    s == "-h" || s == "--help"
}

pub(crate) fn parse_cli(args: &[String]) -> Result<Partial, ParseError> {
    let mut partial = Partial::default();
    let mut family = Family::None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if is_help(arg) {
            let topic = match family {
                Family::None => HelpTopic::Full,
                Family::Tap => HelpTopic::Tap,
                Family::Identity => HelpTopic::Identity,
                Family::Pcap => HelpTopic::Pcap,
            };
            set_command(&mut partial, Command::Help(topic))?;
            i += 1;
            continue;
        }
        if let Some((flag, value)) = split_eq(arg).filter(|(f, _)| f.starts_with("--")) {
            apply_flag(&mut partial, flag, Some(value))?;
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            match arg {
                "-q" | "--quiet" => partial.quiet = Some(true),
                "-V" | "--version" => set_command(&mut partial, Command::Version)?,
                "--hex" => partial.hex = Some(true),
                "--offline" => partial.offline = Some(true),
                "--once" => partial.count = Some(1),
                "-c" | "--count" => {
                    let v = take_value(args, &mut i, arg)?;
                    partial.count = Some(parse_count(v)?);
                }
                "--iface" | "--addr" | "--mac" | "--linux-addr" | "--tun" | "--write"
                | "--config" | "--drop" | "--drop-pct" | "--ttl" | "--id" | "--fwd"
                | "--listen" => {
                    let v = take_value(args, &mut i, arg)?;
                    apply_flag(&mut partial, arg, Some(v))?;
                }
                other => {
                    return Err(ParseError::msg(format!("unknown flag '{other}'")));
                }
            }
            i += 1;
            continue;
        }
        match arg {
            "help" if partial.command.is_none() => {
                set_command(&mut partial, Command::Help(HelpTopic::Full))?;
            }
            "run" => set_command(&mut partial, Command::Run)?,
            "stack" => set_command(&mut partial, Command::Stack)?,
            "replay" => {
                let file = take_value(args, &mut i, "replay").map_err(|_| {
                    ParseError::with_usage("replay needs a pcap path", USAGE_REPLAY)
                })?;
                set_command(&mut partial, Command::Replay(PathBuf::from(file)))?;
            }
            "pcap" | "pcap-info" => {
                family = Family::Pcap;
                match peek(args, i) {
                    None => return Err(ParseError::usage_only(USAGE_PCAP)),
                    Some(next) if is_help(next) => {}
                    Some(next) if next.starts_with('-') => {
                        return Err(ParseError::usage_only(USAGE_PCAP));
                    }
                    Some(_) => {
                        let file = take_value(args, &mut i, "pcap")
                            .map_err(|_| ParseError::usage_only(USAGE_PCAP))?;
                        set_command(&mut partial, Command::Pcap(PathBuf::from(file)))?;
                    }
                }
            }
            "bridge" => set_command(&mut partial, Command::Bridge)?,
            "tap" => {
                family = Family::Tap;
                parse_tap(args, &mut i, &mut partial)?;
            }
            "identity" => {
                family = Family::Identity;
                parse_identity(args, &mut i, &mut partial)?;
            }
            other => {
                return Err(ParseError::with_usage(
                    format!("unknown command '{other}'"),
                    USAGE_COMMANDS,
                ));
            }
        }
        i += 1;
    }
    Ok(partial)
}

fn parse_tap(args: &[String], i: &mut usize, partial: &mut Partial) -> Result<(), ParseError> {
    match peek(args, *i) {
        None => set_command(partial, Command::TapShow),
        Some(next) if is_help(next) => Ok(()),
        Some(next) if next.starts_with('-') => set_command(partial, Command::TapShow),
        Some("up") => {
            *i += 1;
            set_command(partial, Command::TapUp)
        }
        Some("down") => {
            *i += 1;
            set_command(partial, Command::TapDown)
        }
        Some("iface") => {
            *i += 1;
            let name =
                take_value(args, i, "tap iface").map_err(|_| ParseError::usage_only(USAGE_TAP))?;
            set_command(partial, Command::TapSetIface(name.to_string()))
        }
        Some("addr") => {
            *i += 1;
            let ip =
                take_value(args, i, "tap addr").map_err(|_| ParseError::usage_only(USAGE_TAP))?;
            set_command(partial, Command::TapSetAddr(parse_ipv4(ip)?))
        }
        Some("tun") => {
            *i += 1;
            let path =
                take_value(args, i, "tap tun").map_err(|_| ParseError::usage_only(USAGE_TAP))?;
            set_command(partial, Command::TapSetTun(PathBuf::from(path)))
        }
        Some(_) => {
            *i += 1;
            Err(ParseError::usage_only(USAGE_TAP))
        }
    }
}

fn parse_identity(args: &[String], i: &mut usize, partial: &mut Partial) -> Result<(), ParseError> {
    match peek(args, *i) {
        None => set_command(partial, Command::IdentityShow),
        Some(next) if is_help(next) => Ok(()),
        Some(next) if next.starts_with('-') => set_command(partial, Command::IdentityShow),
        Some("addr") => {
            *i += 1;
            let ip = take_value(args, i, "identity addr")
                .map_err(|_| ParseError::usage_only(USAGE_IDENTITY))?;
            set_command(partial, Command::IdentitySetAddr(parse_ipv4(ip)?))
        }
        Some("mac") => {
            *i += 1;
            let mac = take_value(args, i, "identity mac")
                .map_err(|_| ParseError::usage_only(USAGE_IDENTITY))?;
            set_command(
                partial,
                Command::IdentitySetMac(parse_mac(mac).map_err(ParseError::msg)?),
            )
        }
        Some(_) => {
            *i += 1;
            Err(ParseError::usage_only(USAGE_IDENTITY))
        }
    }
}

fn set_command(partial: &mut Partial, command: Command) -> Result<(), ParseError> {
    match &partial.command {
        None => {
            partial.command = Some(command);
            Ok(())
        }
        Some(Command::Help(_)) => Ok(()),
        Some(_) => Err(ParseError::with_usage(
            "only one command is allowed",
            USAGE_COMMANDS,
        )),
    }
}

fn apply_flag(partial: &mut Partial, flag: &str, value: Option<&str>) -> Result<(), ParseError> {
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
        "--mac" => partial.mac = Some(parse_mac(need()?).map_err(ParseError::msg)?),
        "--linux-addr" => partial.linux_addr = Some(parse_ipv4(need()?)?),
        "--tun" => partial.tun = Some(PathBuf::from(need()?)),
        "--write" => partial.write = Some(PathBuf::from(need()?)),
        "--config" => partial.config = Some(PathBuf::from(need()?)),
        "--drop" => partial.drop = Some(parse_drop_list(need()?)?),
        "--drop-pct" => {
            let n = parse_count(need()?)?;
            if n > 100 {
                return Err(ParseError::with_usage(
                    "drop-pct must be 0-100",
                    flag_usage("--drop-pct"),
                ));
            }
            partial.drop_pct = Some(n as u8);
        }
        "--ttl" => {
            let n = parse_count(need()?)?;
            if n > 255 {
                return Err(ParseError::with_usage(
                    "ttl must be 0-255",
                    flag_usage("--ttl"),
                ));
            }
            partial.ttl = Some(n as u8);
        }
        "--id" => {
            let n = parse_count(need()?)?;
            if n > u16::MAX as u64 {
                return Err(ParseError::with_usage(
                    "id must be 0-65535",
                    flag_usage("--id"),
                ));
            }
            partial.icmp_id = Some(n as u16);
        }
        "-c" | "--count" => partial.count = Some(parse_count(need()?)?),
        other => return Err(ParseError::msg(format!("unknown flag '{other}'"))),
    }
    Ok(())
}

fn parse_count(s: &str) -> Result<u64, ParseError> {
    s.parse()
        .map_err(|_| ParseError::msg(format!("invalid number: {s}")))
}

// Turning one flag and its text into a value.
//
// `apply_flag` is the single table of every flag minitcp accepts: what it is
// called, whether it takes a value, and what that value must look like. The
// small parsers below it are shared with minitcp.toml, so `--addr 10.0.0.3` and
// `addr = "10.0.0.3"` are validated by exactly the same code and cannot drift
// apart.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::proto::ethernet::MacAddress;

use super::error::{ParseError, missing_value};
use super::options::{DropKind, Partial};
use super::usage::flag_usage;

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

pub(super) fn parse_count(s: &str) -> Result<u64, ParseError> {
    s.parse()
        .map_err(|_| ParseError::msg(format!("invalid number: {s}")))
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

use std::path::Path;

use super::args::{parse_drop_list, parse_ipv4, parse_mac};
use super::config::{DropKind, Partial};
use super::error::{flag_usage, ParseError, USAGE_CONFIG};

fn toml_string(v: &::toml::Value, key: &str) -> Result<String, ParseError> {
    v.as_str()
        .map(str::to_string)
        .ok_or_else(|| {
            ParseError::with_usage(format!("config key {key} must be a string"), USAGE_CONFIG)
        })
}

fn toml_bool(v: &::toml::Value, key: &str) -> Result<bool, ParseError> {
    v.as_bool().ok_or_else(|| {
        ParseError::with_usage(format!("config key {key} must be a boolean"), USAGE_CONFIG)
    })
}

fn toml_u64(v: &::toml::Value, key: &str) -> Result<u64, ParseError> {
    v.as_integer()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| {
            ParseError::with_usage(
                format!("config key {key} must be a non-negative integer"),
                USAGE_CONFIG,
            )
        })
}

pub(crate) fn apply(partial: &mut Partial, table: &::toml::Table) -> Result<(), ParseError> {
    for (key, value) in table {
        match key.as_str() {
            "iface" => partial.iface = Some(toml_string(value, key)?),
            "addr" => partial.addr = Some(parse_ipv4(&toml_string(value, key)?)?),
            "mac" => partial.mac = Some(parse_mac(&toml_string(value, key)?)?),
            "linux-addr" | "linux_addr" => {
                partial.linux_addr = Some(parse_ipv4(&toml_string(value, key)?)?)
            }
            "tun" => partial.tun = Some(std::path::PathBuf::from(toml_string(value, key)?)),
            "no_create_tap" | "no-create-tap" => {
                partial.no_create_tap = Some(toml_bool(value, key)?)
            }
            "write" => partial.write = Some(std::path::PathBuf::from(toml_string(value, key)?)),
            "hex" => partial.hex = Some(toml_bool(value, key)?),
            "quiet" => partial.quiet = Some(toml_bool(value, key)?),
            "count" => partial.count = Some(toml_u64(value, key)?),
            "drop" => partial.drop = Some(toml_drop(value)?),
            "drop-pct" | "drop_pct" => {
                let n = toml_u64(value, key)?;
                if n > 100 {
                    return Err(ParseError::with_usage(
                        "drop-pct must be 0-100",
                        flag_usage("--drop-pct"),
                    ));
                }
                partial.drop_pct = Some(n as u8);
            }
            "ttl" => {
                let n = toml_u64(value, key)?;
                if n > 255 {
                    return Err(ParseError::with_usage(
                        "ttl must be 0-255",
                        flag_usage("--ttl"),
                    ));
                }
                partial.ttl = Some(n as u8);
            }
            "id" => {
                let n = toml_u64(value, key)?;
                if n > u16::MAX as u64 {
                    return Err(ParseError::with_usage(
                        "id must be 0-65535",
                        flag_usage("--id"),
                    ));
                }
                partial.icmp_id = Some(n as u16);
            }
            other => {
                return Err(ParseError::with_usage(
                    format!("unknown config key: {other}"),
                    USAGE_CONFIG,
                ))
            }
        }
    }
    Ok(())
}

fn toml_drop(value: &::toml::Value) -> Result<Vec<DropKind>, ParseError> {
    match value {
        ::toml::Value::String(s) => parse_drop_list(s),
        ::toml::Value::Array(items) => {
            let mut joined = Vec::new();
            for item in items {
                let name = item.as_str().ok_or_else(|| {
                    ParseError::with_usage("drop entries must be strings", flag_usage("--drop"))
                })?;
                joined.push(DropKind::parse(name)?);
            }
            if joined.is_empty() {
                return Err(ParseError::with_usage(
                    "drop must list arp, icmp, or ip",
                    flag_usage("--drop"),
                ));
            }
            Ok(joined)
        }
        _ => Err(ParseError::with_usage(
            "drop must be a string or array of strings",
            flag_usage("--drop"),
        )),
    }
}

pub(crate) fn load(path: &Path) -> Result<::toml::Table, ParseError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        ParseError::with_usage(
            format!("config file not found: {} ({e})", path.display()),
            USAGE_CONFIG,
        )
    })?;
    text.parse::<::toml::Table>().map_err(|e| {
        ParseError::with_usage(
            format!("invalid TOML in {}: {e}", path.display()),
            USAGE_CONFIG,
        )
    })
}

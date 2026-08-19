// src/cli.rs
// Flags anywhere. Defaults < minitcp.toml < command line.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::proto::arp::{OUR_IP, OUR_MAC};
use crate::proto::ethernet::MacAddress;

pub const DEFAULT_IFACE: &str = "tap0";
pub const DEFAULT_TUN: &str = "/dev/net/tun";
pub const DEFAULT_TTL: u8 = 64;
pub const DEFAULT_CONFIG: &str = "minitcp.toml";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Run,
    Stack,
    Replay(PathBuf),
    PcapInfo(PathBuf),
    Help,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropKind {
    Arp,
    Icmp,
    Ip,
}

impl DropKind {
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "arp" => Ok(Self::Arp),
            "icmp" => Ok(Self::Icmp),
            "ip" => Ok(Self::Ip),
            other => Err(format!("unknown drop kind: {other} (want arp, icmp, or ip)")),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub command: Command,
    pub iface: String,
    pub addr: Ipv4Addr,
    pub mac: MacAddress,
    pub linux_addr: Ipv4Addr,
    pub tun: PathBuf,
    pub no_create_tap: bool,
    pub write: Option<PathBuf>,
    pub hex: bool,
    pub quiet: bool,
    pub count: Option<u64>,
    pub drop: Vec<DropKind>,
    pub drop_pct: u8,
    pub ttl: u8,
    pub icmp_id: Option<u16>,
}

impl Config {
    pub fn defaults() -> Self {
        let addr = Ipv4Addr::from(OUR_IP);
        Self {
            command: Command::Run,
            iface: DEFAULT_IFACE.into(),
            addr,
            mac: OUR_MAC,
            linux_addr: default_linux_addr(addr),
            tun: PathBuf::from(DEFAULT_TUN),
            no_create_tap: false,
            write: None,
            hex: false,
            quiet: false,
            count: None,
            drop: Vec::new(),
            drop_pct: 0,
            ttl: DEFAULT_TTL,
            icmp_id: None,
        }
    }

    pub fn our_ip_bytes(&self) -> [u8; 4] {
        self.addr.octets()
    }

    pub fn verbose(&self) -> bool {
        !self.quiet
    }

    /// Flags the TUI child `minitcp stack` process should inherit.
    pub fn child_stack_args(&self, verbose: bool) -> Vec<String> {
        let mut args = vec!["stack".into()];
        args.push("--iface".into());
        args.push(self.iface.clone());
        args.push("--addr".into());
        args.push(self.addr.to_string());
        args.push("--mac".into());
        args.push(self.mac.to_string());
        args.push("--linux-addr".into());
        args.push(self.linux_addr.to_string());
        args.push("--tun".into());
        args.push(self.tun.display().to_string());
        if self.no_create_tap {
            args.push("--no-create-tap".into());
        }
        if let Some(path) = &self.write {
            args.push("--write".into());
            args.push(path.display().to_string());
        }
        if self.hex {
            args.push("--hex".into());
        }
        if !verbose {
            args.push("--quiet".into());
        }
        if let Some(n) = self.count {
            args.push("--count".into());
            args.push(n.to_string());
        }
        if !self.drop.is_empty() {
            args.push("--drop".into());
            args.push(
                self.drop
                    .iter()
                    .map(|k| match k {
                        DropKind::Arp => "arp",
                        DropKind::Icmp => "icmp",
                        DropKind::Ip => "ip",
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if self.drop_pct > 0 {
            args.push("--drop-pct".into());
            args.push(self.drop_pct.to_string());
        }
        args.push("--ttl".into());
        args.push(self.ttl.to_string());
        if let Some(id) = self.icmp_id {
            args.push("--id".into());
            args.push(id.to_string());
        }
        args
    }
}

#[derive(Default)]
struct Partial {
    command: Option<Command>,
    iface: Option<String>,
    addr: Option<Ipv4Addr>,
    mac: Option<MacAddress>,
    linux_addr: Option<Ipv4Addr>,
    tun: Option<PathBuf>,
    no_create_tap: Option<bool>,
    write: Option<PathBuf>,
    hex: Option<bool>,
    quiet: Option<bool>,
    count: Option<u64>,
    drop: Option<Vec<DropKind>>,
    drop_pct: Option<u8>,
    ttl: Option<u8>,
    icmp_id: Option<u16>,
    config: Option<PathBuf>,
}

pub fn usage() -> &'static str {
    "minitcp — userspace TCP/IP lab

  minitcp [run]           terminal UI (default) | run is the same
  minitcp stack           TAP loop only (no UI)
  minitcp replay FILE     play a pcap instead of TAP
  minitcp pcap-info FILE  list frames in a pcap (no stack)

Everything below is optional.

Cable and identity:
  --iface NAME            which TAP (default: tap0)
  --addr IP               MiniTCP's IPv4 (default: 10.0.0.2)
  --mac MAC               MiniTCP's MAC (default: 02:00:00:00:00:02)
                          change with --addr only if two MiniTCPs share one TAP
  --linux-addr IP         Linux's IPv4 on that TAP (default: same street, .1)
  --tun PATH              tun device (default: /dev/net/tun)
  --no-create-tap         do not create the TAP; fail if it is missing
  --config FILE           TOML instead of ./minitcp.toml

Captures:
  --write FILE            also save frames to a pcap
  --hex                   read hex Ethernet frames from stdin (stack)

Lab knobs:
  -q, --quiet             one line per exchange
  -c, --count N           stop after N frames (stack/replay)
  --once                  same as -c 1
  --drop arp|icmp|ip      ignore that kind of frame (comma-ok: arp,icmp)
  --drop-pct N            drop N percent of frames at random (0-100)
  --ttl N                 hop count on MiniTCP's IPv4 replies (default: 64)
  --id N                  ICMP echo id on replies (default: copy from request)

Config file if needed — same flags.

  # minitcp.toml
  iface = \"tap1\"
  addr = \"10.0.0.3\"
  quiet = true
  drop = [\"icmp\"]

Examples (typical combinations):
  minitcp
  minitcp -q
  minitcp --iface tap1
  minitcp --addr 10.0.0.3 --mac 02:00:00:00:00:03
  minitcp stack --write out.pcap
  minitcp replay out.pcap -q
  minitcp pcap-info out.pcap
  minitcp stack --drop icmp -c 5
  minitcp --config ./lab.toml stack
"
}

pub fn default_linux_addr(addr: Ipv4Addr) -> Ipv4Addr {
    let o = addr.octets();
    Ipv4Addr::new(o[0], o[1], o[2], 1)
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

fn parse_ipv4(s: &str) -> Result<Ipv4Addr, String> {
    s.parse()
        .map_err(|_| format!("invalid IPv4 address: {s}"))
}

fn parse_drop_list(s: &str) -> Result<Vec<DropKind>, String> {
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
        return Err("flag --drop needs arp, icmp, or ip".into());
    }
    Ok(out)
}

fn take_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, String> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| format!("flag {flag} needs a value"))
}

fn split_eq(arg: &str) -> Option<(&str, &str)> {
    arg.split_once('=')
}

fn apply_partial(base: &mut Config, over: &Partial) {
    if let Some(v) = &over.iface {
        base.iface = v.clone();
    }
    if let Some(v) = over.addr {
        base.addr = v;
    }
    if let Some(v) = over.mac {
        base.mac = v;
    }
    if let Some(v) = over.linux_addr {
        base.linux_addr = v;
    }
    if let Some(v) = &over.tun {
        base.tun = v.clone();
    }
    if let Some(v) = over.no_create_tap {
        base.no_create_tap = v;
    }
    if let Some(v) = &over.write {
        base.write = Some(v.clone());
    }
    if let Some(v) = over.hex {
        base.hex = v;
    }
    if let Some(v) = over.quiet {
        base.quiet = v;
    }
    if let Some(v) = over.count {
        base.count = Some(v);
    }
    if let Some(v) = &over.drop {
        base.drop = v.clone();
    }
    if let Some(v) = over.drop_pct {
        base.drop_pct = v;
    }
    if let Some(v) = over.ttl {
        base.ttl = v;
    }
    if let Some(v) = over.icmp_id {
        base.icmp_id = Some(v);
    }
}

fn toml_string(v: &toml::Value, key: &str) -> Result<String, String> {
    v.as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("config key {key} must be a string"))
}

fn toml_bool(v: &toml::Value, key: &str) -> Result<bool, String> {
    v.as_bool()
        .ok_or_else(|| format!("config key {key} must be a boolean"))
}

fn toml_u64(v: &toml::Value, key: &str) -> Result<u64, String> {
    v.as_integer()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| format!("config key {key} must be a non-negative integer"))
}

fn apply_toml(partial: &mut Partial, table: &toml::Table) -> Result<(), String> {
    for (key, value) in table {
        match key.as_str() {
            "iface" => partial.iface = Some(toml_string(value, key)?),
            "addr" => partial.addr = Some(parse_ipv4(&toml_string(value, key)?)?),
            "mac" => partial.mac = Some(parse_mac(&toml_string(value, key)?)?),
            "linux-addr" | "linux_addr" => {
                partial.linux_addr = Some(parse_ipv4(&toml_string(value, key)?)?)
            }
            "tun" => partial.tun = Some(PathBuf::from(toml_string(value, key)?)),
            "no_create_tap" | "no-create-tap" => {
                partial.no_create_tap = Some(toml_bool(value, key)?)
            }
            "write" => partial.write = Some(PathBuf::from(toml_string(value, key)?)),
            "hex" => partial.hex = Some(toml_bool(value, key)?),
            "quiet" => partial.quiet = Some(toml_bool(value, key)?),
            "count" => partial.count = Some(toml_u64(value, key)?),
            "drop" => partial.drop = Some(toml_drop(value)?),
            "drop-pct" | "drop_pct" => {
                let n = toml_u64(value, key)?;
                if n > 100 {
                    return Err("drop-pct must be 0-100".into());
                }
                partial.drop_pct = Some(n as u8);
            }
            "ttl" => {
                let n = toml_u64(value, key)?;
                if n > 255 {
                    return Err("ttl must be 0-255".into());
                }
                partial.ttl = Some(n as u8);
            }
            "id" => {
                let n = toml_u64(value, key)?;
                if n > u16::MAX as u64 {
                    return Err("id must be 0-65535".into());
                }
                partial.icmp_id = Some(n as u16);
            }
            other => return Err(format!("unknown config key: {other}")),
        }
    }
    Ok(())
}

fn toml_drop(value: &toml::Value) -> Result<Vec<DropKind>, String> {
    match value {
        toml::Value::String(s) => parse_drop_list(s),
        toml::Value::Array(items) => {
            let mut joined = Vec::new();
            for item in items {
                let name = item
                    .as_str()
                    .ok_or_else(|| "drop entries must be strings".to_string())?;
                joined.push(DropKind::parse(name)?);
            }
            if joined.is_empty() {
                return Err("drop must list arp, icmp, or ip".into());
            }
            Ok(joined)
        }
        _ => Err("drop must be a string or array of strings".into()),
    }
}

fn parse_cli(args: &[String]) -> Result<Partial, String> {
    let mut partial = Partial::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "-h" || arg == "--help" {
            partial.command = Some(Command::Help);
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
                "--hex" => partial.hex = Some(true),
                "--no-create-tap" => partial.no_create_tap = Some(true),
                "--once" => partial.count = Some(1),
                "-c" | "--count" => {
                    let v = take_value(args, &mut i, arg)?;
                    partial.count = Some(parse_count(v)?);
                }
                "--iface" | "--addr" | "--mac" | "--linux-addr" | "--tun" | "--write"
                | "--config" | "--drop" | "--drop-pct" | "--ttl" | "--id" => {
                    let v = take_value(args, &mut i, arg)?;
                    apply_flag(&mut partial, arg, Some(v))?;
                }
                other => return Err(format!("unknown flag: {other}")),
            }
            i += 1;
            continue;
        }
        match arg {
            "help" if partial.command.is_none() => partial.command = Some(Command::Help),
            "run" => set_command(&mut partial, Command::Run)?,
            "stack" => set_command(&mut partial, Command::Stack)?,
            "replay" => {
                let file = take_value(args, &mut i, "replay")
                    .map_err(|_| "replay needs a file".to_string())?;
                set_command(&mut partial, Command::Replay(PathBuf::from(file)))?;
            }
            "pcap-info" => {
                let file = take_value(args, &mut i, "pcap-info")
                    .map_err(|_| "pcap-info needs a file".to_string())?;
                set_command(&mut partial, Command::PcapInfo(PathBuf::from(file)))?;
            }
            other => return Err(format!("unknown command: {other}")),
        }
        i += 1;
    }
    Ok(partial)
}

fn set_command(partial: &mut Partial, command: Command) -> Result<(), String> {
    match &partial.command {
        None => {
            partial.command = Some(command);
            Ok(())
        }
        Some(Command::Help) => Ok(()),
        Some(_) => Err("only one command is allowed".into()),
    }
}

fn apply_flag(partial: &mut Partial, flag: &str, value: Option<&str>) -> Result<(), String> {
    let need = || value.ok_or_else(|| format!("flag {flag} needs a value"));
    match flag {
        "--quiet" => partial.quiet = Some(true),
        "--hex" => partial.hex = Some(true),
        "--no-create-tap" => partial.no_create_tap = Some(true),
        "--once" => partial.count = Some(1),
        "--iface" => partial.iface = Some(need()?.to_string()),
        "--addr" => partial.addr = Some(parse_ipv4(need()?)?),
        "--mac" => partial.mac = Some(parse_mac(need()?)?),
        "--linux-addr" => partial.linux_addr = Some(parse_ipv4(need()?)?),
        "--tun" => partial.tun = Some(PathBuf::from(need()?)),
        "--write" => partial.write = Some(PathBuf::from(need()?)),
        "--config" => partial.config = Some(PathBuf::from(need()?)),
        "--drop" => partial.drop = Some(parse_drop_list(need()?)?),
        "--drop-pct" => {
            let n = parse_count(need()?)?;
            if n > 100 {
                return Err("drop-pct must be 0-100".into());
            }
            partial.drop_pct = Some(n as u8);
        }
        "--ttl" => {
            let n = parse_count(need()?)?;
            if n > 255 {
                return Err("ttl must be 0-255".into());
            }
            partial.ttl = Some(n as u8);
        }
        "--id" => {
            let n = parse_count(need()?)?;
            if n > u16::MAX as u64 {
                return Err("id must be 0-65535".into());
            }
            partial.icmp_id = Some(n as u16);
        }
        "-c" | "--count" => partial.count = Some(parse_count(need()?)?),
        other => return Err(format!("unknown flag: {other}")),
    }
    Ok(())
}

fn parse_count(s: &str) -> Result<u64, String> {
    s.parse()
        .map_err(|_| format!("invalid number: {s}"))
}

fn load_toml_file(path: &Path) -> Result<toml::Table, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    text.parse::<toml::Table>()
        .map_err(|e| format!("invalid TOML in {}: {e}", path.display()))
}

/// Parse argv without the program name. `cwd` is where `./minitcp.toml` is sought.
pub fn parse_from(args: &[String], cwd: &Path) -> Result<Config, String> {
    let cli = parse_cli(args)?;
    if matches!(cli.command, Some(Command::Help)) {
        let mut cfg = Config::defaults();
        cfg.command = Command::Help;
        return Ok(cfg);
    }

    let mut file = Partial::default();
    if let Some(path) = &cli.config {
        if !path.is_file() {
            return Err(format!("cannot read {}", path.display()));
        }
        apply_toml(&mut file, &load_toml_file(path)?)?;
    } else {
        let default_path = cwd.join(DEFAULT_CONFIG);
        if default_path.is_file() {
            apply_toml(&mut file, &load_toml_file(&default_path)?)?;
        }
    }

    let mut cfg = Config::defaults();
    apply_partial(&mut cfg, &file);
    apply_partial(&mut cfg, &cli);
    if file.linux_addr.is_none() && cli.linux_addr.is_none() {
        cfg.linux_addr = default_linux_addr(cfg.addr);
    }
    cfg.command = cli.command.unwrap_or(Command::Run);
    Ok(cfg)
}

pub fn parse(args: &[String]) -> Result<Config, String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    parse_from(args, &cwd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn empty_cwd() -> PathBuf {
        PathBuf::from("/tmp")
    }

    fn parse_ok(parts: &[&str]) -> Config {
        parse_from(&args(parts), &empty_cwd()).unwrap()
    }

    fn parse_err(parts: &[&str]) -> String {
        parse_from(&args(parts), &empty_cwd()).unwrap_err()
    }

    fn unique_dir() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("minitcp-cli-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn defaults_match_the_lab() {
        let cfg = parse_ok(&[]);
        assert_eq!(cfg.command, Command::Run);
        assert_eq!(cfg.iface, "tap0");
        assert_eq!(cfg.addr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(cfg.mac, OUR_MAC);
        assert_eq!(cfg.linux_addr, Ipv4Addr::new(10, 0, 0, 1));
        assert!(!cfg.quiet);
        assert!(cfg.drop.is_empty());
        assert_eq!(cfg.ttl, 64);
        assert!(!cfg.no_create_tap);
    }

    #[test]
    fn flags_can_sit_before_or_after_stack() {
        let before = parse_ok(&["-q", "--iface", "tap1", "stack"]);
        let after = parse_ok(&["stack", "--iface", "tap1", "-q"]);
        assert_eq!(before.command, Command::Stack);
        assert_eq!(after.command, Command::Stack);
        assert_eq!(before.iface, "tap1");
        assert_eq!(after.iface, "tap1");
        assert!(before.quiet && after.quiet);
    }

    #[test]
    fn quiet_and_once_are_flags() {
        let q = parse_ok(&["--quiet"]);
        assert!(q.quiet);
        let once = parse_ok(&["stack", "--once"]);
        assert_eq!(once.count, Some(1));
        let count = parse_ok(&["-c", "3"]);
        assert_eq!(count.count, Some(3));
        assert_eq!(once.count, parse_ok(&["--once"]).count);
    }

    #[test]
    fn unknown_flag_errors() {
        let err = parse_err(&["--nope"]);
        assert!(err.contains("unknown flag"), "{err}");
    }

    #[test]
    fn replay_needs_a_file() {
        let err = parse_err(&["replay"]);
        assert_eq!(err, "replay needs a file");
        let cfg = parse_ok(&["replay", "out.pcap"]);
        assert_eq!(cfg.command, Command::Replay(PathBuf::from("out.pcap")));
    }

    #[test]
    fn addr_and_mac_are_independent() {
        let only_addr = parse_ok(&["--addr", "10.0.0.3"]);
        assert_eq!(only_addr.addr, Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(only_addr.mac, OUR_MAC);
        assert_eq!(only_addr.linux_addr, Ipv4Addr::new(10, 0, 0, 1));

        let only_mac = parse_ok(&["--mac", "02:00:00:00:00:03"]);
        assert_eq!(only_mac.addr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            only_mac.mac,
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x03])
        );
    }

    #[test]
    fn linux_addr_defaults_to_dot_one_on_the_same_street() {
        let cfg = parse_ok(&["--addr", "10.1.2.9"]);
        assert_eq!(cfg.linux_addr, Ipv4Addr::new(10, 1, 2, 1));
        let explicit = parse_ok(&["--addr", "10.1.2.9", "--linux-addr", "10.1.2.5"]);
        assert_eq!(explicit.linux_addr, Ipv4Addr::new(10, 1, 2, 5));
    }

    #[test]
    fn no_create_tap_parses() {
        assert!(parse_ok(&["--no-create-tap"]).no_create_tap);
    }

    #[test]
    fn drop_accepts_comma_lists() {
        let cfg = parse_ok(&["--drop", "arp,icmp"]);
        assert_eq!(cfg.drop, vec![DropKind::Arp, DropKind::Icmp]);
    }

    #[test]
    fn help_text_names_the_new_commands() {
        let text = usage();
        assert!(text.contains("replay"));
        assert!(text.contains("--iface"));
        assert!(text.contains("--drop"));
        assert!(text.contains("--config"));
        assert!(text.contains("minitcp.toml"));
    }

    #[test]
    fn missing_default_toml_is_ok() {
        let dir = unique_dir();
        let cfg = parse_from(&[], &dir).unwrap();
        assert_eq!(cfg.addr, Ipv4Addr::new(10, 0, 0, 2));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_config_path_errors() {
        let err = parse_err(&["--config", "/no/such/minitcp.toml"]);
        assert!(err.contains("cannot read"), "{err}");
    }

    #[test]
    fn toml_sets_addr_and_cli_wins() {
        let dir = unique_dir();
        fs::write(
            dir.join("lab.toml"),
            "addr = \"10.0.0.9\"\nquiet = true\n",
        )
        .unwrap();
        let from_file = parse_from(
            &args(&["--config", dir.join("lab.toml").to_str().unwrap()]),
            &dir,
        )
        .unwrap();
        assert_eq!(from_file.addr, Ipv4Addr::new(10, 0, 0, 9));
        assert!(from_file.quiet);

        let overridden = parse_from(
            &args(&[
                "--config",
                dir.join("lab.toml").to_str().unwrap(),
                "--addr",
                "10.0.0.4",
            ]),
            &dir,
        )
        .unwrap();
        assert_eq!(overridden.addr, Ipv4Addr::new(10, 0, 0, 4));
        assert!(overridden.quiet);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn toml_unknown_key_errors() {
        let dir = unique_dir();
        fs::write(dir.join("lab.toml"), "nope = true\n").unwrap();
        let err = parse_from(
            &args(&["--config", dir.join("lab.toml").to_str().unwrap()]),
            &dir,
        )
        .unwrap_err();
        assert!(err.contains("unknown config key"), "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn default_minitcp_toml_in_cwd_is_loaded() {
        let dir = unique_dir();
        fs::write(dir.join("minitcp.toml"), "iface = \"tap1\"\n").unwrap();
        let cfg = parse_from(&[], &dir).unwrap();
        assert_eq!(cfg.iface, "tap1");
        let _ = fs::remove_dir_all(dir);
    }
}

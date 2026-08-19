use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::proto::arp::{OUR_IP, OUR_MAC};
use crate::proto::ethernet::MacAddress;

use super::error::{flag_usage, ParseError};

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
    pub fn parse(name: &str) -> Result<Self, ParseError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "arp" => Ok(Self::Arp),
            "icmp" => Ok(Self::Icmp),
            "ip" => Ok(Self::Ip),
            other => Err(ParseError::with_usage(
                format!("unknown drop kind '{other}' (want arp, icmp, or ip)"),
                flag_usage("--drop"),
            )),
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
pub(crate) struct Partial {
    pub command: Option<Command>,
    pub iface: Option<String>,
    pub addr: Option<Ipv4Addr>,
    pub mac: Option<MacAddress>,
    pub linux_addr: Option<Ipv4Addr>,
    pub tun: Option<PathBuf>,
    pub no_create_tap: Option<bool>,
    pub write: Option<PathBuf>,
    pub hex: Option<bool>,
    pub quiet: Option<bool>,
    pub count: Option<u64>,
    pub drop: Option<Vec<DropKind>>,
    pub drop_pct: Option<u8>,
    pub ttl: Option<u8>,
    pub icmp_id: Option<u16>,
    pub config: Option<PathBuf>,
}

pub fn default_linux_addr(addr: Ipv4Addr) -> Ipv4Addr {
    let o = addr.octets();
    Ipv4Addr::new(o[0], o[1], o[2], 1)
}

pub(crate) fn apply_partial(base: &mut Config, over: &Partial) {
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

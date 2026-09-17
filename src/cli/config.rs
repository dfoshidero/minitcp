use std::net::Ipv4Addr;
use std::path::PathBuf;

use minitcp::proto::arp::{OUR_IP, OUR_MAC};
use minitcp::proto::ethernet::MacAddress;

use super::error::{ParseError, flag_usage};

pub(crate) const DEFAULT_IFACE: &str = "tap0";
pub(crate) const DEFAULT_TUN: &str = "/dev/net/tun";
pub(crate) const DEFAULT_TTL: u8 = 64;
pub(crate) const DEFAULT_CONFIG: &str = "minitcp.toml";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HelpTopic {
    Full,
    Tap,
    Identity,
    Pcap,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Command {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DropKind {
    Arp,
    Icmp,
    Ip,
}

impl DropKind {
    pub(crate) fn parse(name: &str) -> Result<Self, ParseError> {
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

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Icmp => "icmp",
            Self::Ip => "ip",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Config {
    pub(crate) command: Command,
    pub(crate) iface: String,
    pub(crate) addr: Ipv4Addr,
    pub(crate) mac: MacAddress,
    pub(crate) linux_addr: Ipv4Addr,
    pub(crate) tun: PathBuf,
    pub(crate) write: Option<PathBuf>,
    pub(crate) hex: bool,
    pub(crate) quiet: bool,
    pub(crate) count: Option<u64>,
    pub(crate) drop: Vec<DropKind>,
    pub(crate) drop_pct: u8,
    pub(crate) ttl: u8,
    pub(crate) icmp_id: Option<u16>,
    pub(crate) fwd: Option<String>,
    pub(crate) listen: String,
    pub(crate) offline: bool,
    pub(crate) config_path: PathBuf,
}

impl Config {
    pub(crate) fn defaults() -> Self {
        let addr = Ipv4Addr::from(OUR_IP);
        Self {
            command: Command::Run,
            iface: DEFAULT_IFACE.into(),
            addr,
            mac: OUR_MAC,
            linux_addr: default_linux_addr(addr),
            tun: PathBuf::from(DEFAULT_TUN),
            write: None,
            hex: false,
            quiet: false,
            count: None,
            drop: Vec::new(),
            drop_pct: 0,
            ttl: DEFAULT_TTL,
            icmp_id: None,
            fwd: None,
            listen: crate::fwd::DEFAULT_LISTEN.into(),
            offline: false,
            config_path: PathBuf::from(DEFAULT_CONFIG),
        }
    }

    pub(crate) fn our_ip_bytes(&self) -> [u8; 4] {
        self.addr.octets()
    }

    pub(crate) fn verbose(&self) -> bool {
        !self.quiet
    }

    /// Host stack talks to the TAP sidecar over TCP unless `/dev/net/tun` is here.
    pub(crate) fn use_fwd(&self) -> bool {
        if self.fwd.is_some() {
            return true;
        }
        !self.tun.exists()
    }

    pub(crate) fn fwd_addr(&self) -> String {
        self.fwd
            .clone()
            .unwrap_or_else(|| crate::fwd::DEFAULT_FWD.into())
    }

    /// Flags the TUI child `minitcp stack` process should inherit.
    pub(crate) fn child_stack_args(&self, verbose: bool) -> Vec<String> {
        fn flag(args: &mut Vec<String>, name: &str, value: String) {
            args.extend([name.to_string(), value]);
        }

        let mut args = vec!["stack".into()];
        flag(&mut args, "--iface", self.iface.clone());
        flag(&mut args, "--addr", self.addr.to_string());
        flag(&mut args, "--mac", self.mac.to_string());
        flag(&mut args, "--linux-addr", self.linux_addr.to_string());
        flag(&mut args, "--tun", self.tun.display().to_string());
        if let Some(path) = &self.write {
            flag(&mut args, "--write", path.display().to_string());
        }
        if self.hex {
            args.push("--hex".into());
        }
        if !verbose {
            args.push("--quiet".into());
        }
        if let Some(n) = self.count {
            flag(&mut args, "--count", n.to_string());
        }
        if !self.drop.is_empty() {
            let kinds: Vec<_> = self.drop.iter().map(|k| k.name()).collect();
            flag(&mut args, "--drop", kinds.join(","));
        }
        if self.drop_pct > 0 {
            flag(&mut args, "--drop-pct", self.drop_pct.to_string());
        }
        flag(&mut args, "--ttl", self.ttl.to_string());
        if let Some(id) = self.icmp_id {
            flag(&mut args, "--id", id.to_string());
        }
        if let Some(fwd) = &self.fwd {
            flag(&mut args, "--fwd", fwd.clone());
        }
        args
    }
}

#[derive(Default)]
pub(crate) struct Partial {
    pub(crate) command: Option<Command>,
    pub(crate) iface: Option<String>,
    pub(crate) addr: Option<Ipv4Addr>,
    pub(crate) mac: Option<MacAddress>,
    pub(crate) linux_addr: Option<Ipv4Addr>,
    pub(crate) tun: Option<PathBuf>,
    pub(crate) write: Option<PathBuf>,
    pub(crate) hex: Option<bool>,
    pub(crate) quiet: Option<bool>,
    pub(crate) count: Option<u64>,
    pub(crate) drop: Option<Vec<DropKind>>,
    pub(crate) drop_pct: Option<u8>,
    pub(crate) ttl: Option<u8>,
    pub(crate) icmp_id: Option<u16>,
    pub(crate) config: Option<PathBuf>,
    pub(crate) fwd: Option<String>,
    pub(crate) listen: Option<String>,
    pub(crate) offline: Option<bool>,
}

pub(crate) fn default_linux_addr(addr: Ipv4Addr) -> Ipv4Addr {
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
    if let Some(v) = &over.fwd {
        base.fwd = Some(v.clone());
    }
    if let Some(v) = &over.listen {
        base.listen = v.clone();
    }
    if let Some(v) = over.offline {
        base.offline = v;
    }
}

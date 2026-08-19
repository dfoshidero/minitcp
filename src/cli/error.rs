// Command-specific parse errors. Full --help is only for --help.

pub(crate) const TRY_HELP: &str = "Try 'minitcp --help' for the full list.";

pub(crate) const USAGE_COMMANDS: &str = "\
usage:
  minitcp [run]           terminal UI (default) | run is the same
  minitcp stack           TAP loop only (no UI)
  minitcp replay FILE     play a pcap instead of TAP
  minitcp pcap-info FILE  list frames in a pcap (no stack)";

pub(crate) const USAGE_REPLAY: &str = "\
usage: minitcp replay FILE
  play a pcap instead of TAP

example: minitcp replay out.pcap -q";

pub(crate) const USAGE_PCAP_INFO: &str = "\
usage: minitcp pcap-info FILE
  list frames in a pcap (no stack)

example: minitcp pcap-info out.pcap";

pub(crate) const USAGE_CONFIG: &str = "\
usage: --config FILE           TOML instead of ./minitcp.toml
  --config must point at an existing file.
  Omit it to use ./minitcp.toml if that file is present.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub usage: Option<String>,
}

impl ParseError {
    pub(crate) fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: Some(TRY_HELP.into()),
        }
    }

    pub(crate) fn with_usage(message: impl Into<String>, usage: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: Some(usage.into()),
        }
    }

    pub fn report(&self) -> String {
        match &self.usage {
            Some(usage) => format!("error: {}\n\n{usage}\n", self.message),
            None => format!("error: {}\n\n{TRY_HELP}\n", self.message),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.report())
    }
}

impl From<String> for ParseError {
    fn from(message: String) -> Self {
        Self::msg(message)
    }
}

impl From<&str> for ParseError {
    fn from(message: &str) -> Self {
        Self::msg(message)
    }
}

pub(crate) fn flag_usage(flag: &str) -> &'static str {
    match flag {
        "--iface" => "usage: --iface NAME            which TAP (default: tap0)",
        "--addr" => "usage: --addr IP               MiniTCP's IPv4 (default: 10.0.0.2)",
        "--mac" => "usage: --mac MAC               MiniTCP's MAC (default: 02:00:00:00:00:02)",
        "--linux-addr" => {
            "usage: --linux-addr IP         Linux's IPv4 on that TAP (default: same street, .1)"
        }
        "--tun" => "usage: --tun PATH              tun device (default: /dev/net/tun)",
        "--write" => "usage: --write FILE            also save frames to a pcap",
        "--config" => USAGE_CONFIG,
        "--drop" => "usage: --drop arp|icmp|ip      ignore that kind of frame (comma-ok: arp,icmp)",
        "--drop-pct" => {
            "usage: --drop-pct N            drop N percent of frames at random (0-100)"
        }
        "--ttl" => {
            "usage: --ttl N                 hop count on MiniTCP's IPv4 replies (default: 64)"
        }
        "--id" => {
            "usage: --id N                  ICMP echo id on replies (default: copy from request)"
        }
        "-c" | "--count" => "usage: -c, --count N           stop after N frames (stack/replay)",
        "replay" => USAGE_REPLAY,
        "pcap-info" => USAGE_PCAP_INFO,
        _ => TRY_HELP,
    }
}

pub(crate) fn missing_value(flag: &str) -> ParseError {
    ParseError::with_usage(format!("{flag} needs a value"), flag_usage(flag))
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

#[cfg(test)]
mod tests {
    use super::usage;

    #[test]
    fn help_text_names_the_new_commands() {
        let text = usage();
        assert!(text.contains("replay"));
        assert!(text.contains("--iface"));
        assert!(text.contains("--drop"));
        assert!(text.contains("--config"));
        assert!(text.contains("minitcp.toml"));
    }
}

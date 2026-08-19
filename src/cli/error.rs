// Command-specific parse errors. Full --help is only for --help.

use std::io::IsTerminal;

use crossterm::style::Stylize;

pub(crate) const TRY_HELP: &str = "Try 'minitcp --help' for the full list.";

pub(crate) const USAGE_COMMANDS: &str = "\
usage:
  minitcp [run]           terminal UI (default) | run is the same
  minitcp stack           TAP loop only (no UI)
  minitcp tap up|down     start/stop the TAP sidecar (Docker)
  minitcp bridge          TAP <-> frames on :7946 (inside the sidecar)
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

pub(crate) const USAGE_TAP: &str = "\
usage: minitcp tap up|down
  tap up    start the TAP sidecar (Docker) or a local Linux TAP
  tap down  stop it

example: minitcp tap up";

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
        "--fwd" => "usage: --fwd HOST:PORT         stack over TCP frames (default: 127.0.0.1:7946)",
        "--listen" => {
            "usage: --listen ADDR           bridge listen address (default: 0.0.0.0:7946)"
        }
        "tap" => USAGE_TAP,
        "--write" => "usage: --write FILE            also save frames to a pcap",
        "--config" => USAGE_CONFIG,
        "--drop" => "usage: --drop arp|icmp|ip      ignore that kind of frame (comma-ok: arp,icmp)",
        "--drop-pct" => "usage: --drop-pct N            drop N percent of frames at random (0-100)",
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

pub fn usage() -> String {
    let color = std::io::stderr().is_terminal();
    let title = "minitcp — userspace TCP/IP lab";
    let title = if color {
        title.bold().cyan().to_string()
    } else {
        title.to_string()
    };
    let cmd = |s: &str| {
        if color {
            s.bold().to_string()
        } else {
            s.to_string()
        }
    };
    format!(
        "
{title}

	{install}

	{run}           terminal UI (default) | run is the same
	{stack}           TAP loop only (no UI)
	{tap}     start/stop the TAP sidecar (needs Docker)
	{bridge}        TAP <-> TCP frames; used by the sidecar image
	{replay}     play a pcap instead of TAP
	{pcap_info}  list frames in a pcap (no stack)

Everything below is optional.

Cable and identity:
	--iface NAME            which TAP (default: tap0)
	--addr IP               MiniTCP's IPv4 (default: 10.0.0.2)
	--mac MAC               MiniTCP's MAC (default: 02:00:00:00:00:02)
	                        change with --addr only if two MiniTCPs share one TAP
	--linux-addr IP         Linux's IPv4 on that TAP (default: same street, .1)
	--tun PATH              tun device (default: /dev/net/tun)
	--fwd HOST:PORT         stack over TCP frames (default: 127.0.0.1:7946)
	--listen ADDR           bridge listen address (default: 0.0.0.0:7946)
	--tap                   force a local TAP even if a sidecar is available
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
	--offline               skip the GitHub update check

Config file if needed — same flags.

	# minitcp.toml
	iface = \"tap1\"
	addr = \"10.0.0.3\"
	quiet = true
	drop = [\"icmp\"]

Examples (typical combinations):
	{ex1}
	{ex2}
	{ex3}
	{ex4}
	{ex5}
	{ex6}
	{ex7}
	{ex8}
	{ex9}
	{ex10}
",
        install = cmd(
            "curl -fsSL https://github.com/dfoshidero/minitcp/releases/latest/download/install.sh | sh"
        ),
        run = cmd("minitcp [run]"),
        stack = cmd("minitcp stack"),
        tap = cmd("minitcp tap up|down"),
        bridge = cmd("minitcp bridge"),
        replay = cmd("minitcp replay FILE"),
        pcap_info = cmd("minitcp pcap-info FILE"),
        ex1 = cmd("minitcp tap up"),
        ex2 = cmd("minitcp"),
        ex3 = cmd("minitcp tap down"),
        ex4 = cmd("minitcp -q"),
        ex5 = cmd("minitcp --iface tap1"),
        ex6 = cmd("minitcp stack --write out.pcap"),
        ex7 = cmd("minitcp replay out.pcap -q"),
        ex8 = cmd("minitcp pcap-info out.pcap"),
        ex9 = cmd("minitcp stack --drop icmp -c 5"),
        ex10 = cmd("minitcp --config ./lab.toml stack"),
    )
}

#[cfg(test)]
mod tests {
    use super::usage;

    #[test]
    fn help_text_names_the_new_commands() {
        let text = usage();
        assert!(text.contains("replay"));
        assert!(text.contains("tap up"));
        assert!(text.contains("bridge"));
        assert!(text.contains("install.sh"));
        assert!(text.contains("--fwd"));
        assert!(text.contains("--iface"));
        assert!(text.contains("--drop"));
        assert!(text.contains("--config"));
        assert!(text.contains("minitcp.toml"));
        assert!(!text.contains("docker run"));
    }
}

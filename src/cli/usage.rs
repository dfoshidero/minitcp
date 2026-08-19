// The help text, and the one-line usage blocks that go with a specific error.
//
// Kept apart from the parser so that adding a flag means touching a table here
// rather than hunting through parsing code, and so an error can point at the
// three lines that matter instead of dumping the whole of --help.

use std::io::IsTerminal;

use crossterm::style::Stylize;

use super::command::HelpTopic;

pub(crate) const TRY_HELP: &str = "Try 'minitcp --help' for the full list.";

pub(crate) const USAGE_COMMANDS: &str = "\
usage:
  minitcp [run]              terminal UI (default)
  minitcp stack              TAP loop only (no UI)
  minitcp replay FILE        same loop, from a pcap
  minitcp tap                the virtual cable
    up | down | iface | addr | tun
  minitcp identity           MiniTCP on the wire
    addr | mac
  minitcp pcap FILE          list frames (no stack)";

pub(crate) const USAGE_REPLAY: &str = "\
usage: minitcp replay FILE
  play a pcap instead of TAP

example: minitcp replay out.pcap -q";

pub(crate) const USAGE_PCAP: &str = "\
usage: minitcp pcap FILE
  list frames in a pcap (no stack)

example: minitcp pcap out.pcap";

pub(crate) const USAGE_TAP: &str = "\
usage: minitcp tap <command>

  up            start sidecar or local TAP
  down          stop it
  iface NAME    which TAP (default: tap0)
  addr IP       Linux's IPv4 on that TAP
  tun PATH      tun device (default: /dev/net/tun)

example: minitcp tap up";

pub(crate) const USAGE_IDENTITY: &str = "\
usage: minitcp identity [command]

  addr IP     MiniTCP's IPv4 (default: 10.0.0.2)
  mac MAC     MiniTCP's MAC

No command prints the current identity. Setters write minitcp.toml.

example: minitcp identity addr 10.0.0.3";

pub(crate) const USAGE_CONFIG: &str = "\
usage: --config FILE           TOML instead of ./minitcp.toml
  --config must point at an existing file.
  Omit it to use ./minitcp.toml if that file is present.";

pub(crate) fn flag_usage(flag: &str) -> &'static str {
    match flag {
        "--iface" => "usage: --iface NAME            which TAP (default: tap0)",
        "--addr" => "usage: --addr IP               MiniTCP's IPv4 (default: 10.0.0.2)",
        "--mac" => "usage: --mac MAC               MiniTCP's MAC (default: 02:00:00:00:00:02)",
        "--linux-addr" => {
            "usage: --linux-addr IP         Linux's IPv4 on that TAP (default: same street, .1)"
        }
        "--tun" => "usage: --tun PATH              tun device (default: /dev/net/tun)",
        "--fwd" => {
            "usage: --fwd HOST:PORT         talk to the TAP sidecar over TCP (default: 127.0.0.1:7946)"
        }
        "--listen" => {
            "usage: --listen ADDR           bridge listen address (default: 127.0.0.1:7946)"
        }
        "tap" => USAGE_TAP,
        "identity" => USAGE_IDENTITY,
        "pcap" | "pcap-info" => USAGE_PCAP,
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
        _ => TRY_HELP,
    }
}

pub fn usage_topic(topic: HelpTopic) -> String {
    match topic {
        HelpTopic::Full => usage(),
        HelpTopic::Tap => format!("{USAGE_TAP}\n"),
        HelpTopic::Identity => format!("{USAGE_IDENTITY}\n"),
        HelpTopic::Pcap => format!("{USAGE_PCAP}\n"),
    }
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

	{run}                 terminal UI (default)
	{stack}                 TAP loop only (no UI)
	{replay}           same loop, from a pcap

	{tap}                   the virtual cable
	  {tap_up}                          start sidecar or local TAP
	  {tap_down}                        stop it
	  {tap_iface}                  which TAP (default: tap0)
	  {tap_addr}                     Linux's IPv4 on that TAP
	  {tap_tun}                    tun device (default: /dev/net/tun)

	{identity}              MiniTCP on the wire
	  {id_addr}                     MiniTCP's IPv4 (default: 10.0.0.2)
	  {id_mac}                     MiniTCP's MAC

	{pcap}             list frames (no stack)

	{quiet}                   one line per exchange
	{count}                 stop after N frames (stack/replay)
	{write}                  also save frames to a pcap
	{drop}            ignore that kind of frame
	{fwd}               talk to the TAP sidecar over TCP
	{offline}                     don't check GitHub for a newer minitcp
	{version}                 print the packaged minitcp version

Same knobs can live in minitcp.toml in this directory, or --config FILE.
Command line wins over the file. identity / tap setters write that file.

Exit status: 0 success, 1 runtime failure, 2 command-line usage error.

	# minitcp.toml
	iface = \"tap1\"
	addr = \"10.0.0.3\"
	quiet = true
	drop = [\"icmp\"]
",
        install = cmd(&format!("curl -fsSL {} | sh", crate::release::INSTALL_URL)),
        run = cmd("minitcp [run]"),
        stack = cmd("minitcp stack"),
        replay = cmd("minitcp replay FILE"),
        tap = cmd("minitcp tap"),
        tap_up = cmd("up"),
        tap_down = cmd("down"),
        tap_iface = cmd("iface NAME"),
        tap_addr = cmd("addr IP"),
        tap_tun = cmd("tun PATH"),
        identity = cmd("minitcp identity"),
        id_addr = cmd("addr IP"),
        id_mac = cmd("mac MAC"),
        pcap = cmd("minitcp pcap FILE"),
        quiet = cmd("--quiet, -q"),
        count = cmd("-c, --count N"),
        write = cmd("--write FILE"),
        drop = cmd("--drop arp|icmp|ip"),
        fwd = cmd("--fwd HOST:PORT"),
        offline = cmd("--offline"),
        version = cmd("--version, -V"),
    )
}

#[cfg(test)]
mod tests {
    use super::usage;

    #[test]
    fn help_text_names_the_new_commands() {
        let text = usage();
        assert!(text.contains("replay"));
        assert!(text.contains("minitcp tap"));
        assert!(text.contains("iface NAME"));
        assert!(text.contains("minitcp identity"));
        assert!(text.contains("minitcp pcap FILE"));
        assert!(text.contains("install.sh"));
        assert!(text.contains("--fwd"));
        assert!(text.contains("--quiet"));
        assert!(text.contains("-q"));
        assert!(text.contains("--drop"));
        assert!(text.contains("--version"));
        assert!(text.contains("Exit status: 0 success"));
        assert!(text.contains("--config FILE"));
        assert!(text.contains("minitcp.toml"));
        assert!(!text.contains("minitcp bridge"));
        assert!(!text.contains("docker run"));
        assert!(!text.contains("--no-create-tap"));
        assert!(!text.contains("force a local TAP"));
    }
}

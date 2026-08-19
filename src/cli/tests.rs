use super::*;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::proto::arp::OUR_MAC;
use crate::proto::ethernet::MacAddress;

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
    parse_from(&args(parts), &empty_cwd()).unwrap_err().report()
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
    assert!(cfg.verbose);
    assert!(cfg.drop.is_empty());
    assert_eq!(cfg.ttl, 64);
}

#[test]
fn flags_can_sit_before_or_after_stack() {
    let before = parse_ok(&["-q", "--iface", "tap1", "stack"]);
    let after = parse_ok(&["stack", "--iface", "tap1", "-q"]);
    assert_eq!(before.command, Command::Stack);
    assert_eq!(after.command, Command::Stack);
    assert_eq!(before.iface, "tap1");
    assert_eq!(after.iface, "tap1");
    assert!(!before.verbose && !after.verbose);
}

#[test]
fn quiet_and_once_are_flags() {
    let q = parse_ok(&["--quiet"]);
    assert!(!q.verbose);
    let once = parse_ok(&["stack", "--once"]);
    assert_eq!(once.count, Some(1));
    let count = parse_ok(&["-c", "3"]);
    assert_eq!(count.count, Some(3));
    assert_eq!(once.count, parse_ok(&["--once"]).count);
}

#[test]
fn unknown_flag_errors() {
    let err = parse_err(&["--nope"]);
    assert!(err.contains("unknown flag '--nope'"), "{err}");
    assert!(err.contains("Try 'minitcp --help'"), "{err}");
    assert!(!err.contains("Everything below is optional"), "{err}");
}

#[test]
fn replay_needs_a_file() {
    let err = parse_err(&["replay"]);
    assert!(err.contains("replay needs a pcap path"), "{err}");
    assert!(err.contains("replay FILE"), "{err}");
    assert!(!err.contains("Everything below is optional"), "{err}");
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
fn drop_accepts_comma_lists() {
    let cfg = parse_ok(&["--drop", "arp,icmp"]);
    assert_eq!(cfg.drop, vec![DropKind::Arp, DropKind::Icmp]);
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
    assert!(err.contains("config file not found"), "{err}");
    assert!(err.contains("/no/such/minitcp.toml"), "{err}");
    assert!(!err.contains("Everything below is optional"), "{err}");
    assert!(err.contains("--config FILE"), "{err}");
}

#[test]
fn toml_sets_addr_and_cli_wins() {
    let dir = unique_dir();
    fs::write(dir.join("lab.toml"), "addr = \"10.0.0.9\"\nquiet = true\n").unwrap();
    let from_file = parse_from(
        &args(&["--config", dir.join("lab.toml").to_str().unwrap()]),
        &dir,
    )
    .unwrap();
    assert_eq!(from_file.addr, Ipv4Addr::new(10, 0, 0, 9));
    assert!(!from_file.verbose);

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
    assert!(!overridden.verbose);
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
    .unwrap_err()
    .report();
    assert!(err.contains("unknown config key"), "{err}");
    assert!(!err.contains("Everything below is optional"), "{err}");
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

#[test]
fn tap_family_parses() {
    assert_eq!(parse_ok(&["tap", "up"]).command, Command::TapUp);
    assert_eq!(parse_ok(&["tap", "down"]).command, Command::TapDown);
    assert_eq!(parse_ok(&["bridge"]).command, Command::Bridge);
    assert_eq!(parse_ok(&["tap"]).command, Command::TapShow);
    assert_eq!(
        parse_ok(&["tap", "--help"]).command,
        Command::Help(HelpTopic::Tap)
    );
    // A bad subcommand says what was wrong before it shows the family usage.
    let err = parse_err(&["tap", "nope"]);
    assert!(
        err.contains("error: unknown tap subcommand 'nope'"),
        "{err}"
    );
    assert!(err.contains("usage: minitcp tap"), "{err}");
    let set = parse_ok(&["tap", "addr", "10.0.0.9"]);
    assert_eq!(set.command, Command::TapSetAddr(Ipv4Addr::new(10, 0, 0, 9)));
}

#[test]
fn a_missing_argument_says_what_was_missing() {
    for (argv, want) in [
        (vec!["pcap"], "pcap needs a FILE"),
        (vec!["tap", "iface"], "tap iface needs a NAME"),
        (vec!["tap", "addr"], "tap addr needs an IP"),
        (vec!["identity", "mac"], "identity mac needs a MAC"),
    ] {
        let err = parse_err(&argv);
        assert!(err.contains(want), "{argv:?}: {err}");
    }
}

#[test]
fn pcap_and_replay_parse() {
    let cfg = parse_ok(&["pcap", "out.pcap"]);
    assert_eq!(cfg.command, Command::Pcap(PathBuf::from("out.pcap")));
    let alias = parse_ok(&["pcap-info", "out.pcap"]);
    assert_eq!(alias.command, Command::Pcap(PathBuf::from("out.pcap")));
    let err = parse_err(&["pcap"]);
    assert!(err.contains("usage: minitcp pcap FILE"), "{err}");
    assert!(!err.contains("needs a value"), "{err}");
}

#[test]
fn identity_parses_and_writes_toml() {
    assert_eq!(parse_ok(&["identity"]).command, Command::IdentityShow);
    assert_eq!(
        parse_ok(&["identity", "--help"]).command,
        Command::Help(HelpTopic::Identity)
    );
    let dir = unique_dir();
    let path = dir.join("minitcp.toml");
    let cfg = parse_from(
        &args(&[
            "--config",
            path.to_str().unwrap(),
            "identity",
            "addr",
            "10.0.0.9",
        ]),
        &dir,
    )
    .unwrap();
    assert_eq!(
        cfg.command,
        Command::IdentitySetAddr(Ipv4Addr::new(10, 0, 0, 9))
    );
    write_config_key(&cfg, "addr", "10.0.0.9").unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("10.0.0.9"), "{text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn fwd_and_offline_parse() {
    let fwd = parse_ok(&["--fwd", "127.0.0.1:7946"]);
    assert_eq!(fwd.fwd.as_deref(), Some("127.0.0.1:7946"));
    assert!(parse_ok(&["--offline"]).offline);
}

#[test]
fn version_flag_does_not_require_config() {
    assert_eq!(parse_ok(&["--version"]).command, Command::Version);
    assert_eq!(parse_ok(&["-V"]).command, Command::Version);
}

#[test]
fn force_tap_and_no_create_are_gone() {
    let err = parse_err(&["--tap"]);
    assert!(err.contains("unknown flag '--tap'"), "{err}");
    let err = parse_err(&["--no-create-tap"]);
    assert!(err.contains("unknown flag '--no-create-tap'"), "{err}");
}

// The flag table is the single list of what minitcp accepts. These pin the
// three consumers to it, so a flag added in one place and forgotten in another
// fails here rather than at somebody's terminal.

#[test]
fn every_flag_in_the_table_parses() {
    // --config is checked for existence at parse time, so it needs a real file.
    let config = unique_dir().join("minitcp.toml");
    fs::write(&config, "").unwrap();
    for flag in super::flags::FLAGS {
        let mut argv = vec![flag.name.to_string()];
        if let Some(metavar) = flag.metavar {
            let value = if flag.name == "--config" {
                config.display().to_string()
            } else {
                sample_value(metavar).to_string()
            };
            argv.push(value);
        }
        assert!(
            parse_from(&argv, &empty_cwd()).is_ok(),
            "{} is in FLAGS but apply_flag rejects it",
            flag.name
        );
    }
}

#[test]
fn short_spellings_mean_the_same_as_long_ones() {
    for flag in super::flags::FLAGS {
        let Some(short) = flag.short else { continue };
        assert_eq!(super::flags::canonical(short), flag.name);
        assert_eq!(
            super::flags::takes_value(short),
            flag.metavar.is_some(),
            "{short} and {} disagree about taking a value",
            flag.name
        );
    }
}

#[test]
fn the_tui_child_is_only_handed_flags_that_exist() {
    let cfg = parse_ok(&["stack"]);
    let argv = cfg.child_stack_args(true);
    for word in argv.iter().filter(|w| w.starts_with('-')) {
        assert!(
            super::flags::lookup(word).is_some(),
            "child_stack_args passes {word}, which is not in FLAGS"
        );
    }
}

#[test]
fn flag_usage_names_the_flag_and_its_value() {
    assert_eq!(
        super::usage::flag_usage("--iface"),
        "usage: --iface NAME            which TAP (default: tap0)"
    );
    assert_eq!(
        super::usage::flag_usage("-c"),
        "usage: -c, --count N           stop after N frames (stack/replay)"
    );
}

/// A value each metavar will actually accept, so the table test exercises the
/// parser rather than the error path.
fn sample_value(metavar: &str) -> &'static str {
    match metavar {
        "NAME" => "tap0",
        "IP" => "10.0.0.9",
        "MAC" => "02:00:00:00:00:09",
        "PATH" | "FILE" => "/tmp/minitcp-flag-table",
        "HOST:PORT" => "127.0.0.1:7946",
        "ADDR" => "127.0.0.1:7946",
        "arp|icmp|ip" => "icmp",
        "N" => "1",
        other => panic!("no sample value for metavar {other}"),
    }
}

//! Black-box tests for the `minitcp` command line.
//!
//! The unit tests inside `src/` check individual functions. These run the real
//! compiled binary the way a user would, and pin down the three things a user
//! actually experiences:
//!
//!   * **exit status** — 0 success, 1 runtime failure, 2 command-line misuse
//!   * **which stream** the output lands on — stdout is data you can pipe,
//!     stderr is commentary for a human
//!   * **the wording of errors** — so a refactor cannot quietly turn a helpful
//!     message into a cryptic one
//!
//! Everything here is a *characterisation* test: it records what the tool does
//! today. When we deliberately change behaviour we change the assertion in the
//! same commit, which makes the change visible in review instead of invisible.
//!
//! Two rules keep these tests honest:
//!
//!   * every test runs in its own temporary directory, so a stray
//!     `minitcp.toml` in the repository can never leak into a result;
//!   * anything that would otherwise talk to GitHub passes `--offline`, so the
//!     suite never touches the network.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cargo builds the binary before running integration tests and hands us the
/// path in this environment variable, so we always test the current code.
const BIN: &str = env!("CARGO_BIN_EXE_minitcp");

// ---------------------------------------------------------------------------
// Sample frames
// ---------------------------------------------------------------------------

/// A broadcast ARP request: "who has 10.0.0.2? tell 10.0.0.1".
///
/// 10.0.0.2 is MiniTCP's default address, so the stack should answer this.
/// Laid out the way it sits on the wire:
///
/// ```text
/// ff:ff:ff:ff:ff:ff        destination — broadcast, nobody knows the MAC yet
/// 02:00:00:00:00:01        source — Linux's MAC
/// 0x0806                   ethertype — ARP
/// 0x0001 0x0800            hardware Ethernet, protocol IPv4
/// 6 4                      MAC length 6, IPv4 length 4
/// 0x0001                   opcode — request
/// 02:00:00:00:00:01        sender MAC
/// 10.0.0.1                 sender IPv4
/// 00:00:00:00:00:00        target MAC — unknown, that is the question
/// 10.0.0.2                 target IPv4
/// ```
const ARP_REQUEST: [u8; 42] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
];

/// Render bytes as one line of hex, the format `minitcp stack --hex` reads.
fn hex_line(frame: &[u8]) -> String {
    let mut line: String = frame.iter().map(|b| format!("{b:02x}")).collect();
    line.push('\n');
    line
}

// ---------------------------------------------------------------------------
// Running the binary
// ---------------------------------------------------------------------------

/// What a finished `minitcp` process left behind.
struct Run {
    /// Exit status. A process killed by a signal is recorded as -1.
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    /// Both streams together, for assertions that care about the message but
    /// not (yet) about which stream carried it.
    fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    /// Panic with the full captured output. Assertion failures in a subprocess
    /// test are useless without seeing what the subprocess actually said.
    fn dump(&self, what: &str) -> String {
        format!(
            "{what}\n--- exit {} ---\n--- stdout ---\n{}--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// Run `minitcp` in `dir` with `stdin` piped in, and collect everything.
fn run_in_with_stdin(dir: &Path, args: &[&str], stdin: &str) -> Run {
    let mut child = Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {BIN}: {e}"));
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(stdin.as_bytes())
        .expect("child accepted stdin");
    let output = child.wait_with_output().expect("child finished");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Run `minitcp` in `dir` with empty stdin.
///
/// stdin is still a pipe rather than inherited: a test must never be able to
/// block waiting for a terminal that is not there.
fn run_in(dir: &Path, args: &[&str]) -> Run {
    run_in_with_stdin(dir, args, "")
}

/// Run `minitcp` in a throwaway directory, so no `minitcp.toml` is in scope.
fn run(args: &[&str]) -> Run {
    let dir = TempDir::new("run");
    run_in(dir.path(), args)
}

// ---------------------------------------------------------------------------
// Temporary directories
// ---------------------------------------------------------------------------

/// A scratch directory that deletes itself. Tests run in parallel threads, so
/// the name mixes pid, clock and a counter to stay unique.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after 1970")
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "minitcp-cli-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("can create a temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Write a text file into the directory and return its path.
    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, body).expect("can write into the temp dir");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Writing a pcap by hand
// ---------------------------------------------------------------------------

/// Write a classic little-endian libpcap file containing `frames`.
///
/// We build it by hand rather than calling into the crate so that these tests
/// stay a genuinely independent check on the pcap code: if the reader and the
/// writer ever drift together in the same wrong direction, this still catches
/// it. The layout is a 24-byte file header followed by one 16-byte record
/// header per frame.
fn write_pcap(path: &Path, frames: &[&[u8]]) {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic: classic, little-endian
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0u32.to_le_bytes()); // timezone offset (always 0)
    out.extend_from_slice(&0u32.to_le_bytes()); // timestamp accuracy (always 0)
    out.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen: longest frame stored
    out.extend_from_slice(&1u32.to_le_bytes()); // link type 1 = Ethernet
    for (i, frame) in frames.iter().enumerate() {
        let len = frame.len() as u32;
        out.extend_from_slice(&(1_700_000_000 + i as u32).to_le_bytes()); // seconds
        out.extend_from_slice(&0u32.to_le_bytes()); // microseconds
        out.extend_from_slice(&len.to_le_bytes()); // bytes stored
        out.extend_from_slice(&len.to_le_bytes()); // bytes on the wire
        out.extend_from_slice(frame);
    }
    std::fs::write(path, out).expect("can write a pcap");
}

// ===========================================================================
// Exit status and stream routing
// ===========================================================================

#[test]
fn version_goes_to_stdout_and_succeeds() {
    let out = run(&["--version"]);
    assert_eq!(out.code, 0, "{}", out.dump("--version should succeed"));
    assert!(
        out.stdout.starts_with("minitcp "),
        "{}",
        out.dump("version belongs on stdout so it can be piped")
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        out.dump("stderr should be quiet")
    );
}

#[test]
fn short_version_flag_matches_long_one() {
    assert_eq!(run(&["-V"]).stdout, run(&["--version"]).stdout);
}

#[test]
fn help_succeeds_and_lists_every_command() {
    let out = run(&["--help"]);
    assert_eq!(out.code, 0, "{}", out.dump("--help should succeed"));
    let text = out.all();
    for expected in [
        "minitcp [run]",
        "minitcp stack",
        "minitcp replay FILE",
        "minitcp tap",
        "minitcp identity",
        "minitcp pcap FILE",
        "--quiet",
        "--drop",
        "--fwd",
        "Exit status: 0 success",
        "minitcp.toml",
    ] {
        assert!(
            text.contains(expected),
            "{}",
            out.dump(&format!("help should mention {expected:?}"))
        );
    }
}

#[test]
fn help_word_and_flag_agree() {
    assert_eq!(run(&["help"]).all(), run(&["--help"]).all());
    assert_eq!(run(&["-h"]).all(), run(&["--help"]).all());
}

/// Help was asked for, so it is the result: stdout, exit 0, pipeable.
#[test]
fn help_goes_to_stdout() {
    let out = run(&["--help"]);
    assert_eq!(out.code, 0, "{}", out.dump("--help should succeed"));
    assert!(
        !out.stdout.is_empty() && out.stderr.is_empty(),
        "{}",
        out.dump("help belongs on stdout")
    );
}

#[test]
fn topic_help_is_scoped_to_the_family() {
    let tap = run(&["tap", "--help"]);
    assert_eq!(tap.code, 0, "{}", tap.dump("tap --help should succeed"));
    assert!(
        tap.all().contains("usage: minitcp tap"),
        "{}",
        tap.dump("tap help")
    );
    assert!(
        !tap.all().contains("minitcp identity"),
        "{}",
        tap.dump("tap help should not dump the whole manual")
    );

    let identity = run(&["identity", "--help"]);
    assert!(
        identity.all().contains("usage: minitcp identity"),
        "{}",
        identity.dump("identity help")
    );

    let pcap = run(&["pcap", "--help"]);
    assert!(
        pcap.all().contains("usage: minitcp pcap"),
        "{}",
        pcap.dump("pcap help")
    );
}

// ===========================================================================
// Usage errors — all exit 2
// ===========================================================================

#[test]
fn unknown_command_exits_two_and_names_it() {
    let out = run(&["nope"]);
    assert_eq!(out.code, 2, "{}", out.dump("usage errors exit 2"));
    assert!(
        out.stderr.contains("unknown command 'nope'"),
        "{}",
        out.dump("the message should quote what was typed")
    );
    assert!(
        out.stderr.contains("minitcp stack"),
        "{}",
        out.dump("and should list the commands that do exist")
    );
}

#[test]
fn unknown_flag_exits_two_and_names_it() {
    let out = run(&["--nope"]);
    assert_eq!(out.code, 2, "{}", out.dump("usage errors exit 2"));
    assert!(
        out.stderr.contains("unknown flag '--nope'"),
        "{}",
        out.dump("the message should quote what was typed")
    );
}

#[test]
fn two_commands_are_rejected() {
    let out = run(&["stack", "bridge"]);
    assert_eq!(out.code, 2, "{}", out.dump("usage errors exit 2"));
    assert!(
        out.stderr.contains("only one command is allowed"),
        "{}",
        out.dump("two commands")
    );
}

#[test]
fn a_flag_missing_its_value_names_the_flag() {
    for flag in ["--iface", "--addr", "--mac", "--tun", "--config", "--fwd"] {
        let out = run(&[flag]);
        assert_eq!(
            out.code,
            2,
            "{}",
            out.dump(&format!("{flag} with no value"))
        );
        assert!(
            out.stderr.contains(&format!("{flag} needs a value")),
            "{}",
            out.dump(&format!("{flag} should say it needs a value"))
        );
    }
}

#[test]
fn replay_without_a_file_is_a_usage_error() {
    let out = run(&["replay"]);
    assert_eq!(out.code, 2, "{}", out.dump("replay with no path"));
    assert!(
        out.stderr.contains("replay needs a pcap path"),
        "{}",
        out.dump("replay with no path")
    );
}

#[test]
fn pcap_without_a_file_prints_its_usage() {
    let out = run(&["pcap"]);
    assert_eq!(out.code, 2, "{}", out.dump("pcap with no path"));
    assert!(
        out.stderr.contains("usage: minitcp pcap FILE"),
        "{}",
        out.dump("pcap with no path")
    );
}

// ---------------------------------------------------------------------------
// Value validation. These bounds are currently checked in one place; the tests
// exist so that moving the checks into a shared table cannot loosen them.
// ---------------------------------------------------------------------------

#[test]
fn out_of_range_numbers_are_rejected_with_their_bounds() {
    // (flag, value, expected wording)
    for (flag, value, expected) in [
        ("--ttl", "256", "ttl must be 0-255"),
        ("--drop-pct", "101", "drop-pct must be 0-100"),
        ("--id", "65536", "id must be 0-65535"),
    ] {
        let out = run(&[flag, value]);
        assert_eq!(out.code, 2, "{}", out.dump(&format!("{flag} {value}")));
        assert!(
            out.stderr.contains(expected),
            "{}",
            out.dump(&format!("{flag} {value} should say {expected:?}"))
        );
    }
}

#[test]
fn boundary_values_are_accepted() {
    // The largest legal value of each flag must still parse. `identity` is a
    // command that only reads config, so it exercises parsing and nothing else.
    for (flag, value) in [("--ttl", "255"), ("--drop-pct", "100"), ("--id", "65535")] {
        let out = run(&["identity", flag, value]);
        assert_eq!(
            out.code,
            0,
            "{}",
            out.dump(&format!("{flag} {value} is legal"))
        );
    }
}

#[test]
fn malformed_values_are_rejected() {
    for (args, expected) in [
        (["--mac", "not-a-mac"], "invalid MAC"),
        (["--mac", "02:00:00:00:00"], "invalid MAC"),
        (["--addr", "999.1.1.1"], "invalid IPv4 address"),
        (["--linux-addr", "10.0.0"], "invalid IPv4 address"),
        (["--count", "many"], "invalid number"),
        (["--drop", "http"], "unknown drop kind 'http'"),
    ] {
        let out = run(&args);
        assert_eq!(out.code, 2, "{}", out.dump(&format!("{args:?}")));
        assert!(
            out.stderr.contains(expected),
            "{}",
            out.dump(&format!("{args:?} should say {expected:?}"))
        );
    }
}

#[test]
fn flags_accept_both_spaced_and_equals_forms() {
    let dir = TempDir::new("eq");
    let spaced = run_in(dir.path(), &["tap", "--iface", "tap9"]);
    let equals = run_in(dir.path(), &["tap", "--iface=tap9"]);
    assert_eq!(
        spaced.all(),
        equals.all(),
        "{}",
        spaced.dump("--iface X vs --iface=X")
    );
    assert!(
        spaced.all().contains("tap9"),
        "{}",
        spaced.dump("--iface should take effect")
    );
}

// ===========================================================================
// Configuration: defaults < minitcp.toml < command line
// ===========================================================================

#[test]
fn defaults_apply_when_there_is_no_config_file() {
    let out = run(&["tap"]);
    assert_eq!(out.code, 0, "{}", out.dump("tap show"));
    let text = out.all();
    assert!(text.contains("tap0"), "{}", out.dump("default iface"));
    assert!(text.contains("/dev/net/tun"), "{}", out.dump("default tun"));
}

#[test]
fn a_toml_in_the_working_directory_is_picked_up() {
    let dir = TempDir::new("toml");
    dir.write("minitcp.toml", "iface = \"tapx\"\naddr = \"10.9.9.2\"\n");

    let tap = run_in(dir.path(), &["tap"]);
    assert!(
        tap.all().contains("tapx"),
        "{}",
        tap.dump("iface from minitcp.toml")
    );

    let identity = run_in(dir.path(), &["identity"]);
    assert!(
        identity.all().contains("10.9.9.2"),
        "{}",
        identity.dump("addr from minitcp.toml")
    );
}

#[test]
fn the_command_line_beats_the_config_file() {
    let dir = TempDir::new("override");
    dir.write("minitcp.toml", "iface = \"fromfile\"\n");
    let out = run_in(dir.path(), &["tap", "--iface", "fromflag"]);
    assert!(
        out.all().contains("fromflag"),
        "{}",
        out.dump("flag should win")
    );
    assert!(
        !out.all().contains("fromfile"),
        "{}",
        out.dump("file should lose")
    );
}

#[test]
fn config_flag_selects_a_different_file() {
    let dir = TempDir::new("configflag");
    dir.write("minitcp.toml", "iface = \"ignored\"\n");
    let other = dir.write("other.toml", "iface = \"chosen\"\n");
    let out = run_in(dir.path(), &["tap", "--config", other.to_str().unwrap()]);
    assert!(
        out.all().contains("chosen"),
        "{}",
        out.dump("--config should be used")
    );
    assert!(
        !out.all().contains("ignored"),
        "{}",
        out.dump("./minitcp.toml should be skipped")
    );
}

#[test]
fn a_missing_config_file_is_reported_not_ignored() {
    let out = run(&["tap", "--config", "/no/such/file.toml"]);
    assert_eq!(out.code, 2, "{}", out.dump("missing --config"));
    assert!(
        out.stderr.contains("config file not found"),
        "{}",
        out.dump("missing --config should say so rather than falling back")
    );
}

#[test]
fn malformed_toml_is_reported() {
    let dir = TempDir::new("badtoml");
    dir.write("minitcp.toml", "iface = \n");
    let out = run_in(dir.path(), &["tap"]);
    assert_ne!(
        out.code,
        0,
        "{}",
        out.dump("broken toml should not be silently ignored")
    );
}

#[test]
fn linux_addr_defaults_to_dot_one_on_the_same_subnet() {
    // MiniTCP at 10.9.9.2 implies Linux is the .1 on that street, unless told
    // otherwise. This rule lives in one place and is easy to lose in a refactor.
    let out = run(&["tap", "--addr", "10.9.9.2"]);
    assert!(
        out.all().contains("10.9.9.1"),
        "{}",
        out.dump("linux-addr should default to .1")
    );

    let explicit = run(&["tap", "--addr", "10.9.9.2", "--linux-addr", "10.9.9.7"]);
    assert!(
        explicit.all().contains("10.9.9.7"),
        "{}",
        explicit.dump("an explicit --linux-addr should stick")
    );
}

// ===========================================================================
// Read-only commands
// ===========================================================================

#[test]
fn tap_show_reports_iface_addr_and_tun() {
    let out = run(&["tap"]);
    assert_eq!(out.code, 0, "{}", out.dump("tap show"));
    for field in ["iface", "addr", "tun"] {
        assert!(
            out.all().contains(field),
            "{}",
            out.dump(&format!("tap show should list {field}"))
        );
    }
}

/// `tap` with no subcommand answers what the settings are. It is not an error
/// and not a help request, so it says that and stops.
#[test]
fn a_flag_the_command_cannot_use_warns_but_still_runs() {
    let out = run(&["identity", "--ttl", "3", "--drop", "icmp", "--offline"]);
    assert_eq!(out.code, 0, "{}", out.dump("identity with stray flags"));
    assert!(
        out.stdout.contains("addr"),
        "{}",
        out.dump("identity still reports")
    );
    assert!(
        out.stderr
            .contains("--ttl and --drop have no effect on `identity`"),
        "{}",
        out.dump("stray flags are named on stderr")
    );
}

#[test]
fn tap_show_reports_settings_on_stdout_without_a_help_page() {
    let out = run(&["tap"]);
    assert_eq!(out.code, 0, "{}", out.dump("tap show"));
    assert!(
        out.stderr.is_empty(),
        "{}",
        out.dump("tap show belongs on stdout")
    );
    assert!(
        !out.stdout.contains("usage: minitcp tap"),
        "{}",
        out.dump("tap show should not append a usage block")
    );
}

#[test]
fn identity_show_reports_addr_and_mac_on_stdout() {
    let out = run(&["identity"]);
    assert_eq!(out.code, 0, "{}", out.dump("identity show"));
    assert!(
        out.stdout.contains("10.0.0.2"),
        "{}",
        out.dump("default addr")
    );
    assert!(
        out.stdout.contains("02:00:00:00:00:02"),
        "{}",
        out.dump("default mac")
    );
}

#[test]
fn identity_setters_write_the_config_file() {
    let dir = TempDir::new("setters");
    let out = run_in(dir.path(), &["identity", "addr", "10.4.4.2"]);
    assert_eq!(out.code, 0, "{}", out.dump("identity addr"));

    let written = std::fs::read_to_string(dir.path().join("minitcp.toml"))
        .expect("the setter should create minitcp.toml");
    assert!(written.contains("10.4.4.2"), "wrote: {written}");

    // And the value must be read back on the next run.
    let back = run_in(dir.path(), &["identity"]);
    assert!(
        back.stdout.contains("10.4.4.2"),
        "{}",
        back.dump("round trip through the file")
    );
}

#[test]
fn tap_setters_write_the_config_file() {
    let dir = TempDir::new("tapsetters");
    assert_eq!(run_in(dir.path(), &["tap", "iface", "tap7"]).code, 0);
    assert_eq!(run_in(dir.path(), &["tap", "addr", "10.5.5.1"]).code, 0);

    let back = run_in(dir.path(), &["tap"]);
    assert!(
        back.all().contains("tap7"),
        "{}",
        back.dump("iface round trip")
    );
    assert!(
        back.all().contains("10.5.5.1"),
        "{}",
        back.dump("addr round trip")
    );
}

// ===========================================================================
// pcap inspection
// ===========================================================================

#[test]
fn pcap_lists_frames_and_their_ethertype() {
    let dir = TempDir::new("pcapinfo");
    let path = dir.path().join("two.pcap");
    write_pcap(&path, &[&ARP_REQUEST, &ARP_REQUEST]);

    let out = run_in(dir.path(), &["pcap", path.to_str().unwrap()]);
    assert_eq!(out.code, 0, "{}", out.dump("pcap info"));
    assert!(
        out.stdout.contains("0x0806"),
        "{}",
        out.dump("ARP ethertype")
    );
    assert!(
        out.stdout.contains("2 frames"),
        "{}",
        out.dump("frame count")
    );
}

#[test]
fn pcap_on_a_missing_file_is_a_runtime_error_not_a_usage_error() {
    let out = run(&["pcap", "/no/such/file.pcap"]);
    assert_eq!(
        out.code,
        1,
        "{}",
        out.dump("a file that is absent at run time is exit 1, not exit 2")
    );
    assert!(
        out.stderr.contains("cannot open pcap"),
        "{}",
        out.dump("missing pcap")
    );
}

#[test]
fn pcap_rejects_a_file_that_is_not_a_pcap() {
    let dir = TempDir::new("notpcap");
    let path = dir.write("hello.txt", "this is not a pcap\n");
    let out = run_in(dir.path(), &["pcap", path.to_str().unwrap()]);
    assert_eq!(out.code, 1, "{}", out.dump("not a pcap"));
    assert!(
        out.stderr.contains("magic"),
        "{}",
        out.dump("the error should explain the file is not a pcap")
    );
}

// ===========================================================================
// The stack itself, end to end
//
// `--hex` reads frames from stdin and `replay` reads them from a pcap. Neither
// needs a TAP device, Docker or root, so both run anywhere — which makes them
// the safety net for refactors of the frame-handling code.
// ===========================================================================

#[test]
fn hex_stack_answers_an_arp_request() {
    let out = run_in_with_stdin(
        TempDir::new("hex").path(),
        &["stack", "--hex", "--offline", "--quiet"],
        &hex_line(&ARP_REQUEST),
    );
    assert_eq!(
        out.code,
        0,
        "{}",
        out.dump("hex stack should end cleanly at EOF")
    );
    assert!(
        out.stdout.contains("arp") && out.stdout.contains("10.0.0.1 -> 10.0.0.2"),
        "{}",
        out.dump("the quiet line should name the protocol and both addresses")
    );
    assert!(
        out.stdout.contains("who-has"),
        "{}",
        out.dump("and should say what the ARP was asking")
    );
}

#[test]
fn verbose_output_shows_the_layer_tree_and_the_reply() {
    let out = run_in_with_stdin(
        TempDir::new("verbose").path(),
        &["stack", "--hex", "--offline"],
        &hex_line(&ARP_REQUEST),
    );
    assert_eq!(out.code, 0, "{}", out.dump("verbose hex stack"));
    let text = out.stdout.clone();
    // Frame in, decoded down the layers, reply out.
    assert!(
        text.contains("[IN]"),
        "{}",
        out.dump("should mark the inbound frame")
    );
    assert!(
        text.contains("ethernet"),
        "{}",
        out.dump("should name the L2 header")
    );
    assert!(
        text.contains("L2"),
        "{}",
        out.dump("should label the OSI layer")
    );
    assert!(
        text.contains("who-has"),
        "{}",
        out.dump("should decode the request")
    );
    assert!(
        text.contains("[OUT]"),
        "{}",
        out.dump("should mark the reply")
    );
    assert!(
        text.contains("is-at 02:00:00:00:00:02"),
        "{}",
        out.dump("and the reply should carry MiniTCP's MAC")
    );
}

#[test]
fn replay_answers_an_arp_request_from_a_pcap() {
    let dir = TempDir::new("replay");
    let path = dir.path().join("in.pcap");
    write_pcap(&path, &[&ARP_REQUEST]);

    let out = run_in(
        dir.path(),
        &["replay", path.to_str().unwrap(), "--offline", "--quiet"],
    );
    assert_eq!(
        out.code,
        0,
        "{}",
        out.dump("replay ends cleanly at end of file")
    );
    assert!(
        out.stdout.contains("who-has"),
        "{}",
        out.dump("replayed ARP")
    );
}

#[test]
fn drop_arp_silences_the_reply() {
    let out = run_in_with_stdin(
        TempDir::new("droparp").path(),
        &["stack", "--hex", "--offline", "--quiet", "--drop", "arp"],
        &hex_line(&ARP_REQUEST),
    );
    assert_eq!(out.code, 0, "{}", out.dump("--drop arp"));
    assert!(
        out.stdout.contains("[DROP]"),
        "{}",
        out.dump("a dropped frame should still be reported, not hidden")
    );
    assert!(
        !out.stdout.contains("who-has"),
        "{}",
        out.dump("but it should not be decoded or answered")
    );
}

#[test]
fn count_stops_after_the_given_number_of_frames() {
    let mut stdin = String::new();
    for _ in 0..5 {
        stdin.push_str(&hex_line(&ARP_REQUEST));
    }
    let out = run_in_with_stdin(
        TempDir::new("count").path(),
        &["stack", "--hex", "--offline", "--quiet", "--count", "2"],
        &stdin,
    );
    assert_eq!(out.code, 0, "{}", out.dump("--count 2"));
    assert_eq!(
        out.stdout.lines().filter(|l| l.contains("arp")).count(),
        2,
        "{}",
        out.dump("--count 2 should handle exactly two frames")
    );
}

#[test]
fn write_captures_both_directions_into_a_readable_pcap() {
    let dir = TempDir::new("write");
    let capture = dir.path().join("out.pcap");

    let stack = run_in_with_stdin(
        dir.path(),
        &[
            "stack",
            "--hex",
            "--offline",
            "--quiet",
            "--write",
            capture.to_str().unwrap(),
        ],
        &hex_line(&ARP_REQUEST),
    );
    assert_eq!(stack.code, 0, "{}", stack.dump("--write"));

    // One frame in, one reply out: the capture should hold both, and minitcp
    // must be able to read back what it just wrote.
    let info = run_in(dir.path(), &["pcap", capture.to_str().unwrap()]);
    assert_eq!(
        info.code,
        0,
        "{}",
        info.dump("reading back our own capture")
    );
    assert!(
        info.stdout.contains("2 frames"),
        "{}",
        info.dump("the capture should hold the request and the reply")
    );
}

#[test]
fn a_malformed_hex_line_is_a_runtime_error() {
    let out = run_in_with_stdin(
        TempDir::new("badhex").path(),
        &["stack", "--hex", "--offline", "--quiet"],
        "not hex at all\n",
    );
    assert_eq!(out.code, 1, "{}", out.dump("bad hex is a runtime failure"));
    assert!(
        out.stderr.contains("minitcp: error:"),
        "{}",
        out.dump("runtime failures are announced on stderr with the tool's prefix")
    );
}

#[test]
fn a_short_frame_is_dropped_rather_than_crashing() {
    let out = run_in_with_stdin(
        TempDir::new("short").path(),
        &["stack", "--hex", "--offline", "--quiet"],
        "0011\n",
    );
    assert_eq!(
        out.code,
        0,
        "{}",
        out.dump("a runt frame should not be fatal")
    );
    assert!(
        out.stdout.contains("[DROP]"),
        "{}",
        out.dump("and should be reported as a drop")
    );
}

#[test]
fn empty_input_is_not_an_error_for_hex_or_replay() {
    let hex = run_in_with_stdin(
        TempDir::new("emptyhex").path(),
        &["stack", "--hex", "--offline", "--quiet"],
        "",
    );
    assert_eq!(hex.code, 0, "{}", hex.dump("no frames on stdin is fine"));

    let dir = TempDir::new("emptypcap");
    let path = dir.path().join("empty.pcap");
    write_pcap(&path, &[]);
    let replay = run_in(dir.path(), &["replay", path.to_str().unwrap(), "--offline"]);
    assert_eq!(replay.code, 0, "{}", replay.dump("an empty pcap is fine"));
}

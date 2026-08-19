//! Running other programs.
//!
//! minitcp shells out to `ip`, `sudo`, `docker` and `tcpdump`. Every such call
//! goes through here, so the awkward parts are solved once: no child hangs
//! forever, steals the terminal, floods us, or speaks an unexpected language.

use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;

/// A failure worth treating as success, because the thing we asked for was
/// already true. `ip` has no "create if missing" flag, so `minitcp tap up`
/// asks unconditionally and forgives the "already done" complaint.
#[derive(Clone, Copy)]
pub enum AllowedFailure {
    None,
    AlreadyExists,
    DoesNotExist,
}

pub fn run_checked(program: &str, args: &[&str], allowed: AllowedFailure) -> io::Result<()> {
    check_output(
        program,
        args,
        output_timeout(program, args, DEFAULT_COMMAND_TIMEOUT)?,
        allowed,
    )
}

/// Run `sudo` without ever letting it prompt.
///
/// Every child gets a closed stdin, so a prompt could not be answered anyway.
/// `-n` turns that into a refusal we can recognise and explain, instead of
/// sudo's raw "no tty present", which reads like a bug in minitcp.
pub fn run_sudo(args: &[&str], allowed: AllowedFailure) -> io::Result<()> {
    let full: Vec<&str> = std::iter::once("-n").chain(args.iter().copied()).collect();
    run_checked("sudo", &full, allowed).map_err(|error| explain_sudo_failure(args, error))
}

/// Turn sudo's refusals into something a user can act on.
fn explain_sudo_failure(args: &[&str], error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::NotFound {
        return io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "`{}` needs root, but sudo is not installed. Run minitcp as root, \
                 or use the TAP sidecar (`minitcp tap up`).",
                args.join(" ")
            ),
        );
    }
    let detail = error.to_string().to_ascii_lowercase();
    // sudo's own words. Matching English is safe because `output_timeout`
    // pins every child to the C locale.
    let needs_password = detail.contains("password is required")
        || detail.contains("no tty present")
        || detail.contains("askpass");
    if needs_password {
        return io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "`{}` needs root and sudo asked for a password, which minitcp cannot type. \
                 Run `sudo -v` in this terminal first, then try again.",
                args.join(" ")
            ),
        );
    }
    if detail.contains("not in the sudoers file") || detail.contains("not allowed to execute") {
        return io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "`{}` needs root, but this account is not allowed to use sudo. \
                 Run minitcp as root, or use the TAP sidecar (`minitcp tap up`).",
                args.join(" ")
            ),
        );
    }
    error
}

pub fn check_output(
    program: &str,
    args: &[&str],
    output: Output,
    allowed: AllowedFailure,
) -> io::Result<()> {
    if output.status.success() {
        return Ok(());
    }

    let detail = output_detail(&output);
    let accepted = match allowed {
        AllowedFailure::None => false,
        AllowedFailure::AlreadyExists => is_already_exists(&detail),
        AllowedFailure::DoesNotExist => is_does_not_exist(&detail),
    };
    if accepted {
        return Ok(());
    }

    let status = output.status.code().map_or_else(
        || "by signal".to_string(),
        |code| format!("with exit {code}"),
    );
    let command = display_command(program, args);
    let suffix = if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    };
    Err(io::Error::other(format!(
        "`{command}` failed {status}{suffix}"
    )))
}

/// Run a program to completion, with a hard time limit.
///
///   * **C locale** — we read `ip` and `sudo` error prose, which is translated.
///   * **closed stdin** — a child that prompts gets EOF, not the TUI's terminal.
///   * **own process group** — `sudo` and `docker` spawn helpers to kill too.
///   * **timeout** — `docker` blocks forever on an unreachable daemon.
pub fn output_timeout(program: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let Some(mut stdout) = child.stdout.take() else {
        kill_child_group(&mut child);
        return Err(io::Error::other("could not capture child stdout"));
    };
    let Some(mut stderr) = child.stderr.take() else {
        kill_child_group(&mut child);
        return Err(io::Error::other("could not capture child stderr"));
    };
    let stdout_reader = match thread::Builder::new()
        .name("minitcp-command-stdout".into())
        .spawn(move || read_limited(&mut stdout))
    {
        Ok(reader) => reader,
        Err(error) => {
            kill_child_group(&mut child);
            return Err(io::Error::new(
                error.kind(),
                format!("cannot read child stdout: {error}"),
            ));
        }
    };
    let stderr_reader = match thread::Builder::new()
        .name("minitcp-command-stderr".into())
        .spawn(move || read_limited(&mut stderr))
    {
        Ok(reader) => reader,
        Err(error) => {
            kill_child_group(&mut child);
            let _ = join_reader(stdout_reader, "stdout");
            return Err(io::Error::new(
                error.kind(),
                format!("cannot read child stderr: {error}"),
            ));
        }
    };
    let started = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Output {
                    status,
                    stdout: join_reader(stdout_reader, "stdout")?,
                    stderr: join_reader(stderr_reader, "stderr")?,
                });
            }
            Ok(None) => {}
            Err(error) => {
                kill_child_group(&mut child);
                let _ = join_reader(stdout_reader, "stdout");
                let _ = join_reader(stderr_reader, "stderr");
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "cannot wait for `{}`: {error}",
                        display_command(program, args)
                    ),
                ));
            }
        }
        if started.elapsed() >= timeout {
            kill_child_group(&mut child);
            let _ = join_reader(stdout_reader, "stdout");
            let _ = join_reader(stderr_reader, "stderr");
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "`{}` did not finish within {}s",
                    display_command(program, args),
                    timeout.as_secs()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn kill_child_group(child: &mut std::process::Child) {
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn read_limited(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    const TRUNCATED: &[u8] = b"\n[output truncated by minitcp]\n";

    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let available = MAX_COMMAND_OUTPUT.saturating_sub(output.len());
        let keep = read.min(available);
        output.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    if truncated {
        let keep = MAX_COMMAND_OUTPUT.saturating_sub(TRUNCATED.len());
        output.truncate(keep);
        output.extend_from_slice(TRUNCATED);
    }
    Ok(output)
}

fn join_reader(
    reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    stream: &str,
) -> io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| io::Error::other(format!("{stream} reader thread panicked")))?
}

pub fn output_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn display_command(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

// `ip` reports "already exists" and "not there" only in prose, so we read the
// prose — safe because every child is pinned to the C locale. Phrasings:
//   ip addr add    -> "RTNETLINK answers: File exists"
//   ip link add    -> "RTNETLINK answers: File exists"
//   ip link delete -> "Cannot find device \"tap0\""
//   docker rm      -> "No such container: minitcp-tap"

/// Did this failure mean "that already exists", rather than a real problem?
///
/// `ip tuntap add` is the odd one out: a name that is taken comes back as
/// `ioctl(TUNSETIFF): Device or resource busy`, not EEXIST. The busy check is
/// tied to TUNSETIFF because a bare "resource busy" elsewhere is real.
fn is_already_exists(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("file exists")
        || lower.contains("already exists")
        || (lower.contains("tunsetiff") && lower.contains("busy"))
}

fn is_does_not_exist(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("cannot find device")
        || lower.contains("does not exist")
        || lower.contains("no such device")
        || lower.contains("no such object")
        || lower.contains("no such container")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn failed(stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(2 << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn already_exists_can_be_idempotent() {
        check_output(
            "ip",
            &["addr", "add"],
            failed("RTNETLINK answers: File exists"),
            AllowedFailure::AlreadyExists,
        )
        .unwrap();
    }

    #[test]
    fn unexpected_failure_includes_command_and_stderr() {
        let error = check_output(
            "ip",
            &["link", "set"],
            failed("Operation not permitted"),
            AllowedFailure::None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("ip link set"), "{error}");
        assert!(error.contains("Operation not permitted"), "{error}");
    }

    #[test]
    fn command_timeout_is_reported_cleanly() {
        let error =
            output_timeout("sh", &["-c", "sleep 1"], Duration::from_millis(30)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("did not finish"), "{error}");
    }

    #[test]
    fn children_run_in_the_c_locale_so_parsed_messages_are_stable() {
        // Harmless-failure detection reads `ip`'s prose, so it must not be
        // translated.
        let output = output_timeout(
            "sh",
            &["-c", "printf '%s' \"$LC_ALL\""],
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout), "C");
    }

    #[test]
    fn a_sudo_password_prompt_becomes_an_actionable_message() {
        let raw = io::Error::other(
            "`sudo -n ip link set` failed with exit 1: sudo: a password is required",
        );
        let explained = explain_sudo_failure(&["ip", "link", "set"], raw);
        assert_eq!(explained.kind(), io::ErrorKind::PermissionDenied);
        assert!(explained.to_string().contains("sudo -v"), "{explained}");
    }

    #[test]
    fn a_missing_sudo_says_what_to_do_instead() {
        let raw = io::Error::new(io::ErrorKind::NotFound, "No such file or directory");
        let explained = explain_sudo_failure(&["ip", "link", "set"], raw);
        assert!(explained.to_string().contains("sidecar"), "{explained}");
    }

    #[test]
    fn an_ordinary_sudo_failure_is_passed_through_unchanged() {
        let raw =
            io::Error::other("`sudo -n ip link set` failed with exit 1: Operation not permitted");
        let explained = explain_sudo_failure(&["ip", "link", "set"], raw);
        assert!(
            explained.to_string().contains("Operation not permitted"),
            "{explained}"
        );
    }

    #[test]
    fn a_tap_that_already_exists_is_not_an_error() {
        // The tun driver's EBUSY, not an EEXIST — which is why the obvious
        // "File exists" check missed it.
        check_output(
            "ip",
            &[
                "tuntap", "add", "dev", "tap0", "mode", "tap", "user", "1001",
            ],
            failed("ioctl(TUNSETIFF): Device or resource busy"),
            AllowedFailure::AlreadyExists,
        )
        .unwrap();
    }

    #[test]
    fn an_address_the_interface_already_has_is_not_an_error() {
        check_output(
            "ip",
            &["addr", "add", "10.0.0.1/24", "dev", "tap0"],
            failed("RTNETLINK answers: File exists"),
            AllowedFailure::AlreadyExists,
        )
        .unwrap();
    }

    #[test]
    fn a_busy_resource_elsewhere_is_still_a_real_failure() {
        // Only TUNSETIFF's EBUSY means "the name is taken".
        check_output(
            "ip",
            &["link", "delete", "tap0"],
            failed("RTNETLINK answers: Device or resource busy"),
            AllowedFailure::AlreadyExists,
        )
        .unwrap_err();
    }

    #[test]
    fn a_missing_docker_container_counts_as_already_gone() {
        check_output(
            "docker",
            &["rm", "-f", "minitcp-tap"],
            failed("Error response from daemon: No such container: minitcp-tap"),
            AllowedFailure::DoesNotExist,
        )
        .unwrap();
    }

    #[test]
    fn child_output_is_capped_with_a_visible_marker() {
        let mut input = io::Cursor::new(vec![b'x'; MAX_COMMAND_OUTPUT + 100]);
        let output = read_limited(&mut input).unwrap();
        assert_eq!(output.len(), MAX_COMMAND_OUTPUT);
        assert!(
            output.ends_with(b"[output truncated by minitcp]\n"),
            "{}",
            String::from_utf8_lossy(&output[output.len() - 64..])
        );
    }
}

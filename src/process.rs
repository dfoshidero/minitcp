use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_COMMAND_OUTPUT: usize = 1024 * 1024;

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

pub fn output_timeout(program: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let mut command = Command::new(program);
    command
        .args(args)
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

fn is_already_exists(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("file exists") || lower.contains("already exists")
}

fn is_does_not_exist(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("cannot find device")
        || lower.contains("does not exist")
        || lower.contains("no such device")
        || lower.contains("no such object")
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

//! The processes the lab runs on your behalf.
//!
//! The lab does not implement the stack or the capture; it starts `minitcp
//! stack` and `tcpdump` as children and shows what they print. That is
//! deliberate — every pane is something you could have typed yourself, and the
//! pane title tells you the command.
//!
//! Stopping them is the subtle part: a capture inside the sidecar has a PID in
//! the container's namespace, meaningless here, so the signal goes back through
//! `docker exec`.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::Config;
use crate::sys::docker::CONTAINER;

pub(super) static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

pub(super) fn install_signal_handlers() -> std::io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = request_shutdown as *const () as usize;
    action.sa_flags = 0;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

pub(super) fn configure_child_process() -> std::io::Result<()> {
    unsafe {
        if libc::setpgid(0, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() == 1 {
                libc::raise(libc::SIGTERM);
            }
        }
    }
    Ok(())
}

/// Where the TAP we want to watch lives — and so which machine runs tcpdump.
///
/// A TAP is a kernel object and can only be sniffed from inside the kernel that
/// owns it. On the host that is us (as root); with the sidecar it is the
/// container's network namespace, reached with `docker exec`. Sniffing the
/// wrong one shows nothing at all.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CaptureHost {
    Local,
    Sidecar,
}

/// How to stop a child we started — not every child is ours to signal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Stop {
    /// An ordinary child running as us; signalled by process group.
    Group,
    /// A root-owned tcpdump here; sudo signals it by exact PID, since matching
    /// by name could kill somebody else's capture.
    HostRoot,
    /// A tcpdump inside the sidecar; its PID is only meaningful in the
    /// container's namespace, so the signal is sent from in there too.
    InContainer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DumpFilter {
    All,
    Arp,
    Ip,
}

impl DumpFilter {
    pub(super) fn next(self) -> Self {
        match self {
            Self::All => Self::Arp,
            Self::Arp => Self::Ip,
            Self::Ip => Self::All,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Arp => "arp",
            Self::Ip => "ip",
        }
    }

    /// The `tcpdump` expression this filter appends, if any.
    pub(super) fn expression(self) -> &'static str {
        match self {
            Self::All => "",
            Self::Arp => " arp",
            Self::Ip => " ip",
        }
    }

    /// The command shown in the pane title, `docker exec` prefix and all, so
    /// it is obvious where the frames come from.
    pub(super) fn title(self, iface: &str, host: CaptureHost) -> String {
        let prefix = match host {
            CaptureHost::Local => String::new(),
            CaptureHost::Sidecar => format!("docker exec {CONTAINER} "),
        };
        format!("{prefix}tcpdump -eni {iface} -l{}", self.expression())
    }
}

pub(super) struct ChildProc {
    pub(super) child: Option<Child>,
    pub(super) stop: Stop,
    pub(super) command_pid: Option<i32>,
    pub(super) exit_status: Option<std::process::ExitStatus>,
    pub(super) exit_error: Option<String>,
}

impl ChildProc {
    pub(super) fn spawn_stack(cfg: &Config, verbose: bool) -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let mut cmd = Command::new(exe);
        cmd.args(cfg.child_stack_args(verbose));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(configure_child_process);
        }
        let child = cmd.spawn()?;
        let command_pid = Some(child.id() as i32);
        Ok(Self {
            child: Some(child),
            stop: Stop::Group,
            command_pid,
            exit_status: None,
            exit_error: None,
        })
    }

    /// Start the capture, wherever the TAP happens to be.
    ///
    /// Both wrappers put tcpdump behind a monitor process, so what we spawn is
    /// not what we later signal. The shell prints its own PID before `exec`
    /// replaces it with tcpdump, which gives us the real one.
    pub(super) fn spawn_dump(
        filter: DumpFilter,
        iface: &str,
        host: CaptureHost,
    ) -> std::io::Result<Self> {
        let script = format!(
            "echo __MINITCP_DUMP_PID=$$; exec tcpdump -eni {iface} -l{}",
            filter.expression()
        );
        let (program, args, stop) = match host {
            CaptureHost::Local => (
                "sudo",
                vec!["-n".to_string(), "sh".into(), "-c".into(), script],
                Stop::HostRoot,
            ),
            CaptureHost::Sidecar => (
                "docker",
                vec![
                    "exec".to_string(),
                    CONTAINER.into(),
                    "sh".into(),
                    "-c".into(),
                    script,
                ],
                Stop::InContainer,
            ),
        };
        let mut cmd = Command::new(program);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(configure_child_process);
        }
        let mut child = cmd
            .spawn()
            .map_err(|error| explain_dump_failure(host, error))?;
        let command_pid = match child.stdout.as_mut().and_then(read_dump_pid) {
            Some(pid) => Some(pid),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::other(explain_no_pid(host)));
            }
        };
        Ok(Self {
            child: Some(child),
            stop,
            command_pid,
            exit_status: None,
            exit_error: None,
        })
    }

    /// A placeholder for a child that never started, so the UI holds no
    /// `Option`.
    pub(super) fn not_running() -> Self {
        Self {
            child: None,
            stop: Stop::Group,
            command_pid: None,
            exit_status: None,
            exit_error: None,
        }
    }

    pub(super) fn spawn_action(command: &str) -> std::io::Result<Self> {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
        let mut cmd = Command::new(shell);
        cmd.args(["-c", command])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(configure_child_process);
        }
        let child = cmd.spawn()?;
        let command_pid = Some(child.id() as i32);
        Ok(Self {
            child: Some(child),
            stop: Stop::Group,
            command_pid,
            exit_status: None,
            exit_error: None,
        })
    }

    pub(super) fn take_stdout_stderr(
        &mut self,
    ) -> Option<(std::process::ChildStdout, std::process::ChildStderr)> {
        let child = self.child.as_mut()?;
        Some((child.stdout.take()?, child.stderr.take()?))
    }

    pub(super) fn pid(&self) -> Option<i32> {
        self.child.as_ref().map(|c| c.id() as i32)
    }

    pub(super) fn alive(&mut self) -> bool {
        match self.child.as_mut() {
            None => false,
            Some(c) => match c.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    self.exit_status = Some(status);
                    false
                }
                Err(error) => {
                    self.exit_error = Some(error.to_string());
                    false
                }
            },
        }
    }

    pub(super) fn exit_summary(&self) -> String {
        match self.exit_status {
            Some(status) if status.success() => "successfully".into(),
            Some(status) => status.code().map_or_else(
                || "after a signal".into(),
                |code| format!("with status {code}"),
            ),
            None if self.exit_error.is_some() => {
                format!(
                    "after its status could not be read: {}",
                    self.exit_error.as_deref().unwrap_or("unknown error")
                )
            }
            None => "without an exit status".into(),
        }
    }

    pub(super) fn exited_successfully(&self) -> bool {
        self.exit_status.is_some_and(|status| status.success())
    }

    pub(super) fn kill(&mut self) {
        if let Some(pid) = self.pid() {
            match self.stop {
                Stop::Group => unsafe {
                    libc::kill(-pid, libc::SIGTERM);
                },
                // Ask politely, then insist. Killing only the wrapper leaves
                // tcpdump alive and invisible.
                Stop::HostRoot | Stop::InContainer => {
                    if let Some(command_pid) = self.command_pid {
                        signal_elsewhere(self.stop, command_pid, "TERM");
                        if !wait_for_exit(self.stop, command_pid, Duration::from_millis(500)) {
                            signal_elsewhere(self.stop, command_pid, "KILL");
                            wait_for_exit(self.stop, command_pid, Duration::from_millis(200));
                        }
                    }
                }
            }
        }
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Explain why a capture could not start — the raw OS error ("No such file or
/// directory") names neither the cause nor the fix.
pub(super) fn explain_dump_failure(host: CaptureHost, error: std::io::Error) -> std::io::Error {
    if error.kind() != std::io::ErrorKind::NotFound {
        return error;
    }
    let advice = match host {
        CaptureHost::Local => {
            "sudo is not installed, so tcpdump cannot be run as root. \
             Run minitcp as root, or use the TAP sidecar (`minitcp tap up`)."
        }
        CaptureHost::Sidecar => {
            "the TAP is in the sidecar container, but docker is not installed here. \
             Install Docker, or run minitcp on Linux with a local TAP."
        }
    };
    std::io::Error::new(std::io::ErrorKind::NotFound, advice)
}

/// The capture started but never announced itself, which almost always means
/// the wrapper refused before tcpdump ever ran.
pub(super) fn explain_no_pid(host: CaptureHost) -> &'static str {
    match host {
        CaptureHost::Local => {
            "tcpdump did not start. sudo probably wanted a password: \
             run `sudo -v` in another terminal, then press t."
        }
        CaptureHost::Sidecar => {
            "tcpdump did not start in the sidecar. Check the container is running \
             (`minitcp tap up`), then press t."
        }
    }
}

/// Signal a process we cannot signal ourselves: sudo borrows root's authority,
/// docker exec borrows the container's PID namespace. `kill` is a shell
/// builtin, so the image needs nothing installed.
pub(super) fn signal_elsewhere(stop: Stop, pid: i32, signal: &str) {
    let flag = format!("-{signal}");
    let pid = pid.to_string();
    let (program, args): (&str, Vec<&str>) = match stop {
        Stop::HostRoot => ("sudo", vec!["-n", "kill", &flag, "--", &pid]),
        Stop::InContainer => ("docker", vec!["exec", CONTAINER, "kill", &flag, &pid]),
        Stop::Group => return,
    };
    match crate::sys::process::output_timeout(program, &args, Duration::from_secs(3)) {
        Ok(output) if output.status.success() => {}
        Ok(output) => crate::log::status::warn(format!(
            "could not stop the tcpdump process {pid}: {}",
            crate::sys::process::output_detail(&output)
        )),
        Err(error) => {
            crate::log::status::warn(format!("could not stop the tcpdump process {pid}: {error}"))
        }
    }
}

pub(super) fn read_dump_pid(stdout: &mut std::process::ChildStdout) -> Option<i32> {
    const PREFIX: &str = "__MINITCP_DUMP_PID=";
    let mut marker = Vec::with_capacity(64);
    let mut byte = [0u8; 1];

    while marker.len() < 128 {
        match stdout.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => marker.push(byte[0]),
        }
    }

    let marker = String::from_utf8(marker).ok()?;
    marker.strip_prefix(PREFIX)?.trim().parse().ok()
}

/// Wait, briefly, for a process to actually be gone — a delivered signal is
/// not a dead process. Checking `/proc/PID` here is free; each check inside the
/// container is a whole `docker exec`, so that side is polled far less.
pub(super) fn wait_for_exit(stop: Stop, pid: i32, timeout: Duration) -> bool {
    let (interval, alive): (Duration, &dyn Fn() -> bool) = match stop {
        Stop::InContainer => (Duration::from_millis(100), &|| {
            // `kill -0` sends no signal; it only asks whether the PID is there.
            let pid = pid.to_string();
            crate::sys::process::output_timeout(
                "docker",
                &["exec", CONTAINER, "kill", "-0", &pid],
                Duration::from_secs(3),
            )
            .is_ok_and(|output| output.status.success())
        }),
        _ => (Duration::from_millis(10), &|| {
            Path::new(&format!("/proc/{pid}")).exists()
        }),
    };

    let started = Instant::now();
    while alive() {
        if started.elapsed() >= timeout {
            return false;
        }
        thread::sleep(interval);
    }
    true
}

impl Drop for ChildProc {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Start a capture, retrying once: the sidecar accepts connections a moment
/// before `docker exec` works, and a previous tcpdump's exit is not instant.
pub(super) fn spawn_dump_with_retry(
    filter: DumpFilter,
    iface: &str,
    host: CaptureHost,
) -> std::io::Result<ChildProc> {
    match ChildProc::spawn_dump(filter, iface, host) {
        Ok(child) => Ok(child),
        Err(_) => {
            thread::sleep(Duration::from_millis(200));
            ChildProc::spawn_dump(filter, iface, host)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_filter_cycles_through_each_view() {
        assert!(DumpFilter::All.next() == DumpFilter::Arp);
        assert!(DumpFilter::Arp.next() == DumpFilter::Ip);
        assert!(DumpFilter::Ip.next() == DumpFilter::All);
    }

    #[test]
    fn a_local_tap_is_captured_on_this_host() {
        assert_eq!(
            DumpFilter::All.title("tap0", CaptureHost::Local),
            "tcpdump -eni tap0 -l"
        );
    }

    #[test]
    fn a_sidecar_tap_is_captured_inside_the_container() {
        // tap0 in the sidecar's namespace is not there to sniff from here.
        assert_eq!(
            DumpFilter::Arp.title("tap0", CaptureHost::Sidecar),
            "docker exec minitcp-tap tcpdump -eni tap0 -l arp"
        );
    }

    #[test]
    fn the_filter_only_changes_the_expression_not_the_location() {
        for filter in [DumpFilter::All, DumpFilter::Arp, DumpFilter::Ip] {
            for host in [CaptureHost::Local, CaptureHost::Sidecar] {
                let title = filter.title("tap0", host);
                assert!(title.contains("tcpdump -eni tap0 -l"), "{title}");
                assert!(title.ends_with(filter.expression()), "{title}");
                assert_eq!(
                    title.starts_with("docker exec"),
                    host == CaptureHost::Sidecar,
                    "{title}"
                );
            }
        }
    }

    #[test]
    fn a_capture_that_cannot_start_says_which_tool_is_missing() {
        let missing = || std::io::Error::from(std::io::ErrorKind::NotFound);

        let local = explain_dump_failure(CaptureHost::Local, missing()).to_string();
        assert!(local.contains("sudo"), "{local}");

        let sidecar = explain_dump_failure(CaptureHost::Sidecar, missing()).to_string();
        assert!(sidecar.contains("docker"), "{sidecar}");

        // Only a missing program gets rewritten; anything else stays verbatim.
        let other = std::io::Error::other("disk on fire");
        assert_eq!(
            explain_dump_failure(CaptureHost::Local, other).to_string(),
            "disk on fire"
        );
    }

    #[test]
    fn shutdown_signal_requests_clean_ui_exit() {
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
        request_shutdown(libc::SIGTERM);
        assert!(SHUTDOWN_REQUESTED.load(Ordering::Relaxed));
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    }
}

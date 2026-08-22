// Terminal UI. The protocol implementation lives outside this folder.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, IsTerminal, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::cli::{Config, Transport};
use crate::tapcmd::CONTAINER;

const MAX_LINES: usize = 2000;
const SHORT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() -> std::io::Result<()> {
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

fn configure_child_process() -> std::io::Result<()> {
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Stack,
    Dump,
    Actions,
}

impl Pane {
    fn next(self) -> Self {
        match self {
            Self::Stack => Self::Dump,
            Self::Dump => Self::Actions,
            Self::Actions => Self::Stack,
        }
    }
}

/// Where the TAP device we want to watch actually lives.
///
/// The capture pane always shows the same thing — every frame on the wire, as
/// seen by `tcpdump` — but *which machine* runs tcpdump depends on where the
/// TAP is. A TAP is a kernel object, so it can only be sniffed from inside the
/// kernel that owns it:
///
///   * on Linux, `minitcp tap up` makes tap0 a device on this host, so tcpdump
///     runs here (as root, hence sudo).
///   * everywhere else, tap0 lives in the sidecar container's network
///     namespace. tcpdump has to run *in there*, which is what `docker exec`
///     gives us. Sniffing on the host would show the container's port
///     forwarding, not the frames on tap0.
///
/// Getting this wrong is not a difference in formatting — it is the difference
/// between seeing traffic and seeing nothing at all.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CaptureHost {
    Local,
    Sidecar,
}

/// How to stop a child we started.
///
/// Not every child can be stopped the same way, because not every child is ours
/// to signal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// An ordinary child running as us. We signal its whole process group, so
    /// any helpers it spawned go too.
    Group,
    /// A root-owned tcpdump on this host. We cannot signal it as ourselves, so
    /// we ask sudo to, naming the exact PID tcpdump reported (matching by name
    /// could kill somebody else's capture).
    HostRoot,
    /// A tcpdump inside the sidecar. Its PID is a number in the *container's*
    /// PID namespace and means nothing here — signalling it on the host could
    /// hit an unrelated process — so the signal is sent from inside the
    /// container too.
    InContainer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DumpFilter {
    All,
    Arp,
    Ip,
}

impl DumpFilter {
    fn next(self) -> Self {
        match self {
            Self::All => Self::Arp,
            Self::Arp => Self::Ip,
            Self::Ip => Self::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Arp => "arp",
            Self::Ip => "ip",
        }
    }

    /// The `tcpdump` expression this filter appends, if any.
    fn expression(self) -> &'static str {
        match self {
            Self::All => "",
            Self::Arp => " arp",
            Self::Ip => " ip",
        }
    }

    /// The command shown in the pane's title — the real one, including the
    /// `docker exec` prefix when the capture is happening in the sidecar, so it
    /// is obvious where the frames are coming from.
    fn title(self, iface: &str, host: CaptureHost) -> String {
        let prefix = match host {
            CaptureHost::Local => String::new(),
            CaptureHost::Sidecar => format!("docker exec {CONTAINER} "),
        };
        format!("{prefix}tcpdump -eni {iface} -l{}", self.expression())
    }
}

enum Msg {
    Stack(String),
    StackStatus(String),
    Dump(String),
    Action(String),
}

struct Buffer {
    lines: VecDeque<String>,
    /// Lines hidden at the bottom while looking through scrollback.
    from_bottom: usize,
    viewport_height: usize,
    auto_follow: bool,
}

impl Buffer {
    fn new() -> Self {
        Self {
            lines: VecDeque::new(),
            from_bottom: 0,
            viewport_height: 0,
            auto_follow: true,
        }
    }

    fn push(&mut self, line: String) {
        self.lines.push_back(line);
        while self.lines.len() > MAX_LINES {
            self.lines.pop_front();
        }
        if self.auto_follow {
            self.from_bottom = 0;
        } else {
            let max = self.lines.len().saturating_sub(self.viewport_height);
            self.from_bottom = self.from_bottom.saturating_add(1).min(max);
        }
    }

    fn push_output(&mut self, line: String, force_follow: bool) {
        if force_follow {
            self.follow();
        }
        self.push(line);
    }

    fn clear(&mut self) {
        self.lines.clear();
        self.from_bottom = 0;
        self.auto_follow = true;
    }

    fn scroll_up(&mut self, n: usize) {
        let max = self.lines.len().saturating_sub(self.viewport_height);
        self.from_bottom = (self.from_bottom + n).min(max);
        if self.from_bottom > 0 {
            self.auto_follow = false;
        }
    }

    fn scroll_down(&mut self, n: usize) {
        self.from_bottom = self.from_bottom.saturating_sub(n);
        if self.from_bottom == 0 {
            self.auto_follow = true;
        }
    }

    fn follow(&mut self) {
        self.from_bottom = 0;
        self.auto_follow = true;
    }

    fn toggle_follow(&mut self) {
        if self.auto_follow {
            self.auto_follow = false;
        } else {
            self.follow();
        }
    }

    fn page_size(&self) -> usize {
        self.viewport_height.saturating_sub(1).max(1)
    }

    fn visible(&mut self, height: usize) -> Vec<String> {
        self.viewport_height = height;
        let max = self.lines.len().saturating_sub(height);
        self.from_bottom = self.from_bottom.min(max);
        if max == 0 {
            self.auto_follow = true;
        }
        if height == 0 || self.lines.is_empty() {
            return Vec::new();
        }
        let end = self.lines.len().saturating_sub(self.from_bottom);
        let start = end.saturating_sub(height);
        self.lines
            .iter()
            .skip(start)
            .take(end - start)
            .cloned()
            .collect()
    }
}

struct ChildProc {
    child: Option<Child>,
    stop: Stop,
    command_pid: Option<i32>,
    exit_status: Option<std::process::ExitStatus>,
    exit_error: Option<String>,
}

impl ChildProc {
    fn spawn_stack(cfg: &Config, verbose: bool) -> std::io::Result<Self> {
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
    /// Both variants run the same tcpdump; only the wrapper differs. Either
    /// wrapper can put tcpdump behind a monitor process — `sudo` does, and so
    /// does `docker exec` — so the process we spawn is *not* the process we
    /// will later need to signal. The shell prints its own PID before `exec`
    /// replaces it with tcpdump, which gives us the real one.
    fn spawn_dump(filter: DumpFilter, iface: &str, host: CaptureHost) -> std::io::Result<Self> {
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

    /// A placeholder for a child that could not be started, so the rest of the
    /// UI has something to hold and does not need to special-case `None`.
    fn not_running() -> Self {
        Self {
            child: None,
            stop: Stop::Group,
            command_pid: None,
            exit_status: None,
            exit_error: None,
        }
    }

    fn spawn_action(command: &str) -> std::io::Result<Self> {
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

    fn take_stdout_stderr(
        &mut self,
    ) -> Option<(std::process::ChildStdout, std::process::ChildStderr)> {
        let child = self.child.as_mut()?;
        Some((child.stdout.take()?, child.stderr.take()?))
    }

    fn pid(&self) -> Option<i32> {
        self.child.as_ref().map(|c| c.id() as i32)
    }

    fn alive(&mut self) -> bool {
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

    fn exit_summary(&self) -> String {
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

    fn exited_successfully(&self) -> bool {
        self.exit_status.is_some_and(|status| status.success())
    }

    fn kill(&mut self) {
        if let Some(pid) = self.pid() {
            match self.stop {
                Stop::Group => unsafe {
                    libc::kill(-pid, libc::SIGTERM);
                },
                // Ask politely first, then insist. Killing the wrapper we
                // spawned is not enough: tcpdump outlives it, and on the next
                // `t` we would be competing with a capture nobody can see.
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

/// Explain why a capture could not even be started.
///
/// Both wrappers fail for boring, fixable reasons, and the raw OS error
/// ("No such file or directory") names neither the cause nor the fix.
fn explain_dump_failure(host: CaptureHost, error: std::io::Error) -> std::io::Error {
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
fn explain_no_pid(host: CaptureHost) -> &'static str {
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

/// Send a signal to a process we cannot signal ourselves.
///
/// `Stop::HostRoot` borrows root's authority via sudo. `Stop::InContainer`
/// borrows the container's *PID namespace* via docker exec — the PID is
/// meaningless outside it, so the signal has to be sent from inside. `kill` is
/// a shell builtin, so this needs nothing installed in the image.
fn signal_elsewhere(stop: Stop, pid: i32, signal: &str) {
    let flag = format!("-{signal}");
    let pid = pid.to_string();
    let (program, args): (&str, Vec<&str>) = match stop {
        Stop::HostRoot => ("sudo", vec!["-n", "kill", &flag, "--", &pid]),
        Stop::InContainer => ("docker", vec!["exec", CONTAINER, "kill", &flag, &pid]),
        Stop::Group => return,
    };
    match crate::process::output_timeout(program, &args, Duration::from_secs(3)) {
        Ok(output) if output.status.success() => {}
        Ok(output) => crate::log::status::warn(format!(
            "could not stop the tcpdump process {pid}: {}",
            crate::process::output_detail(&output)
        )),
        Err(error) => {
            crate::log::status::warn(format!("could not stop the tcpdump process {pid}: {error}"))
        }
    }
}

fn read_dump_pid(stdout: &mut std::process::ChildStdout) -> Option<i32> {
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

/// Wait, briefly, for a process to actually be gone.
///
/// Signals are asynchronous: `kill` returning says the signal was delivered,
/// not that the process has died. Checking costs almost nothing on this host
/// (`/proc/PID` either exists or does not), but each check inside the container
/// is a whole `docker exec`, so that side is polled far less often.
fn wait_for_exit(stop: Stop, pid: i32, timeout: Duration) -> bool {
    let (interval, alive): (Duration, &dyn Fn() -> bool) = match stop {
        Stop::InContainer => (Duration::from_millis(100), &|| {
            // `kill -0` sends no signal; it only asks "does this exist, and
            // may I signal it?".
            let pid = pid.to_string();
            crate::process::output_timeout(
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

/// Start a capture, and if it fails immediately, try once more.
///
/// The retry is for a genuine race at startup: the sidecar's port is accepting
/// connections a moment before `docker exec` will work, and a previous
/// tcpdump's exit is not always instant.
fn spawn_dump_with_retry(
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

struct Lab {
    focus: Pane,
    filter: DumpFilter,
    /// Which machine runs tcpdump for the capture pane. Fixed for the life of
    /// the lab, because the transport it is derived from is too.
    capture: CaptureHost,
    stack_buf: Buffer,
    dump_buf: Buffer,
    action_buf: Buffer,
    stack: ChildProc,
    dump: ChildProc,
    rx: Receiver<Msg>,
    tx: Sender<Msg>,
    last_status: Instant,
    tap_up: bool,
    tap_addr: String,
    stack_alive: bool,
    dump_alive: bool,
    action_process: Option<ChildProc>,
    command_input: Option<String>,
    verbose: bool,
    cfg: Config,
    icmp_in: u32,
    icmp_out: u32,
    arp_in: u32,
    arp_out: u32,
}

/// Report whether the local TAP is there, without touching it.
///
/// Opening the lab deliberately does *not* create the TAP. Bringing up a
/// virtual network device is a real change to the machine — it needs root, and
/// it outlives the program that made it — so it stays an explicit thing the
/// user asks for with `minitcp tap up`. It is also the step worth
/// understanding: a lab that quietly conjures its own wire teaches nothing
/// about where the wire came from.
fn report_tap_status(cfg: &Config, tx: &Sender<Msg>) {
    if !cfg.tun.exists() {
        let _ = tx.send(Msg::Action(format!(
            "minitcp: error: {} is missing; run in the Dev Container or a privileged Linux container.",
            cfg.tun.display()
        )));
        return;
    }

    if Path::new(&format!("/sys/class/net/{}", cfg.iface)).exists() {
        let _ = tx.send(Msg::Action(format!("attached to {}", cfg.iface)));
    } else {
        let _ = tx.send(Msg::Action(format!(
            "minitcp: error: {} does not exist. Run `minitcp tap up` in another terminal, then press r.",
            cfg.iface
        )));
    }
}

fn pump_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    tx: Sender<Msg>,
    wrap: fn(String) -> Msg,
) {
    let error_tx = tx.clone();
    if let Err(error) = thread::Builder::new()
        .name("minitcp-child-output".into())
        .spawn(move || {
            let buf = BufReader::new(reader);
            for line in buf.lines() {
                match line {
                    Ok(s) => {
                        if tx.send(wrap(s)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(wrap(format!(
                            "minitcp: error: cannot read child output: {error}"
                        )));
                        break;
                    }
                }
            }
        })
    {
        let _ = error_tx.send(wrap(format!(
            "minitcp: error: cannot monitor child output: {error}"
        )));
    }
}

fn attach_child(
    child: &mut ChildProc,
    tx: Sender<Msg>,
    stdout_wrap: fn(String) -> Msg,
    stderr_wrap: fn(String) -> Msg,
) {
    if let Some((out, err)) = child.take_stdout_stderr() {
        pump_reader(out, tx.clone(), stdout_wrap);
        pump_reader(err, tx, stderr_wrap);
    }
}

fn tap_status(iface: &str, linux_addr: &str) -> (bool, String) {
    let up = Path::new(&format!("/sys/class/net/{iface}")).exists();
    if !up {
        return (false, "down".into());
    }
    let out = crate::process::output_timeout(
        "ip",
        &["-br", "addr", "show", iface],
        SHORT_COMMAND_TIMEOUT,
    )
    .ok();
    let text = out
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let up = text.contains("UP");
    let addr = text
        .split_whitespace()
        .find(|w| w.contains('.'))
        .unwrap_or(linux_addr)
        .to_string();
    (up, addr)
}

fn run_short(tx: &Sender<Msg>, program: &str, args: &[&str]) {
    let shown = format!("$ {program} {}", args.join(" "));
    let _ = tx.send(Msg::Action(shown));
    match crate::process::output_timeout(program, args, SHORT_COMMAND_TIMEOUT) {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            for line in stdout.lines().chain(stderr.lines()) {
                let _ = tx.send(Msg::Action(line.to_string()));
            }
            if stdout.is_empty() && stderr.is_empty() {
                let _ = tx.send(Msg::Action("(no output)".into()));
            }
            if !out.status.success() {
                let status = out.status.code().map_or_else(
                    || "terminated by signal".to_string(),
                    |code| format!("exited with status {code}"),
                );
                let _ = tx.send(Msg::Action(format!("minitcp: error: command {status}")));
            }
        }
        Err(e) => {
            let _ = tx.send(Msg::Action(format!("minitcp: error: {e}")));
        }
    }
}

impl Lab {
    fn start(mut cfg: Config) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        // Decide the transport once, here, and pin it into the config. The
        // child `minitcp stack` inherits our flags, so if we left it to decide
        // for itself it could reach a different answer — and then the lab would
        // be watching one TAP while the stack talked to another.
        let remote = match cfg.transport() {
            Transport::Forwarded(addr) => {
                cfg.fwd = Some(addr);
                true
            }
            Transport::LocalTap => {
                report_tap_status(&cfg, &tx);
                false
            }
        };

        let verbose = !cfg.quiet;
        let mut stack = ChildProc::spawn_stack(&cfg, verbose)?;
        attach_child(&mut stack, tx.clone(), Msg::Stack, Msg::StackStatus);

        let filter = DumpFilter::All;
        // The capture follows the TAP. When frames are being forwarded from the
        // sidecar, tap0 is a device in *its* network namespace, so that is where
        // tcpdump has to run — otherwise the pane sits empty while traffic
        // flows perfectly well.
        let capture = if remote {
            CaptureHost::Sidecar
        } else {
            CaptureHost::Local
        };
        let mut dump = match spawn_dump_with_retry(filter, &cfg.iface, capture) {
            Ok(mut d) => {
                attach_child(&mut d, tx.clone(), Msg::Dump, Msg::Dump);
                d
            }
            Err(e) => {
                let _ = tx.send(Msg::Dump(format!(
                    "minitcp: error: tcpdump not started: {e}"
                )));
                ChildProc::not_running()
            }
        };

        let linux = cfg.linux_addr.to_string();
        let (tap_up, tap_addr) = if remote {
            (true, cfg.fwd_addr())
        } else {
            tap_status(&cfg.iface, &linux)
        };
        let stack_alive = stack.alive();
        let dump_alive = dump.alive();
        let mut action_buf = Buffer::new();
        action_buf
            .push("lab ready. Tab focuses a pane. p ping  n neigh  f flush  d dump filter.".into());
        if remote {
            action_buf.push(
                "frames via TAP sidecar; capture runs in there too (p, n, f use docker exec)."
                    .into(),
            );
        }
        if !stack_alive {
            action_buf.push(
                "minitcp: error: stack failed to stay up; try `minitcp tap up`, then press r"
                    .into(),
            );
        }

        Ok(Self {
            focus: Pane::Stack,
            filter,
            capture,
            stack_buf: Buffer::new(),
            dump_buf: Buffer::new(),
            action_buf,
            stack,
            dump,
            rx,
            tx,
            last_status: Instant::now(),
            tap_up,
            tap_addr,
            stack_alive,
            dump_alive,
            action_process: None,
            command_input: None,
            verbose,
            cfg,
            icmp_in: 0,
            icmp_out: 0,
            arp_in: 0,
            arp_out: 0,
        })
    }

    fn toggle_verbose(&mut self) {
        self.verbose = !self.verbose;
        self.restart_stack();
        self.push_pane(
            Pane::Stack,
            if self.verbose {
                "— verbose: headers decoded —".into()
            } else {
                "— quiet: one line per exchange —".into()
            },
        );
    }

    fn restart_stack(&mut self) {
        self.stack.kill();
        match ChildProc::spawn_stack(&self.cfg, self.verbose) {
            Ok(mut c) => {
                attach_child(&mut c, self.tx.clone(), Msg::Stack, Msg::StackStatus);
                self.stack = c;
                self.stack_alive = true;
                self.icmp_in = 0;
                self.icmp_out = 0;
                self.arp_in = 0;
                self.arp_out = 0;
                self.push_pane(Pane::Stack, "— stack restarted —".into());
            }
            Err(e) => self.push_pane(
                Pane::Actions,
                format!("minitcp: error: could not restart stack: {e}"),
            ),
        }
    }

    fn restart_dump(&mut self) {
        self.dump.kill();
        match spawn_dump_with_retry(self.filter, &self.cfg.iface, self.capture) {
            Ok(mut c) => {
                attach_child(&mut c, self.tx.clone(), Msg::Dump, Msg::Dump);
                self.dump = c;
                self.dump_alive = true;
                self.push_pane(
                    Pane::Dump,
                    format!("— {} —", self.filter.title(&self.cfg.iface, self.capture)),
                );
            }
            Err(e) => self.push_pane(
                Pane::Dump,
                format!("minitcp: error: could not start tcpdump: {e}"),
            ),
        }
    }

    fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.restart_dump();
    }

    fn clear_focused(&mut self) {
        match self.focus {
            Pane::Stack => self.stack_buf.clear(),
            Pane::Dump => self.dump_buf.clear(),
            Pane::Actions => self.action_buf.clear(),
        }
    }

    fn run_command(&mut self, command: String) {
        let command = command.trim();
        if command.is_empty() {
            return;
        }

        if self.action_process.as_mut().is_some_and(ChildProc::alive) {
            self.action_buf
                .push("a command is already running; wait for it to finish".into());
            return;
        }

        if let Some(mut old) = self.action_process.take() {
            old.kill();
        }

        self.focus = Pane::Actions;
        self.action_buf.follow();
        self.action_buf.push(format!("$ {command}"));
        match ChildProc::spawn_action(command) {
            Ok(mut child) => {
                attach_child(&mut child, self.tx.clone(), Msg::Action, Msg::Action);
                self.action_process = Some(child);
            }
            Err(e) => self
                .action_buf
                .push(format!("minitcp: error: could not start command: {e}")),
        }
    }

    fn focused_buf_mut(&mut self) -> &mut Buffer {
        match self.focus {
            Pane::Stack => &mut self.stack_buf,
            Pane::Dump => &mut self.dump_buf,
            Pane::Actions => &mut self.action_buf,
        }
    }

    fn push_pane(&mut self, pane: Pane, line: String) {
        let force_follow = self.focus != pane;
        match pane {
            Pane::Stack => self.stack_buf.push_output(line, force_follow),
            Pane::Dump => self.dump_buf.push_output(line, force_follow),
            Pane::Actions => self.action_buf.push_output(line, force_follow),
        }
    }

    fn count_stack_line(&mut self, line: &str) {
        if line.contains("echo id=") {
            self.icmp_in += 1;
            self.icmp_out += 1;
            return;
        }
        if line.contains("type=8 ") {
            self.icmp_in += 1;
        }
        if line.contains("type=0 ") {
            self.icmp_out += 1;
        }
        if line.contains("who-has") {
            self.arp_in += 1;
            if !line.contains('[') {
                self.arp_out += 1;
            }
        }
        if line.contains("is-at") {
            self.arp_out += 1;
        }
    }

    fn drain_msgs(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Stack(s) => {
                    self.count_stack_line(&s);
                    self.push_pane(Pane::Stack, s);
                }
                Msg::StackStatus(s) => self.push_pane(Pane::Stack, s),
                Msg::Dump(s) => self.push_pane(Pane::Dump, s),
                Msg::Action(s) => self.push_pane(Pane::Actions, s),
            }
        }
    }

    fn refresh_status(&mut self) {
        if self.last_status.elapsed() > Duration::from_millis(800) {
            if self.cfg.fwd.is_none() {
                let linux = self.cfg.linux_addr.to_string();
                let (up, addr) = tap_status(&self.cfg.iface, &linux);
                self.tap_up = up;
                self.tap_addr = addr;
            }
            let stack_alive = self.stack.alive();
            let dump_alive = self.dump.alive();
            if self.stack_alive && !stack_alive {
                let line = if self.stack.exited_successfully() {
                    "minitcp: stack finished successfully".into()
                } else {
                    format!(
                        "minitcp: error: stack exited {}; press r to restart",
                        self.stack.exit_summary()
                    )
                };
                self.push_pane(Pane::Stack, line);
            }
            if self.dump_alive && !dump_alive {
                self.push_pane(
                    Pane::Dump,
                    format!(
                        "minitcp: error: tcpdump exited {}; press t to restart",
                        self.dump.exit_summary()
                    ),
                );
            }
            self.stack_alive = stack_alive;
            self.dump_alive = dump_alive;
            self.last_status = Instant::now();
        }

        let action_finished = self
            .action_process
            .as_mut()
            .is_some_and(|process| !process.alive());
        if action_finished && let Some(mut process) = self.action_process.take() {
            let success = process.exited_successfully();
            let summary = process.exit_summary();
            process.kill();
            if success {
                self.push_pane(Pane::Actions, "— command finished —".into());
            } else {
                self.push_pane(
                    Pane::Actions,
                    format!("minitcp: error: command exited {summary}"),
                );
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        if self.command_input.is_some() {
            match key.code {
                KeyCode::Esc => self.command_input = None,
                KeyCode::Enter => {
                    if let Some(command) = self.command_input.take() {
                        self.run_command(command);
                    }
                }
                KeyCode::Backspace => {
                    if let Some(input) = self.command_input.as_mut() {
                        input.pop();
                    }
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if let Some(input) = self.command_input.as_mut() {
                        input.push(character);
                    }
                }
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::Char('1') => self.focus = Pane::Stack,
            KeyCode::Char('2') => self.focus = Pane::Dump,
            KeyCode::Char('3') => self.focus = Pane::Actions,
            KeyCode::Char(':') => {
                self.focus = Pane::Actions;
                self.command_input = Some(String::new());
            }
            KeyCode::Char('p') => {
                let tx = self.tx.clone();
                let addr = self.cfg.addr.to_string();
                let sidecar = self.cfg.fwd.is_some();
                thread::spawn(move || {
                    if sidecar {
                        run_short(
                            &tx,
                            "docker",
                            &["exec", CONTAINER, "ping", "-c", "1", "-W", "1", &addr],
                        );
                    } else {
                        run_short(&tx, "ping", &["-c", "1", "-W", "1", &addr]);
                    }
                });
            }
            KeyCode::Char('n') => {
                let tx = self.tx.clone();
                let iface = self.cfg.iface.clone();
                let sidecar = self.cfg.fwd.is_some();
                thread::spawn(move || {
                    if sidecar {
                        run_short(
                            &tx,
                            "docker",
                            &["exec", CONTAINER, "ip", "neigh", "show", "dev", &iface],
                        );
                    } else {
                        run_short(&tx, "ip", &["neigh", "show", "dev", &iface]);
                    }
                });
            }
            KeyCode::Char('f') => {
                let tx = self.tx.clone();
                let iface = self.cfg.iface.clone();
                let sidecar = self.cfg.fwd.is_some();
                thread::spawn(move || {
                    if sidecar {
                        run_short(
                            &tx,
                            "docker",
                            &["exec", CONTAINER, "ip", "neigh", "flush", "dev", &iface],
                        );
                    } else {
                        run_short(&tx, "sudo", &["-n", "ip", "neigh", "flush", "dev", &iface]);
                    }
                });
            }
            KeyCode::Char('r') => self.restart_stack(),
            KeyCode::Char('v') => self.toggle_verbose(),
            KeyCode::Char('t') => self.restart_dump(),
            KeyCode::Char('d') => self.cycle_filter(),
            KeyCode::Char('c') => self.clear_focused(),
            KeyCode::Char('a') => self.focused_buf_mut().toggle_follow(),
            KeyCode::Up => self.focused_buf_mut().scroll_up(1),
            KeyCode::Down => self.focused_buf_mut().scroll_down(1),
            KeyCode::PageUp => {
                let page = self.focused_buf_mut().page_size();
                self.focused_buf_mut().scroll_up(page);
            }
            KeyCode::PageDown => {
                let page = self.focused_buf_mut().page_size();
                self.focused_buf_mut().scroll_down(page);
            }
            KeyCode::End => self.focused_buf_mut().follow(),
            _ => {}
        }
        false
    }
}

fn style_line(text: &str) -> Line<'_> {
    let lower = text.to_ascii_lowercase();
    if text.starts_with("minitcp:") {
        let color = if lower.starts_with("minitcp: error:") {
            Color::Red
        } else if lower.starts_with("minitcp: warning:") {
            Color::Yellow
        } else {
            Color::LightBlue
        };
        return Line::from(Span::styled(text.to_string(), Style::default().fg(color)));
    }
    if lower.contains("error") || lower.contains("failed") || lower.contains("bad ") {
        return Line::from(Span::styled(
            text.to_string(),
            Style::default().fg(Color::Red),
        ));
    }
    if text.starts_with("$ ") {
        return Line::from(Span::styled(
            text.to_string(),
            Style::default().fg(Color::Green),
        ));
    }
    for (tag, color) in [
        ("[DROP]", Color::Red),
        ("[OUT]", Color::Green),
        ("[IN]", Color::Cyan),
        ("[..]", Color::DarkGray),
    ] {
        if let Some(at) = text.find(tag) {
            let gray = Style::default().fg(Color::Gray);
            return Line::from(vec![
                Span::styled(text[..at].to_string(), gray),
                Span::styled(
                    tag.to_string(),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(text[at + tag.len()..].to_string(), gray),
            ]);
        }
    }
    let color = if lower.contains("icmp") || lower.contains(" echo ") {
        Color::Cyan
    } else if lower.contains("arp") {
        Color::Yellow
    } else {
        Color::Gray
    };
    Line::from(Span::styled(text.to_string(), Style::default().fg(color)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PaneRole {
    MiniTcpCore,
    ExternalTool,
}

fn pane_block(title: String, focused: bool, role: PaneRole) -> Block<'static> {
    let (border_color, title_color, background) = match (role, focused) {
        (PaneRole::MiniTcpCore, true) => (Color::LightCyan, Color::Black, Color::Rgb(3, 20, 36)),
        (PaneRole::MiniTcpCore, false) => (Color::Blue, Color::LightCyan, Color::Rgb(3, 15, 28)),
        (PaneRole::ExternalTool, true) => {
            (Color::LightYellow, Color::Black, Color::Rgb(12, 18, 24))
        }
        (PaneRole::ExternalTool, false) => (Color::DarkGray, Color::Gray, Color::Black),
    };
    let title = if focused {
        format!(" ▶ {title} ")
    } else {
        format!(" {title} ")
    };
    let title_style = if focused {
        Style::default()
            .fg(title_color)
            .bg(border_color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(title_color)
            .add_modifier(Modifier::BOLD)
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(if focused {
            BorderType::Double
        } else {
            BorderType::Plain
        })
        .title(title)
        .title_style(title_style)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(background).fg(Color::Gray))
}

fn draw(frame: &mut Frame, lab: &mut Lab) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Ratio(2, 3),
            Constraint::Ratio(1, 3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let ours = lab.cfg.addr.to_string();
    let tap = if lab.tap_up { "UP" } else { "DOWN" };
    let tap_color = if lab.tap_up { Color::Green } else { Color::Red };
    let stack_st = if lab.stack_alive { "run" } else { "off" };
    let dump_st = if lab.dump_alive { "run" } else { "off" };
    let status = Line::from(vec![
        Span::styled(
            " MiniTCP ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {} ", lab.cfg.iface)),
        Span::styled(
            tap,
            Style::default().fg(tap_color).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw(lab.tap_addr.as_str()),
        Span::raw("  ↔  "),
        Span::raw(ours),
        Span::raw("   Core:"),
        Span::styled(
            stack_st,
            Style::default().fg(if lab.stack_alive {
                Color::Green
            } else {
                Color::Red
            }),
        ),
        Span::raw("  log:"),
        Span::styled(
            if lab.verbose { "verbose" } else { "quiet" },
            Style::default().fg(if lab.verbose {
                Color::Cyan
            } else {
                Color::Gray
            }),
        ),
        Span::raw(format!(
            "  icmp {}/{}  arp {}/{}",
            lab.icmp_in, lab.icmp_out, lab.arp_in, lab.arp_out
        )),
        Span::raw("  Capture:"),
        Span::styled(
            format!("{}:{}", dump_st, lab.filter.label()),
            Style::default().fg(if lab.dump_alive {
                Color::Yellow
            } else {
                Color::Red
            }),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(status).style(Style::default().bg(Color::DarkGray)),
        layout[0],
    );

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(layout[1]);
    let stack_focused = lab.focus == Pane::Stack;
    let dump_focused = lab.focus == Pane::Dump;
    let actions_focused = lab.focus == Pane::Actions;

    render_term(
        frame,
        top[0],
        "1 MiniTCP Core",
        &mut lab.stack_buf,
        stack_focused,
        PaneRole::MiniTcpCore,
    );
    // Name where the capture is running. Two people with the same screen open
    // can be sniffing two different kernels, and that is worth saying out loud.
    let capture_title = match lab.capture {
        CaptureHost::Local => "2 TAP Capture (this host)",
        CaptureHost::Sidecar => "2 TAP Capture (sidecar)",
    };
    render_term(
        frame,
        top[1],
        capture_title,
        &mut lab.dump_buf,
        dump_focused,
        PaneRole::ExternalTool,
    );
    render_term(
        frame,
        layout[2],
        "3 External Tools",
        &mut lab.action_buf,
        actions_focused,
        PaneRole::ExternalTool,
    );

    let footer = match &lab.command_input {
        Some(input) => Line::from(vec![
            Span::styled(
                " COMMAND › ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {input}")),
            Span::styled("█", Style::default().fg(Color::Cyan)),
            Span::styled(
                "  Enter run · Esc cancel",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        None => Line::from(vec![
            key("tab/1-3", "focus"),
            key("↑↓", "scroll"),
            key("a", "live"),
            key(":", "command"),
            key("p", "ping"),
            key("n", "neigh"),
            key("f", "flush"),
            key("d", "filter"),
            key("v", if lab.verbose { "quiet" } else { "verbose" }),
            key("q", "quit"),
        ]),
    };
    frame.render_widget(Paragraph::new(footer), layout[3]);
}

fn key<'a>(k: &'a str, label: &'a str) -> Span<'a> {
    Span::from(format!(" <{k}> {label}  ")).style(Style::default().fg(Color::Yellow))
}

fn render_term(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    buf: &mut Buffer,
    focused: bool,
    role: PaneRole,
) {
    let inner_h = area.height.saturating_sub(2) as usize;
    let visible = buf.visible(inner_h);
    let lines: Vec<Line> = visible.iter().map(|s| style_line(s)).collect();
    let title = if buf.auto_follow {
        title.to_string()
    } else {
        format!("{title} · PAUSED")
    };
    let mut widget = Paragraph::new(lines).block(pane_block(title, focused, role));
    if role != PaneRole::MiniTcpCore {
        widget = widget.wrap(Wrap { trim: false });
    }
    frame.render_widget(widget, area);
}

fn ui_loop(terminal: &mut DefaultTerminal, lab: &mut Lab) -> std::io::Result<()> {
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            break;
        }
        lab.drain_msgs();
        lab.refresh_status();
        terminal.draw(|f| draw(f, lab))?;

        if event::poll(Duration::from_millis(80))? {
            match event::read()? {
                Event::Key(key) => {
                    if lab.handle_key(key) {
                        break;
                    }
                }
                Event::Mouse(m) => {
                    use crossterm::event::MouseEventKind;
                    match m.kind {
                        MouseEventKind::ScrollUp => lab.focused_buf_mut().scroll_up(3),
                        MouseEventKind::ScrollDown => lab.focused_buf_mut().scroll_down(3),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn run_lab(cfg: Config) -> std::io::Result<()> {
    if !std::io::stdout().is_terminal() {
        return Err(std::io::Error::other(
            "run needs a terminal; use `minitcp stack` for piped output",
        ));
    }
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    install_signal_handlers().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("cannot install terminal signal handlers: {error}"),
        )
    })?;
    let mut lab = Lab::start(cfg)?;
    let mut terminal = ratatui::try_init().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("cannot initialize terminal UI: {error}"),
        )
    })?;
    let result = ui_loop(&mut terminal, &mut lab);
    if let Err(error) = ratatui::try_restore() {
        crate::log::status::warn(format!("could not fully restore terminal: {error}"));
    }
    lab.stack.kill();
    lab.dump.kill();
    if let Some(mut process) = lab.action_process.take() {
        process.kill();
    }
    result
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
        // The whole point of the fix: when tap0 lives in the sidecar's network
        // namespace, running tcpdump on the host would show nothing, because
        // the device is not there to sniff.
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

        // Anything that is not a missing program is somebody else's problem and
        // must not be rewritten into a misleading explanation.
        let other = std::io::Error::other("disk on fire");
        assert_eq!(
            explain_dump_failure(CaptureHost::Local, other).to_string(),
            "disk on fire"
        );
    }

    #[test]
    fn buffer_scrolls_and_returns_to_latest_output() {
        let mut buffer = Buffer::new();
        for n in 1..=5 {
            buffer.push(n.to_string());
        }

        assert_eq!(buffer.visible(2), ["4", "5"]);
        buffer.scroll_up(2);
        assert_eq!(buffer.visible(2), ["2", "3"]);
        buffer.follow();
        assert_eq!(buffer.visible(2), ["4", "5"]);
    }

    #[test]
    fn paused_buffer_stays_put_until_live_follow_is_restored() {
        let mut buffer = Buffer::new();
        for n in 1..=5 {
            buffer.push(n.to_string());
        }

        assert_eq!(buffer.visible(2), ["4", "5"]);
        buffer.scroll_up(2);
        buffer.push("6".into());
        assert_eq!(buffer.visible(2), ["2", "3"]);

        buffer.push_output("7".into(), true);
        assert!(buffer.auto_follow);
        assert_eq!(buffer.visible(2), ["6", "7"]);
    }

    #[test]
    fn live_follow_can_be_paused_while_at_the_bottom() {
        let mut buffer = Buffer::new();
        for n in 1..=5 {
            buffer.push(n.to_string());
        }

        assert_eq!(buffer.visible(2), ["4", "5"]);
        buffer.toggle_follow();
        buffer.push("6".into());
        assert!(!buffer.auto_follow);
        assert_eq!(buffer.visible(2), ["4", "5"]);
    }

    #[test]
    fn buffer_does_not_scroll_until_it_overflows_the_pane() {
        let mut buffer = Buffer::new();
        buffer.push("first".into());
        buffer.push("second".into());

        assert_eq!(buffer.visible(4), ["first", "second"]);
        buffer.scroll_up(5);
        assert_eq!(buffer.from_bottom, 0);
        assert_eq!(buffer.visible(4), ["first", "second"]);
    }

    #[test]
    fn buffer_clear_removes_scrollback() {
        let mut buffer = Buffer::new();
        buffer.push("packet".into());
        buffer.clear();
        assert!(buffer.visible(10).is_empty());
    }

    #[test]
    fn shutdown_signal_requests_clean_ui_exit() {
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
        request_shutdown(libc::SIGTERM);
        assert!(SHUTDOWN_REQUESTED.load(Ordering::Relaxed));
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    }
}

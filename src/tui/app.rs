// The lab's state, and everything that changes it.
//
// `Lab` owns the three panes, the two child processes, and the status line.
// Output arrives from background reader threads over a channel rather than
// being polled, so a chatty stack cannot stall the UI; `drain_msgs` is where
// those messages become pane content.

use std::io::{BufRead, BufReader};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::{Config, Transport};

use super::buffer::Buffer;
use super::child::{CaptureHost, ChildProc, DumpFilter, spawn_dump_with_retry};

pub(super) const SHORT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Pane {
    Stack,
    Dump,
    Actions,
}

impl Pane {
    pub(super) fn next(self) -> Self {
        match self {
            Self::Stack => Self::Dump,
            Self::Dump => Self::Actions,
            Self::Actions => Self::Stack,
        }
    }
}

/// One line of output, from wherever it came from.
///
/// Children are read on background threads and their output arrives here, so
/// the UI never blocks waiting on a process. `StackStatus` is separate from
/// `Stack` because the stack's stderr is minitcp talking about itself and gets
/// coloured differently from the protocol trace on stdout.
pub(super) enum Msg {
    Stack(String),
    StackStatus(String),
    Dump(String),
    Action(String),
}

pub(super) struct Lab {
    pub(super) focus: Pane,
    pub(super) filter: DumpFilter,
    /// Which machine runs tcpdump for the capture pane. Fixed for the life of
    /// the lab, because the transport it is derived from is too.
    pub(super) capture: CaptureHost,
    pub(super) stack_buf: Buffer,
    pub(super) dump_buf: Buffer,
    pub(super) action_buf: Buffer,
    pub(super) stack: ChildProc,
    pub(super) dump: ChildProc,
    pub(super) rx: Receiver<Msg>,
    pub(super) tx: Sender<Msg>,
    pub(super) last_status: Instant,
    pub(super) tap_up: bool,
    pub(super) tap_addr: String,
    pub(super) stack_alive: bool,
    pub(super) dump_alive: bool,
    pub(super) action_process: Option<ChildProc>,
    pub(super) command_input: Option<String>,
    pub(super) verbose: bool,
    pub(super) cfg: Config,
    pub(super) icmp_in: u32,
    pub(super) icmp_out: u32,
    pub(super) arp_in: u32,
    pub(super) arp_out: u32,
}

/// Report whether the local TAP is there, without touching it.
///
/// Opening the lab deliberately does *not* create the TAP. Bringing up a
/// virtual network device is a real change to the machine — it needs root, and
/// it outlives the program that made it — so it stays an explicit thing the
/// user asks for with `minitcp tap up`. It is also the step worth
/// understanding: a lab that quietly conjures its own wire teaches nothing
/// about where the wire came from.
pub(super) fn report_tap_status(cfg: &Config, tx: &Sender<Msg>) {
    if !cfg.tun.exists() {
        let _ = tx.send(Msg::Action(format!(
            "minitcp: error: {} is missing; run in the Dev Container or a privileged Linux container.",
            cfg.tun.display()
        )));
        return;
    }

    if crate::sys::tapdev::iface_exists(&cfg.iface) {
        let _ = tx.send(Msg::Action(format!("attached to {}", cfg.iface)));
    } else {
        let _ = tx.send(Msg::Action(format!(
            "minitcp: error: {} does not exist. Run `minitcp tap up` in another terminal, then press r.",
            cfg.iface
        )));
    }
}

pub(super) fn pump_reader<R: std::io::Read + Send + 'static>(
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

pub(super) fn attach_child(
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

pub(super) fn tap_status(iface: &str, linux_addr: &str) -> (bool, String) {
    let up = crate::sys::tapdev::iface_exists(iface);
    if !up {
        return (false, "down".into());
    }
    let out = crate::sys::process::output_timeout(
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

pub(super) fn run_short(tx: &Sender<Msg>, program: &str, args: &[&str]) {
    let shown = format!("$ {program} {}", args.join(" "));
    let _ = tx.send(Msg::Action(shown));
    match crate::sys::process::output_timeout(program, args, SHORT_COMMAND_TIMEOUT) {
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
    pub(super) fn start(mut cfg: Config) -> std::io::Result<Self> {
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

    pub(super) fn toggle_verbose(&mut self) {
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

    pub(super) fn restart_stack(&mut self) {
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

    pub(super) fn restart_dump(&mut self) {
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

    pub(super) fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.restart_dump();
    }

    pub(super) fn clear_focused(&mut self) {
        match self.focus {
            Pane::Stack => self.stack_buf.clear(),
            Pane::Dump => self.dump_buf.clear(),
            Pane::Actions => self.action_buf.clear(),
        }
    }

    pub(super) fn run_command(&mut self, command: String) {
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

    pub(super) fn focused_buf_mut(&mut self) -> &mut Buffer {
        match self.focus {
            Pane::Stack => &mut self.stack_buf,
            Pane::Dump => &mut self.dump_buf,
            Pane::Actions => &mut self.action_buf,
        }
    }

    pub(super) fn push_pane(&mut self, pane: Pane, line: String) {
        let force_follow = self.focus != pane;
        match pane {
            Pane::Stack => self.stack_buf.push_output(line, force_follow),
            Pane::Dump => self.dump_buf.push_output(line, force_follow),
            Pane::Actions => self.action_buf.push_output(line, force_follow),
        }
    }

    pub(super) fn count_stack_line(&mut self, line: &str) {
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

    pub(super) fn drain_msgs(&mut self) {
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

    pub(super) fn refresh_status(&mut self) {
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
}

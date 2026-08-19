// Terminal UI. The protocol implementation lives outside this folder.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::cli::Config;
use crate::interface::fwd::DEFAULT_FWD;
use crate::tapcmd::CONTAINER;

const MAX_LINES: usize = 2000;

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

    fn title(self, iface: &str) -> String {
        match self {
            Self::All => format!("tcpdump -eni {iface} -l"),
            Self::Arp => format!("tcpdump -eni {iface} -l arp"),
            Self::Ip => format!("tcpdump -eni {iface} -l ip"),
        }
    }
}

enum Msg {
    Stack(String),
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
    privileged: bool,
    command_pid: Option<i32>,
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
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let command_pid = Some(child.id() as i32);
        Ok(Self {
            child: Some(child),
            privileged: false,
            command_pid,
        })
    }

    fn spawn_dump(filter: DumpFilter, iface: &str) -> std::io::Result<Self> {
        // sudo may put tcpdump behind a monitor process. Have the shell report
        // the exact command PID before exec replaces it with tcpdump.
        let filter_arg = match filter {
            DumpFilter::All => "",
            DumpFilter::Arp => " arp",
            DumpFilter::Ip => " ip",
        };
        let script =
            format!("echo __MINITCP_DUMP_PID=$$; exec tcpdump -eni {iface} -l{filter_arg}");
        let mut cmd = Command::new("sudo");
        cmd.args(["-n", "sh", "-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let mut child = cmd.spawn()?;
        let command_pid = child.stdout.as_mut().and_then(read_dump_pid);
        Ok(Self {
            child: Some(child),
            privileged: true,
            command_pid,
        })
    }

    fn spawn_action(command: &str) -> std::io::Result<Self> {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
        let mut cmd = Command::new(shell);
        cmd.args(["-c", command])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let command_pid = Some(child.id() as i32);
        Ok(Self {
            child: Some(child),
            privileged: false,
            command_pid,
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
            Some(c) => matches!(c.try_wait(), Ok(None)),
        }
    }

    fn kill(&mut self) {
        if let Some(pid) = self.pid() {
            if self.privileged {
                // tcpdump is root-owned, so stop the exact PID it reported rather
                // than matching by command name (which could hit another capture).
                if let Some(command_pid) = self.command_pid {
                    stop_privileged(command_pid, "TERM");
                    if !wait_for_exit(command_pid, Duration::from_millis(500)) {
                        stop_privileged(command_pid, "KILL");
                        wait_for_exit(command_pid, Duration::from_millis(100));
                    }
                }
            } else {
                unsafe {
                    libc::kill(-pid, libc::SIGTERM);
                }
            }
        }
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
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

fn stop_privileged(pid: i32, signal: &str) {
    let _ = Command::new("sudo")
        .args(["-n", "kill"])
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn wait_for_exit(pid: i32, timeout: Duration) -> bool {
    let started = Instant::now();
    let process = format!("/proc/{pid}");
    while Path::new(&process).exists() && started.elapsed() < timeout {
        thread::sleep(Duration::from_millis(10));
    }
    !Path::new(&process).exists()
}

impl Drop for ChildProc {
    fn drop(&mut self) {
        self.kill();
    }
}

struct Lab {
    focus: Pane,
    filter: DumpFilter,
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

fn setup_command(tx: &Sender<Msg>, program: &str, args: &[&str]) -> bool {
    let _ = tx.send(Msg::Action(format!("$ {program} {}", args.join(" "))));
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stdout.lines().chain(stderr.lines()) {
                let _ = tx.send(Msg::Action(line.to_string()));
            }
            output.status.success()
        }
        Err(e) => {
            let _ = tx.send(Msg::Action(format!("failed: {e}")));
            false
        }
    }
}

fn ensure_tap(cfg: &Config, tx: &Sender<Msg>) {
    if !cfg.tun.exists() {
        let _ = tx.send(Msg::Action(format!(
            "{} is missing; run in the Dev Container or a privileged Linux container.",
            cfg.tun.display()
        )));
        return;
    }

    let sys = format!("/sys/class/net/{}", cfg.iface);
    if !Path::new(&sys).exists() {
        if cfg.no_create_tap {
            let _ = tx.send(Msg::Action(format!(
                "{} is missing and --no-create-tap is set",
                cfg.iface
            )));
            return;
        }
        let user = Command::new("id")
            .args(["-un"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "root".into());
        if !setup_command(
            tx,
            "sudo",
            &[
                "ip", "tuntap", "add", "dev", &cfg.iface, "mode", "tap", "user", &user,
            ],
        ) {
            return;
        }
    }

    let cidr = format!("{}/24", cfg.linux_addr);
    let has_addr = Command::new("ip")
        .args(["-4", "addr", "show", "dev", &cfg.iface])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&cidr))
        .unwrap_or(false);
    if !has_addr && !setup_command(tx, "sudo", &["ip", "addr", "add", &cidr, "dev", &cfg.iface]) {
        return;
    }
    setup_command(tx, "sudo", &["ip", "link", "set", "dev", &cfg.iface, "up"]);
}

fn pump_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    tx: Sender<Msg>,
    wrap: fn(String) -> Msg,
) {
    thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            match line {
                Ok(s) => {
                    if tx.send(wrap(s)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn attach_child(child: &mut ChildProc, tx: Sender<Msg>, wrap: fn(String) -> Msg) {
    if let Some((out, err)) = child.take_stdout_stderr() {
        pump_reader(out, tx.clone(), wrap);
        pump_reader(err, tx, wrap);
    }
}

fn tap_status(iface: &str, linux_addr: &str) -> (bool, String) {
    let up = Path::new(&format!("/sys/class/net/{iface}")).exists();
    if !up {
        return (false, "down".into());
    }
    let out = Command::new("ip")
        .args(["-br", "addr", "show", iface])
        .output()
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
    match Command::new(program).args(args).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            for line in stdout.lines().chain(stderr.lines()) {
                let _ = tx.send(Msg::Action(line.to_string()));
            }
            if stdout.is_empty() && stderr.is_empty() {
                let _ = tx.send(Msg::Action("(no output)".into()));
            }
        }
        Err(e) => {
            let _ = tx.send(Msg::Action(format!("failed: {e}")));
        }
    }
}

impl Lab {
    fn start(mut cfg: Config) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let remote = cfg.use_fwd();
        if remote && cfg.fwd.is_none() {
            cfg.fwd = Some(DEFAULT_FWD.into());
        }
        if !remote {
            ensure_tap(&cfg, &tx);
        }

        let verbose = !cfg.quiet;
        let mut stack = ChildProc::spawn_stack(&cfg, verbose)?;
        attach_child(&mut stack, tx.clone(), Msg::Stack);

        let filter = DumpFilter::All;
        let mut dump = if remote {
            let _ = tx.send(Msg::Dump(
                "TAP lives in the sidecar (`minitcp tap up`). tcpdump is not on this host.".into(),
            ));
            ChildProc {
                child: None,
                privileged: true,
                command_pid: None,
            }
        } else {
            match ChildProc::spawn_dump(filter, &cfg.iface) {
                Ok(mut d) => {
                    attach_child(&mut d, tx.clone(), Msg::Dump);
                    d
                }
                Err(e) => {
                    let _ = tx.send(Msg::Dump(format!("tcpdump not started: {e}")));
                    ChildProc {
                        child: None,
                        privileged: true,
                        command_pid: None,
                    }
                }
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
                "frames via TAP sidecar. ping 10.0.0.2 from Linux that owns tap0 (p uses docker exec)."
                    .into(),
            );
        }
        if !stack_alive {
            action_buf.push("stack failed to stay up — try minitcp tap up then r".into());
        }

        Ok(Self {
            focus: Pane::Stack,
            filter,
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
                attach_child(&mut c, self.tx.clone(), Msg::Stack);
                self.stack = c;
                self.stack_alive = true;
                self.icmp_in = 0;
                self.icmp_out = 0;
                self.arp_in = 0;
                self.arp_out = 0;
                self.push_pane(Pane::Stack, "— stack restarted —".into());
            }
            Err(e) => self.push_pane(Pane::Actions, format!("restart stack failed: {e}")),
        }
    }

    fn restart_dump(&mut self) {
        if self.cfg.fwd.is_some() {
            self.push_pane(
                Pane::Dump,
                "tcpdump is not on this host; TAP is in the sidecar.".into(),
            );
            return;
        }
        self.dump.kill();
        match ChildProc::spawn_dump(self.filter, &self.cfg.iface) {
            Ok(mut c) => {
                attach_child(&mut c, self.tx.clone(), Msg::Dump);
                self.dump = c;
                self.dump_alive = true;
                self.push_pane(
                    Pane::Dump,
                    format!("— {} —", self.filter.title(&self.cfg.iface)),
                );
            }
            Err(e) => self.push_pane(Pane::Dump, format!("tcpdump failed: {e}")),
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
                attach_child(&mut child, self.tx.clone(), Msg::Action);
                self.action_process = Some(child);
            }
            Err(e) => self.action_buf.push(format!("command failed: {e}")),
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
                self.push_pane(Pane::Stack, "— stack exited; press r to restart —".into());
            }
            if self.dump_alive && !dump_alive {
                self.push_pane(Pane::Dump, "— tcpdump exited; press t to restart —".into());
            }
            self.stack_alive = stack_alive;
            self.dump_alive = dump_alive;
            self.last_status = Instant::now();
        }

        let action_finished = self
            .action_process
            .as_mut()
            .is_some_and(|process| !process.alive());
        if action_finished {
            if let Some(mut process) = self.action_process.take() {
                process.kill();
            }
            self.push_pane(Pane::Actions, "— command finished —".into());
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
                        run_short(&tx, "sudo", &["ip", "neigh", "flush", "dev", &iface]);
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
    render_term(
        frame,
        top[1],
        "2 TAP Capture",
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
    let mut lab = Lab::start(cfg)?;
    let mut terminal = ratatui::init();
    let result = ui_loop(&mut terminal, &mut lab);
    ratatui::restore();
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
}

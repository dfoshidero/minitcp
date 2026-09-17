// src/log.rs
//
// Quiet:  23:12:05  icmp  10.0.0.1 -> 10.0.0.2  echo id=1 seq=1  len=64
// Verbose first line:
//   23:12:05  [IN]   ethernet  L2  02:00:… -> 02:00:…  ethertype 0x0800
// IPv4/ARP [..] keep src -> dst. ICMP/TCP/UDP sit under IPv4 (they are its payload).

use std::fmt::Display;
use std::io::{self, IsTerminal, Write};
use std::sync::Mutex;

use crossterm::style::Stylize;

use minitcp::event::{Endpoints, Layer, Outcome, Scope, Step};
use minitcp::proto::ipv4::Protocol;

static OUTPUT_ERROR: Mutex<Option<io::Error>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verb {
    In,
    Out,
    Drop,
    More,
}

impl Verb {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::In => "IN",
            Self::Out => "OUT",
            Self::Drop => "DROP",
            Self::More => "..",
        }
    }
}

struct Event<'a> {
    show_time: bool,
    verb: Verb,
    layer: &'a str,
    osi: &'a str,
    address: &'a str,
    reason: &'a str,
}

impl<'a> Event<'a> {
    fn format_with(&self, when: &str) -> String {
        let when_col = if self.show_time {
            when.to_string()
        } else {
            " ".repeat(when.len())
        };
        let verb = format!("[{}]", self.verb.as_str());
        let detail = if self.address.is_empty() {
            self.reason.to_string()
        } else if self.reason.is_empty() {
            self.address.to_string()
        } else {
            format!("{}  {}", self.address, self.reason)
        };
        format!(
            "{when_col}  {verb:<6}  {:<8}  {}  {detail}",
            self.layer, self.osi,
        )
    }

    fn emit_at(&self, when: &str) {
        emit_protocol_line(&self.format_with(when));
    }
}

/// Wall-clock "HH:MM:SS" stamp that opens each protocol line.
pub(crate) fn now() -> String {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        libc::localtime_r(&ts.tv_sec, &mut tm);
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// One-line quiet summary: time, layer, addresses, reason. No IN/OUT.
fn format_quiet(when: &str, layer: &str, address: &str, reason: &str) -> String {
    format!("{when}  {layer}  {address}  {reason}")
}

pub(crate) fn emit_quiet(when: &str, layer: &str, address: &str, reason: &str) {
    emit_protocol_line(&format_quiet(when, layer, address, reason));
}

pub(crate) fn emit_at(when: &str, verb: Verb, layer: &str, osi: &str, address: &str, reason: &str) {
    Event {
        show_time: true,
        verb,
        layer,
        osi,
        address,
        reason,
    }
    .emit_at(when);
}

pub(crate) fn emit_cont(
    when: &str,
    verb: Verb,
    layer: &str,
    osi: &str,
    address: &str,
    reason: &str,
) {
    Event {
        show_time: false,
        verb,
        layer,
        osi,
        address,
        reason,
    }
    .emit_at(when);
}

/// Protocol carried inside IPv4 (ICMP, UDP, TCP). Tree-child of the ipv4 line.
pub(crate) fn emit_inside(when: &str, verb: Verb, layer: &str, osi: &str, reason: &str) {
    let layer = format!("└── {layer}");
    Event {
        show_time: false,
        verb,
        layer: &layer,
        osi,
        address: "",
        reason,
    }
    .emit_at(when);
}

// ---------------------------------------------------------------------------
// Rendering an Outcome
//
// `Stack::handle` decides; this decides how it looks. Verbose prints one line
// per layer, indented under the packet that carried it. Quiet prints one line
// per completed exchange, plus anything that was dropped.
// ---------------------------------------------------------------------------

/// "source -> destination", for either MACs (L2) or IPv4 addresses (L3).
pub(crate) fn pair(src: impl Display, dst: impl Display) -> String {
    format!("{src} -> {dst}")
}

fn endpoints<T: Display + Copy>(ends: Option<Endpoints<T>>) -> String {
    ends.map(|e| pair(e.source, e.destination))
        .unwrap_or_default()
}

fn protocol_name(protocol: Protocol) -> String {
    match protocol {
        Protocol::Icmp => "icmp".into(),
        Protocol::Udp => "udp".into(),
        Protocol::Tcp => "tcp".into(),
        Protocol::Unknown(n) => format!("protocol {n}"),
    }
}

fn icmp_detail(kind: u8, code: u8, echo: Option<minitcp::event::Echo>, len: usize) -> String {
    match echo {
        None => "truncated".into(),
        Some(e) => format!(
            "type={kind} code={code} id={} seq={}  len={len}",
            e.id, e.sequence
        ),
    }
}

pub(crate) fn render(when: &str, outcome: &Outcome, verbose: bool) {
    if verbose {
        render_verbose(when, outcome);
    } else {
        render_quiet(when, outcome);
    }
}

/// Only the first line of a frame carries the clock; the rest hang under it.
fn emit_line(
    first: &mut bool,
    when: &str,
    verb: Verb,
    layer: &str,
    osi: &str,
    addr: &str,
    detail: &str,
) {
    if *first {
        emit_at(when, verb, layer, osi, addr, detail);
        *first = false;
    } else {
        emit_cont(when, verb, layer, osi, addr, detail);
    }
}

fn render_verbose(when: &str, outcome: &Outcome) {
    let mut first = true;
    for step in &outcome.steps {
        match step {
            Step::In(layer) => render_layer(when, &mut first, layer, false),
            Step::Out(layer) => render_layer(when, &mut first, layer, true),
            Step::Drop(dropped) => match dropped.scope {
                // Already sits under an ipv4 line that showed the addresses.
                Scope::Payload => {
                    emit_inside(
                        when,
                        Verb::Drop,
                        dropped.layer,
                        dropped.osi,
                        &dropped.reason.to_string(),
                    );
                    first = false;
                }
                Scope::Network => emit_line(
                    &mut first,
                    when,
                    Verb::Drop,
                    dropped.layer,
                    dropped.osi,
                    "",
                    &dropped.reason.to_string(),
                ),
                Scope::Link => emit_line(
                    &mut first,
                    when,
                    Verb::Drop,
                    dropped.layer,
                    dropped.osi,
                    &endpoints(outcome.link),
                    &dropped.reason.to_string(),
                ),
            },
        }
    }
}

fn render_layer(when: &str, first: &mut bool, layer: &Layer, outbound: bool) {
    match *layer {
        Layer::Ethernet {
            source,
            destination,
            ethertype,
        } => {
            let verb = if outbound { Verb::Out } else { Verb::In };
            emit_line(
                first,
                when,
                verb,
                "ethernet",
                "L2",
                &pair(source, destination),
                &format!("ethertype 0x{ethertype:04x}"),
            );
        }
        Layer::Arp {
            addresses,
            sender_mac,
            ..
        } => {
            let detail = match sender_mac {
                Some(mac) => format!("is-at {mac}"),
                None => "who-has".into(),
            };
            emit_line(
                first,
                when,
                Verb::More,
                "arp",
                "L2",
                &endpoints(addresses),
                &detail,
            );
        }
        Layer::Ipv4 {
            source,
            destination,
            ttl,
            protocol,
            payload_len,
        } => emit_line(
            first,
            when,
            Verb::More,
            "ipv4",
            "L3",
            &pair(source, destination),
            &format!(
                "ttl={ttl} proto={} payload={payload_len}",
                protocol_name(protocol)
            ),
        ),
        // ICMP is IPv4's payload, so it is drawn as a child of the ipv4 line.
        Layer::Icmp {
            kind,
            code,
            echo,
            len,
        } => {
            emit_inside(
                when,
                Verb::More,
                "icmp",
                "L3",
                &icmp_detail(kind, code, echo, len),
            );
            *first = false;
        }
    }
}

fn render_quiet(when: &str, outcome: &Outcome) {
    for step in &outcome.steps {
        if let Step::Drop(dropped) = step {
            let addr = match dropped.scope {
                Scope::Link => endpoints(outcome.link),
                Scope::Network | Scope::Payload => endpoints(outcome.network),
            };
            emit_at(
                when,
                Verb::Drop,
                dropped.layer,
                dropped.osi,
                &addr,
                &dropped.reason.to_string(),
            );
        }
    }

    // Quiet mode reports exchanges, not packets: one line when we answered.
    if outcome.reply.is_none() {
        return;
    }
    if let Some(Layer::Arp { addresses, .. }) = outcome.inbound(|l| matches!(l, Layer::Arp { .. }))
    {
        emit_quiet(when, "arp", &endpoints(*addresses), "who-has");
    } else if let Some(Layer::Icmp { echo, len, .. }) =
        outcome.inbound(|l| matches!(l, Layer::Icmp { .. }))
    {
        let (id, seq) = echo.map(|e| (e.id, e.sequence)).unwrap_or((0, 0));
        emit_quiet(
            when,
            "icmp",
            &endpoints(outcome.network),
            &format!("echo id={id} seq={seq}  len={len}"),
        );
    }
}

fn write_line(writer: &mut impl Write, line: &str) -> io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn emit_protocol_line(line: &str) {
    let stdout = io::stdout();
    if let Err(error) = write_line(&mut stdout.lock(), line)
        && let Ok(mut stored) = OUTPUT_ERROR.lock()
        && stored.is_none()
    {
        *stored = Some(error);
    }
}

pub(crate) fn take_output_error() -> Option<io::Error> {
    OUTPUT_ERROR.lock().ok()?.take()
}

pub(crate) fn write_stdout(text: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()
}

pub(crate) fn write_stderr(text: &str) -> io::Result<()> {
    let stderr = io::stderr();
    let mut stderr = stderr.lock();
    stderr.write_all(text.as_bytes())?;
    stderr.flush()
}

pub(crate) mod status {
    use super::*;

    #[derive(Clone, Copy)]
    enum Level {
        Info,
        Ok,
        Warn,
        Error,
    }

    fn format_line(level: Level, message: &str) -> String {
        match level {
            Level::Info | Level::Ok => format!("minitcp: {message}"),
            Level::Warn => format!("minitcp: warning: {message}"),
            Level::Error => format!("minitcp: error: {message}"),
        }
    }

    fn emit(level: Level, message: &str) {
        let line = format_line(level, message);
        let stderr = io::stderr();
        let color = stderr.is_terminal();
        let rendered = if color {
            match level {
                Level::Info => line,
                Level::Ok => line.green().to_string(),
                Level::Warn => line.yellow().to_string(),
                Level::Error => line.red().to_string(),
            }
        } else {
            line
        };
        let _ = write_line(&mut stderr.lock(), &rendered);
    }

    pub(crate) fn info(message: impl AsRef<str>) {
        emit(Level::Info, message.as_ref());
    }

    pub(crate) fn ok(message: impl AsRef<str>) {
        emit(Level::Ok, message.as_ref());
    }

    pub(crate) fn warn(message: impl AsRef<str>) {
        emit(Level::Warn, message.as_ref());
    }

    pub(crate) fn error(message: impl AsRef<str>) {
        emit(Level::Error, message.as_ref());
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn status_lines_have_stable_plain_prefixes() {
            assert_eq!(format_line(Level::Info, "ready"), "minitcp: ready");
            assert_eq!(format_line(Level::Ok, "ready"), "minitcp: ready");
            assert_eq!(
                format_line(Level::Warn, "retrying"),
                "minitcp: warning: retrying"
            );
            assert_eq!(
                format_line(Level::Error, "failed"),
                "minitcp: error: failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_line_is_one_row() {
        assert_eq!(
            format_quiet(
                "23:12:05",
                "icmp",
                "10.0.0.1 -> 10.0.0.2",
                "echo id=1 seq=1  len=64"
            ),
            "23:12:05  icmp  10.0.0.1 -> 10.0.0.2  echo id=1 seq=1  len=64"
        );
    }

    #[test]
    fn verbose_in_keeps_address() {
        let line = Event {
            show_time: true,
            verb: Verb::In,
            layer: "ethernet",
            osi: "L2",
            address: "02:00:00:00:00:01 -> 02:00:00:00:00:02",
            reason: "ethertype 0x0800",
        }
        .format_with("23:12:05");
        assert_eq!(
            line,
            "23:12:05  [IN]    ethernet  L2  02:00:00:00:00:01 -> 02:00:00:00:00:02  ethertype 0x0800"
        );
    }

    #[test]
    fn verbose_ipv4_has_no_address_gap() {
        let line = Event {
            show_time: false,
            verb: Verb::More,
            layer: "ipv4",
            osi: "L3",
            address: "10.0.0.1 -> 10.0.0.2",
            reason: "ttl=64 proto=icmp payload=64",
        }
        .format_with("23:12:05");
        assert_eq!(
            line,
            "          [..]    ipv4      L3  10.0.0.1 -> 10.0.0.2  ttl=64 proto=icmp payload=64"
        );
    }

    #[test]
    fn verbose_icmp_sits_inside_ipv4() {
        let line = Event {
            show_time: false,
            verb: Verb::More,
            layer: "└── icmp",
            osi: "L3",
            address: "",
            reason: "type=8 code=0 id=1 seq=1  len=64",
        }
        .format_with("23:12:05");
        assert_eq!(
            line,
            "          [..]    └── icmp  L3  type=8 code=0 id=1 seq=1  len=64"
        );
    }

    #[cfg(unix)]
    #[test]
    fn writing_to_closed_pipe_returns_broken_pipe() {
        use std::os::unix::net::UnixStream;

        let (mut writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        let error = write_line(&mut writer, "protocol line").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}

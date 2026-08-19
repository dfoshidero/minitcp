// src/log.rs
//
// Quiet:  23:12:05  icmp  10.0.0.1 -> 10.0.0.2  echo id=1 seq=1  len=64
// Verbose first line:
//   23:12:05  [IN]   ethernet  L2  02:00:… -> 02:00:…  ethertype 0x0800
// IPv4/ARP [..] keep src -> dst. ICMP/TCP/UDP sit under IPv4 (they are its payload).

use std::io::{self, IsTerminal, Write};
use std::sync::Mutex;

use crossterm::style::Stylize;

static OUTPUT_ERROR: Mutex<Option<io::Error>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    In,
    Out,
    Drop,
    More,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::In => "IN",
            Self::Out => "OUT",
            Self::Drop => "DROP",
            Self::More => "..",
        }
    }
}

pub struct Event<'a> {
    pub show_time: bool,
    pub verb: Verb,
    pub layer: &'a str,
    pub osi: &'a str,
    pub address: &'a str,
    pub reason: &'a str,
}

impl<'a> Event<'a> {
    pub fn format_with(&self, when: &str) -> String {
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

    pub fn emit_at(&self, when: &str) {
        emit_protocol_line(&self.format_with(when));
    }
}

pub fn now() -> String {
    timestamp()
}

/// One-line quiet summary: time, layer, addresses, reason. No IN/OUT.
pub fn format_quiet(when: &str, layer: &str, address: &str, reason: &str) -> String {
    format!("{when}  {layer}  {address}  {reason}")
}

pub fn emit_quiet(when: &str, layer: &str, address: &str, reason: &str) {
    emit_protocol_line(&format_quiet(when, layer, address, reason));
}

pub fn emit_at(when: &str, verb: Verb, layer: &str, osi: &str, address: &str, reason: &str) {
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

pub fn emit_cont(when: &str, verb: Verb, layer: &str, osi: &str, address: &str, reason: &str) {
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
pub fn emit_inside(when: &str, verb: Verb, layer: &str, osi: &str, reason: &str) {
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

pub fn take_output_error() -> Option<io::Error> {
    OUTPUT_ERROR.lock().ok()?.take()
}

pub fn write_stdout(text: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()
}

pub fn write_stderr(text: &str) -> io::Result<()> {
    let stderr = io::stderr();
    let mut stderr = stderr.lock();
    stderr.write_all(text.as_bytes())?;
    stderr.flush()
}

pub mod status {
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

    pub fn info(message: impl AsRef<str>) {
        emit(Level::Info, message.as_ref());
    }

    pub fn ok(message: impl AsRef<str>) {
        emit(Level::Ok, message.as_ref());
    }

    pub fn warn(message: impl AsRef<str>) {
        emit(Level::Warn, message.as_ref());
    }

    pub fn error(message: impl AsRef<str>) {
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

fn timestamp() -> String {
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

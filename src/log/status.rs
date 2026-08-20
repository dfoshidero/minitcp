//! Messages from minitcp about itself, as opposed to about the network.
//!
//! These always go to stderr, never stdout. Protocol output is the program's
//! actual result — the thing you would pipe into a file — and mixing "TAP
//! sidecar up" into it would corrupt that. Colour is added only when stderr is a
//! terminal, so redirecting to a file gives plain text.

use std::io::{self, IsTerminal};

use crossterm::style::Stylize;

use super::write_line;

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

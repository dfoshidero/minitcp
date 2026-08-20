//! Writing things out.
//!
//!   trace   the frame-by-frame protocol narration, on stdout
//!   status  minitcp talking about itself, on stderr
//!
//! stdout is the result, stderr is commentary, so `minitcp stack > run.log`
//! gives a clean log and still shows problems. A broken pipe on stdout is normal
//! (`| head`), so protocol writes stash their error here rather than panic.

pub mod status;
pub mod trace;

use std::io::{self, Write};
use std::sync::Mutex;

pub use trace::{Verb, emit_at, emit_cont, emit_inside, emit_quiet};

static OUTPUT_ERROR: Mutex<Option<io::Error>> = Mutex::new(None);

fn write_line(writer: &mut impl Write, line: &str) -> io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub(super) fn emit_protocol_line(line: &str) {
    let stdout = io::stdout();
    if let Err(error) = write_line(&mut stdout.lock(), line)
        && let Ok(mut stored) = OUTPUT_ERROR.lock()
        && stored.is_none()
    {
        *stored = Some(error);
    }
}

/// Hand back the first output error since the last call, if any.
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

/// Wall-clock time as HH:MM:SS, local. libc rather than a date crate — this is
/// the only time formatting minitcp does.
pub(crate) fn timestamp() -> String {
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

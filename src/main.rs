// minitcp — a userspace TCP/IP stack you can watch work.
//
//   cli        the command line and minitcp.toml
//   dispatch   which command runs what
//   proto      wire formats: Ethernet, ARP, IPv4, ICMP
//   stack      the loop that answers frames
//   interface  what carries frames: TAP, sidecar, pcap, hex
//   sys        this machine: processes, the TAP device, Docker
//   log        protocol tracing and status messages
//   tui        the terminal UI
//   release    the update check

mod cli;
mod dispatch;
mod interface;
mod log;
mod proto;
mod release;
mod stack;
mod sys;
mod tui;

/// Why minitcp is about to exit non-zero.
///
/// The three cases exist because they mean different things to whoever ran the
/// command: a usage error is the command line's fault and exits 2, a config
/// error is the file's fault, and a runtime error is the world's. A broken pipe
/// is deliberately none of them — `minitcp stack | head` is a normal way to use
/// the tool and must not look like a failure.
enum AppError {
    Usage(cli::ParseError),
    Config(cli::ParseError),
    Runtime(std::io::Error),
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::Runtime(error)
    }
}

fn main() {
    let code = match dispatch::run() {
        Ok(()) => 0,
        Err(AppError::Usage(error)) => {
            let _ = log::write_stderr(&error.to_string());
            2
        }
        Err(AppError::Config(error)) => {
            let _ = log::write_stderr(&error.to_string());
            1
        }
        Err(AppError::Runtime(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => 0,
        Err(AppError::Runtime(error)) => {
            log::status::error(error.to_string());
            1
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

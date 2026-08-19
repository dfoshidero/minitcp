//! Wiring the stack to something that carries frames.
//!
//! Which carrier that is — a TAP on this machine, the sidecar over TCP, a pcap
//! file, hex on stdin — is decided here and nowhere else. Once chosen, the loop
//! is identical: read a frame, hand it to `handle_frame`, write back whatever
//! comes out. `open_tap` is the fiddly part, because attaching to a device that
//! was created moments ago can briefly fail for reasons that fix themselves.

use std::io::{self, BufReader};
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::cli::{Command, Config};
use crate::interface::capture::CaptureIo;
use crate::interface::hex::HexReader;
use crate::interface::pcap::{PcapReader, PcapWriter};
use crate::interface::tap::TapInterface;
use crate::interface::{FrameIo, FrameSink, FrameSource, ReadOnly};
use crate::log;

use super::handle::handle_frame;
use super::rng::SeededRng;

fn open_tap(cfg: &Config) -> io::Result<TapInterface> {
    if !cfg.tun.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cannot open {}; reopen this folder in the Dev Container",
                cfg.tun.display()
            ),
        ));
    }

    let sys = format!("/sys/class/net/{}", cfg.iface);
    if !Path::new(&sys).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is not up yet; try `minitcp tap up`", cfg.iface),
        ));
    }

    const ATTEMPTS: usize = 5;
    for attempt in 1..=ATTEMPTS {
        match TapInterface::open_at(&cfg.tun, &cfg.iface) {
            Ok(tap) => return Ok(tap),
            Err(error) if attempt < ATTEMPTS && retryable_tap_attach(&error) => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "cannot attach to {}; try `minitcp tap up`: {error}",
                        cfg.iface
                    ),
                ));
            }
        }
    }
    Err(io::Error::other("TAP attach retry loop ended unexpectedly"))
}

fn retryable_tap_attach(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || matches!(error.raw_os_error(), Some(libc::ENODEV) | Some(libc::EBUSY))
}

pub fn run_bridge(cfg: Config) -> std::io::Result<()> {
    crate::sys::tapdev::ensure_iface(&cfg.iface, cfg.linux_addr)?;
    let tap = open_tap(&cfg)?;
    crate::interface::fwd::run_bridge(&cfg.listen, tap)
}

pub fn run_stack(cfg: Config) -> std::io::Result<()> {
    if let Command::Replay(path) = &cfg.command {
        let reader = PcapReader::open(path)?;
        return run_io(cfg, ReadOnly(reader), EofBehavior::Success);
    }
    if cfg.hex {
        return run_io(
            cfg,
            ReadOnly(HexReader::new(BufReader::new(io::stdin()))),
            EofBehavior::Success,
        );
    }
    match cfg.transport() {
        crate::cli::Transport::Forwarded(addr) => {
            let frames = crate::interface::fwd::TcpFrames::connect(&addr).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot connect to TAP sidecar at {addr}; try `minitcp tap up`: {error}"
                    ),
                )
            })?;
            log::status::info(format!(
                "listening {} via {addr} as {} ({})",
                cfg.iface, cfg.addr, cfg.mac
            ));
            run_io(cfg, frames, EofBehavior::Failure)
        }
        crate::cli::Transport::LocalTap => {
            let tap = open_tap(&cfg)?;
            log::status::info(format!(
                "listening {} as {} ({})",
                cfg.iface, cfg.addr, cfg.mac
            ));
            run_io(cfg, tap, EofBehavior::Failure)
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum EofBehavior {
    Success,
    Failure,
}

pub(super) fn run_io<I: FrameIo>(
    cfg: Config,
    inner: I,
    eof_behavior: EofBehavior,
) -> std::io::Result<()> {
    let capture = match &cfg.write {
        Some(path) => Some(PcapWriter::create(path)?),
        None => None,
    };
    let mut frames = CaptureIo::new(inner, capture);
    let mut buffer = [0u8; 2048];
    let mut rng = SeededRng::from_entropy();
    let mut seen = 0u64;
    let _ = log::take_output_error();
    loop {
        if let Some(limit) = cfg.count
            && seen >= limit
        {
            return Ok(());
        }
        let n = frames.read_frame(&mut buffer).map_err(|error| {
            io::Error::new(error.kind(), format!("cannot read next frame: {error}"))
        })?;
        if n == 0 {
            return match eof_behavior {
                EofBehavior::Success => Ok(()),
                EofBehavior::Failure => Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "frame source closed unexpectedly",
                )),
            };
        }
        seen += 1;
        if let Some(reply) = handle_frame(&cfg, &buffer[..n], &mut rng) {
            frames.write_frame(&reply).map_err(|error| {
                io::Error::new(error.kind(), format!("cannot write reply frame: {error}"))
            })?;
        }
        // A closed stdout ends the run. `main` decides what that means for the
        // exit code — a broken pipe is `minitcp stack | head`, not a failure.
        if let Some(error) = log::take_output_error() {
            return Err(io::Error::new(
                error.kind(),
                format!("cannot write protocol output: {error}"),
            ));
        }
    }
}

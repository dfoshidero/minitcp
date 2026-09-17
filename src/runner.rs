// src/runner.rs
//
// Drives the library stack: pick a frame source, feed each frame to
// `minitcp::stack::Stack`, render what came back, write any reply.

use std::io::{self, BufReader};
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::cli::{Command, Config};
use crate::log;
use minitcp::interface::FrameIo;
use minitcp::interface::pcap::{CaptureIo, HexReader, PcapReader, PcapWriter};
use minitcp::interface::tap::TapInterface;
use minitcp::stack::Stack;

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

pub(crate) fn run_bridge(cfg: Config) -> std::io::Result<()> {
    crate::tapcmd::ensure_iface(&cfg.iface, cfg.linux_addr)?;
    let tap = open_tap(&cfg)?;
    crate::fwd::run_bridge(&cfg.listen, tap)
}

pub(crate) fn run_stack(cfg: Config) -> std::io::Result<()> {
    if let Command::Replay(path) = &cfg.command {
        let reader = PcapReader::open(path)?;
        return run_io(cfg, reader, EofBehavior::Success);
    }
    if cfg.hex {
        return run_io(
            cfg,
            HexReader::new(BufReader::new(io::stdin())),
            EofBehavior::Success,
        );
    }
    if cfg.use_fwd() {
        let addr = cfg.fwd_addr();
        let frames = crate::fwd::TcpFrames::connect(&addr).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot connect to TAP sidecar at {addr}; try `minitcp tap up`: {error}"),
            )
        })?;
        log::status::info(format!(
            "listening {} via {addr} as {} ({})",
            cfg.iface, cfg.addr, cfg.mac
        ));
        return run_io(cfg, frames, EofBehavior::Failure);
    }
    let tap = open_tap(&cfg)?;
    log::status::info(format!(
        "listening {} as {} ({})",
        cfg.iface, cfg.addr, cfg.mac
    ));
    run_io(cfg, tap, EofBehavior::Failure)
}

#[derive(Clone, Copy)]
enum EofBehavior {
    Success,
    Failure,
}

fn run_io<I: FrameIo>(cfg: Config, inner: I, eof_behavior: EofBehavior) -> std::io::Result<()> {
    let capture = match &cfg.write {
        Some(path) => Some(PcapWriter::create(path)?),
        None => None,
    };
    let mut frames = CaptureIo::new(inner, capture);
    let mut buffer = [0u8; 2048];
    let mut stack = Stack::new(cfg.stack_config());
    let verbose = cfg.verbose();
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
        let outcome = stack.handle(&buffer[..n]);
        log::render(&log::now(), &outcome, verbose);
        if let Some(reply) = outcome.reply {
            frames.write_frame(&reply).map_err(|error| {
                io::Error::new(error.kind(), format!("cannot write reply frame: {error}"))
            })?;
        }
        if let Some(error) = log::take_output_error() {
            if error.kind() == io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(io::Error::new(
                error.kind(),
                format!("cannot write protocol output: {error}"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minitcp::interface::pcap::pcap_info;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ARP_REQUEST: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];

    struct MockIo {
        reads: Rc<RefCell<VecDeque<Vec<u8>>>>,
        writes: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl FrameIo for MockIo {
        fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.reads.borrow_mut().pop_front() {
                None => Ok(0),
                Some(frame) => {
                    buffer[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
            }
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            self.writes.borrow_mut().push(frame.to_vec());
            Ok(())
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("minitcp-{name}-{n}.pcap"))
    }

    #[test]
    fn count_stops_before_extra_reads() {
        let mut cfg = Config::defaults();
        cfg.count = Some(2);
        let reads = Rc::new(RefCell::new(VecDeque::from([
            ARP_REQUEST.to_vec(),
            ARP_REQUEST.to_vec(),
            ARP_REQUEST.to_vec(),
        ])));
        let writes = Rc::new(RefCell::new(Vec::new()));
        let io = MockIo {
            reads: reads.clone(),
            writes: writes.clone(),
        };
        run_io(cfg, io, EofBehavior::Success).unwrap();
        assert_eq!(writes.borrow().len(), 2);
        assert_eq!(reads.borrow().len(), 1);
    }

    #[test]
    fn unexpected_live_eof_is_a_runtime_failure() {
        let io = MockIo {
            reads: Rc::new(RefCell::new(VecDeque::new())),
            writes: Rc::new(RefCell::new(Vec::new())),
        };
        let error = run_io(Config::defaults(), io, EofBehavior::Failure).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(error.to_string().contains("closed unexpectedly"), "{error}");
    }

    #[test]
    fn pcap_write_replay_roundtrip_through_reader() {
        let path = tmp("round");
        {
            let mut w = PcapWriter::create(&path).unwrap();
            w.write_frame(&ARP_REQUEST).unwrap();
        }
        let mut r = PcapReader::open(&path).unwrap();
        let mut buf = [0u8; 2048];
        let n = r.read_frame(&mut buf).unwrap();
        assert_eq!(&buf[..n], &ARP_REQUEST);
        let info = pcap_info(&path).unwrap();
        assert!(info.contains("0x0806"));
        assert!(info.contains("1 frames"));
        let _ = fs::remove_file(path);
    }
}

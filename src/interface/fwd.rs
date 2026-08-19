// Length-prefixed Ethernet frames over TCP (TAP sidecar <-> host stack).

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use super::tap::TapInterface;
use super::{FrameSink, FrameSource};

/// Where the host stack looks for the bridge.
pub const DEFAULT_FWD: &str = "127.0.0.1:7946";

/// Where the bridge listens unless told otherwise.
///
/// Loopback, deliberately: this socket hands out raw Ethernet frames with no
/// authentication, so anyone who can connect can inject onto the link and read
/// everything crossing it. The sidecar overrides it with `0.0.0.0` because the
/// `docker run` line publishes the port on 127.0.0.1 only, making the
/// container's namespace the boundary.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7946";

const CONNECT_RETRY: Duration = Duration::from_secs(8);
const CONNECT_INTERVAL: Duration = Duration::from_millis(200);
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_FRAME: usize = 65_535;

pub struct TcpFrames {
    stream: TcpStream,
}

impl TcpFrames {
    pub fn connect(addr: &str) -> io::Result<Self> {
        Self::connect_with_retry(addr, CONNECT_RETRY, CONNECT_INTERVAL)
    }

    pub fn connect_with_retry(
        addr: &str,
        timeout: Duration,
        interval: Duration,
    ) -> io::Result<Self> {
        let addresses = resolve(addr)?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let attempt_timeout = CONNECT_ATTEMPT_TIMEOUT.min(remaining);
            match connect_addresses(&addresses, attempt_timeout) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(Self { stream });
                }
                Err(e) if retryable(&e) && Instant::now() < deadline => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    thread::sleep(interval.min(remaining));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

pub fn probe(addr: &str, timeout: Duration) -> io::Result<()> {
    let addresses = resolve(addr)?;
    connect_addresses(&addresses, timeout).map(drop)
}

fn resolve(addr: &str) -> io::Result<Vec<SocketAddr>> {
    let addresses: Vec<_> = addr.to_socket_addrs()?.collect();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{addr} did not resolve to an address"),
        ));
    }
    Ok(addresses)
}

fn connect_addresses(addresses: &[SocketAddr], timeout: Duration) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(address, timeout.max(Duration::from_millis(1))) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to")))
}

fn retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NotFound
    )
}

fn client_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    )
}

impl FrameSource for TcpFrames {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        read_record(&mut self.stream, buffer)
    }
}

impl FrameSink for TcpFrames {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        write_record(&mut self.stream, frame)
    }
}

/// Read one length-prefixed frame: four big-endian length bytes, then the frame.
///
/// `Ok(0)` means the peer closed the connection, and nothing else. A length
/// prefix of zero is *not* the same thing — the caller stops on 0, so treating
/// a zero-length record as a close would let one corrupt prefix end the session
/// while looking like a tidy disconnect.
fn read_record(stream: &mut TcpStream, buffer: &mut [u8]) -> io::Result<usize> {
    let mut len_buf = [0u8; 4];
    if stream.read(&mut len_buf[..1])? == 0 {
        return Ok(0);
    }
    // Part of a length prefix arrived, so the rest of it must follow.
    stream.read_exact(&mut len_buf[1..])?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "forwarded frame claims zero bytes; the link is out of step",
        ));
    }
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("forwarded frame is {n} bytes; maximum is {MAX_FRAME}"),
        ));
    }
    if n > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "forwarded frame is {n} bytes but the receive buffer holds {}",
                buffer.len()
            ),
        ));
    }
    stream.read_exact(&mut buffer[..n])?;
    Ok(n)
}

fn write_record(stream: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    if frame.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "cannot forward {}-byte frame; maximum is {MAX_FRAME}",
                frame.len()
            ),
        ));
    }
    stream.write_all(&(frame.len() as u32).to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()
}

pub fn run_bridge(listen: &str, tap: TapInterface) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    let bound = listener.local_addr()?;
    if let Some(warning) = exposure_warning(bound) {
        crate::log::status::warn(warning);
    }
    crate::log::status::info(format!("bridge listening on {bound}"));
    accept_loop(listener, tap)
}

/// Warn if this bridge is reachable from outside the machine.
///
/// Binding beyond loopback is allowed — the sidecar does it — but never by
/// accident. The check is on the address actually bound, not the string asked
/// for, so `0.0.0.0`, `::` and a LAN address are all caught the same way.
fn exposure_warning(bound: SocketAddr) -> Option<String> {
    if bound.ip().is_loopback() {
        return None;
    }
    Some(format!(
        "bridge is listening on {bound}, which is reachable from outside this machine. \
         It has no authentication: anyone who can connect can read and inject frames \
         on the TAP. Use --listen 127.0.0.1:{} unless you meant this.",
        bound.port()
    ))
}

/// Serve one host stack at a time, forever.
///
/// Deliberately serial: a TAP delivers each frame to exactly one reader, so two
/// stacks at once would steal frames from each other at random. The next client
/// waits in the accept queue. A client hanging up is how a session normally
/// ends, not an error.
fn accept_loop(listener: TcpListener, tap: TapInterface) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept()?;
        crate::log::status::info(format!("bridge client {peer}"));
        stream.set_nodelay(true)?;
        let session = tap.try_clone()?;
        match pump(session, stream) {
            Ok(()) => {}
            Err(e) if client_gone(&e) => {
                crate::log::status::info(format!("bridge client {peer} closed"));
            }
            Err(e) => return Err(e),
        }
    }
}

fn pump(tap: TapInterface, stream: TcpStream) -> io::Result<()> {
    let mut tap_read = tap.try_clone()?;
    let mut tap_write = tap;
    let mut sock_read = stream.try_clone()?;
    let mut sock_write = stream.try_clone()?;

    let (wake_r, wake_w) = UnixStream::pair()?;
    wake_r.set_nonblocking(true)?;

    let up = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 2048];
        loop {
            match poll_tap_or_stop(tap_read.as_raw_fd(), wake_r.as_raw_fd())? {
                Wake::Stop => return Ok(()),
                Wake::Tap => {
                    let n = tap_read.read_frame(&mut buf)?;
                    if n == 0 {
                        return Ok(());
                    }
                    write_record(&mut sock_write, &buf[..n])?;
                }
            }
        }
    });
    let down = thread::spawn(move || -> io::Result<()> {
        let _wake = wake_w;
        let mut buf = [0u8; 2048];
        loop {
            let n = read_record(&mut sock_read, &mut buf)?;
            if n == 0 {
                return Ok(());
            }
            tap_write.write_frame(&buf[..n])?;
        }
    });

    while !up.is_finished() && !down.is_finished() {
        thread::sleep(Duration::from_millis(20));
    }
    let _ = stream.shutdown(Shutdown::Both);

    let up_res = match up.join() {
        Ok(r) => r,
        Err(_) => Err(io::Error::other("bridge tap->sock thread panicked")),
    };
    let down_res = match down.join() {
        Ok(r) => r,
        Err(_) => Err(io::Error::other("bridge sock->tap thread panicked")),
    };
    up_res?;
    down_res
}

enum Wake {
    Stop,
    Tap,
}

fn poll_tap_or_stop(tap_fd: i32, wake_fd: i32) -> io::Result<Wake> {
    let mut fds = [
        libc::pollfd {
            fd: tap_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        },
    ];
    loop {
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(Wake::Stop);
        }
        if fds[0].revents != 0 {
            return Ok(Wake::Tap);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::time::Duration;

    #[test]
    fn a_zero_length_prefix_is_corruption_not_a_disconnect() {
        // Ok(0) is how the read loop learns the peer went away. If a zero
        // length prefix also produced it, one desynchronised byte would end the
        // session looking like a tidy disconnect.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&0u32.to_be_bytes()).unwrap();
            // Hold the connection open, so a genuine close cannot be the cause.
            thread::sleep(Duration::from_millis(200));
        });

        let mut frames = TcpFrames::connect(&addr.to_string()).unwrap();
        let error = frames.read_frame(&mut [0u8; 2048]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        handle.join().unwrap();
    }

    #[test]
    fn the_bridge_keeps_to_itself_by_default() {
        // Change this and `minitcp bridge` puts an unauthenticated raw-frame
        // socket on the network.
        let addr: SocketAddr = DEFAULT_LISTEN.parse().unwrap();
        assert!(addr.ip().is_loopback(), "{DEFAULT_LISTEN}");
        assert!(exposure_warning(addr).is_none());
    }

    #[test]
    fn binding_beyond_loopback_is_said_out_loud() {
        for exposed in ["0.0.0.0:7946", "192.168.1.5:7946", "[::]:7946"] {
            let warning = exposure_warning(exposed.parse().unwrap());
            let warning = warning.unwrap_or_else(|| panic!("{exposed} should warn"));
            assert!(warning.contains("no authentication"), "{warning}");
            // The advice has to name a port the user can actually paste back.
            assert!(warning.contains("127.0.0.1:7946"), "{warning}");
        }
    }

    #[test]
    fn the_loopback_address_family_does_not_matter() {
        assert!(exposure_warning("[::1]:7946".parse().unwrap()).is_none());
    }

    #[test]
    fn length_prefixed_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let frame = b"\x00\x01\x02hello";
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_nodelay(true).unwrap();
            write_record(&mut stream, frame).unwrap();
            let mut buf = [0u8; 64];
            let n = read_record(&mut stream, &mut buf).unwrap();
            buf[..n].to_vec()
        });
        let mut client = TcpFrames::connect(&addr.to_string()).unwrap();
        let mut buf = [0u8; 64];
        let n = client.read_frame(&mut buf).unwrap();
        assert_eq!(&buf[..n], frame);
        client.write_frame(b"ack").unwrap();
        let echoed = handle.join().unwrap();
        assert_eq!(echoed, b"ack");
    }

    #[test]
    fn connect_retries_until_listener_binds() {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let addr_s = addr.to_string();
        let handle = thread::spawn(move || {
            TcpFrames::connect_with_retry(
                &addr_s,
                Duration::from_secs(5),
                Duration::from_millis(50),
            )
        });
        thread::sleep(Duration::from_millis(150));
        let listener = TcpListener::bind(addr).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let client = handle.join().unwrap().expect("connect should succeed");
        drop(peer);
        drop(client);
    }

    #[test]
    fn oversized_length_prefix_is_rejected_without_allocating() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
                .unwrap();
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        let error = read_record(&mut stream, &mut [0u8; 2048]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("maximum"), "{error}");
        writer.join().unwrap();
    }

    #[test]
    fn partial_length_prefix_is_reported_as_corrupt_not_clean_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[0, 1]).unwrap();
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        let error = read_record(&mut stream, &mut [0u8; 2048]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        writer.join().unwrap();
    }

    #[test]
    fn second_client_after_first_drops() {
        let (tap_a, tap_b) = UnixStream::pair().unwrap();
        let tap = TapInterface::from_file(File::from(OwnedFd::from(tap_a)));
        let _hold = tap_b;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let _ = accept_loop(listener, tap);
        });

        let first = TcpStream::connect(addr).unwrap();
        drop(first);
        thread::sleep(Duration::from_millis(200));
        TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            .expect("second client should be accepted after the first drops");
    }
}

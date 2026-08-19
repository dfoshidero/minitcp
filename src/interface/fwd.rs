// Length-prefixed Ethernet frames over TCP (TAP sidecar <-> host stack).

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use super::FrameIo;
use super::tap::TapInterface;

pub const DEFAULT_FWD: &str = "127.0.0.1:7946";
pub const DEFAULT_LISTEN: &str = "0.0.0.0:7946";

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

impl FrameIo for TcpFrames {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        read_record(&mut self.stream, buffer)
    }

    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        write_record(&mut self.stream, frame)
    }
}

fn read_record(stream: &mut TcpStream, buffer: &mut [u8]) -> io::Result<usize> {
    let mut len_buf = [0u8; 4];
    if stream.read(&mut len_buf[..1])? == 0 {
        return Ok(0);
    }
    stream.read_exact(&mut len_buf[1..])?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n == 0 {
        return Ok(0);
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
    crate::log::status::info(format!("bridge listening on {listen}"));
    accept_loop(listener, tap)
}

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

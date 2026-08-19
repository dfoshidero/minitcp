// Length-prefixed Ethernet frames over TCP (TAP sidecar <-> host stack).

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use super::FrameIo;
use super::tap::TapInterface;

pub const DEFAULT_FWD: &str = "127.0.0.1:7946";
pub const DEFAULT_LISTEN: &str = "0.0.0.0:7946";

pub struct TcpFrames {
    stream: TcpStream,
}

impl TcpFrames {
    pub fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        Ok(Self { stream })
    }
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
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len_buf) as usize;
    if n == 0 {
        return Ok(0);
    }
    if n > buffer.len() {
        let mut skip = vec![0u8; n];
        stream.read_exact(&mut skip)?;
        let keep = buffer.len();
        buffer.copy_from_slice(&skip[..keep]);
        return Ok(keep);
    }
    stream.read_exact(&mut buffer[..n])?;
    Ok(n)
}

fn write_record(stream: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    stream.write_all(&(frame.len() as u32).to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()
}

pub fn run_bridge(listen: &str, tap: TapInterface) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    eprintln!("bridge listening on {listen}");
    let (stream, peer) = listener.accept()?;
    eprintln!("bridge client {peer}");
    stream.set_nodelay(true)?;
    pump(tap, stream)
}

fn pump(tap: TapInterface, stream: TcpStream) -> io::Result<()> {
    let mut tap_read = tap.try_clone()?;
    let mut tap_write = tap;
    let mut sock_read = stream.try_clone()?;
    let mut sock_write = stream;

    let up = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 2048];
        loop {
            let n = tap_read.read_frame(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            write_record(&mut sock_write, &buf[..n])?;
        }
    });
    let down = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 2048];
        loop {
            let n = read_record(&mut sock_read, &mut buf)?;
            if n == 0 {
                return Ok(());
            }
            tap_write.write_frame(&buf[..n])?;
        }
    });

    match up.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(io::Error::other("bridge tap->sock thread panicked")),
    }
    match down.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(io::Error::other("bridge sock->tap thread panicked")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

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
}

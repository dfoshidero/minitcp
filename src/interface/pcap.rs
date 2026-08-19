// src/interface/pcap.rs
// Classic pcap (no extra crate). Ethernet link type 1.

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::FrameIo;

const MAGIC_LE: u32 = 0xa1b2_c3d4;
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
const SNAPLEN: u32 = 65535;
const LINKTYPE_ETHERNET: u32 = 1;

pub struct PcapWriter {
    file: File,
}

impl PcapWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut file = File::create(path)?;
        write_u32(&mut file, MAGIC_LE)?;
        write_u16(&mut file, VERSION_MAJOR)?;
        write_u16(&mut file, VERSION_MINOR)?;
        write_u32(&mut file, 0)?; // thiszone
        write_u32(&mut file, 0)?; // sigfigs
        write_u32(&mut file, SNAPLEN)?;
        write_u32(&mut file, LINKTYPE_ETHERNET)?;
        Ok(Self { file })
    }

    pub fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        let (sec, usec) = now_stamp();
        let len = frame.len() as u32;
        write_u32(&mut self.file, sec)?;
        write_u32(&mut self.file, usec)?;
        write_u32(&mut self.file, len)?;
        write_u32(&mut self.file, len)?;
        self.file.write_all(frame)
    }
}

pub struct PcapReader {
    file: File,
}

impl PcapReader {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let magic = read_u32(&mut file)?;
        if magic != MAGIC_LE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported pcap magic (want classic little-endian 0xa1b2c3d4)",
            ));
        }
        let _major = read_u16(&mut file)?;
        let _minor = read_u16(&mut file)?;
        let _zone = read_u32(&mut file)?;
        let _sigfigs = read_u32(&mut file)?;
        let _snaplen = read_u32(&mut file)?;
        let network = read_u32(&mut file)?;
        if network != LINKTYPE_ETHERNET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pcap link type {network} is not Ethernet (1)"),
            ));
        }
        Ok(Self { file })
    }
}

impl FrameIo for PcapReader {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match read_record(&mut self.file, buffer) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn write_frame(&mut self, _frame: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

pub struct HexReader<R> {
    inner: R,
}

impl<R: BufRead> HexReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: BufRead> FrameIo for HexReader<R> {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.inner.read_line(&mut line)?;
            if n == 0 {
                return Ok(0);
            }
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let bytes = decode_hex_line(trimmed)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if bytes.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hex frame larger than read buffer",
                ));
            }
            buffer[..bytes.len()].copy_from_slice(&bytes);
            return Ok(bytes.len());
        }
    }

    fn write_frame(&mut self, _frame: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

pub fn decode_hex_line(line: &str) -> Result<Vec<u8>, String> {
    let hex: String = line
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if hex.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|_| "invalid hex")?;
        out.push(u8::from_str_radix(pair, 16).map_err(|_| format!("invalid hex: {pair}"))?);
    }
    Ok(out)
}

pub fn pcap_info(path: &Path) -> io::Result<String> {
    let mut reader = PcapReader::open(path)?;
    let mut buffer = [0u8; 65535];
    let mut out = String::new();
    let mut count = 0u64;
    loop {
        let n = reader.read_frame(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += 1;
        let ethertype = if n >= 14 {
            u16::from_be_bytes([buffer[12], buffer[13]])
        } else {
            0
        };
        out.push_str(&format!(
            "{count}  {n} bytes  ethertype 0x{ethertype:04x}\n"
        ));
    }
    out.push_str(&format!("{count} frames\n"));
    Ok(out)
}

pub struct CaptureIo<I> {
    inner: I,
    capture: Option<PcapWriter>,
}

impl<I> CaptureIo<I> {
    pub fn new(inner: I, capture: Option<PcapWriter>) -> Self {
        Self { inner, capture }
    }
}

impl<I: FrameIo> FrameIo for CaptureIo<I> {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read_frame(buffer)?;
        if n > 0 {
            if let Some(w) = &mut self.capture {
                w.write_frame(&buffer[..n])?;
            }
        }
        Ok(n)
    }

    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        if let Some(w) = &mut self.capture {
            w.write_frame(frame)?;
        }
        self.inner.write_frame(frame)
    }
}

fn now_stamp() -> (u32, u32) {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (dur.as_secs() as u32, dur.subsec_micros())
}

fn write_u16(w: &mut impl Write, n: u16) -> io::Result<()> {
    w.write_all(&n.to_le_bytes())
}

fn write_u32(w: &mut impl Write, n: u32) -> io::Result<()> {
    w.write_all(&n.to_le_bytes())
}

fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_record(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let _sec = read_u32(file)?;
    let _usec = read_u32(file)?;
    let incl = read_u32(file)? as usize;
    let _orig = read_u32(file)?;
    if incl > buffer.len() {
        let mut skip = vec![0u8; incl];
        file.read_exact(&mut skip)?;
        let n = buffer.len();
        buffer.copy_from_slice(&skip[..n]);
        return Ok(n);
    }
    file.read_exact(&mut buffer[..incl])?;
    Ok(incl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ARP_FRAME: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];

    fn unique_pcap() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("minitcp-{n}.pcap"))
    }

    #[test]
    fn write_then_read_roundtrip() {
        let path = unique_pcap();
        {
            let mut w = PcapWriter::create(&path).unwrap();
            w.write_frame(&ARP_FRAME).unwrap();
        }
        let mut r = PcapReader::open(&path).unwrap();
        let mut buf = [0u8; 2048];
        let n = r.read_frame(&mut buf).unwrap();
        assert_eq!(&buf[..n], &ARP_FRAME);
        assert_eq!(r.read_frame(&mut buf).unwrap(), 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn pcap_info_lists_ethertype() {
        let path = unique_pcap();
        {
            let mut w = PcapWriter::create(&path).unwrap();
            w.write_frame(&ARP_FRAME).unwrap();
        }
        let text = pcap_info(&path).unwrap();
        assert!(text.contains("ethertype 0x0806"), "{text}");
        assert!(text.contains("1 frames"), "{text}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn hex_decodes_spaced_line() {
        let spaced = ARP_FRAME
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(decode_hex_line(&spaced).unwrap(), ARP_FRAME);
    }

    #[test]
    fn hex_rejects_odd_length() {
        assert_eq!(decode_hex_line("abc").unwrap_err(), "odd-length hex");
    }

    #[test]
    fn hex_reader_yields_one_frame() {
        let line = ARP_FRAME.iter().map(|b| format!("{b:02x}")).collect::<String>() + "\n";
        let mut hex = HexReader::new(std::io::Cursor::new(line));
        let mut buf = [0u8; 2048];
        let n = hex.read_frame(&mut buf).unwrap();
        assert_eq!(&buf[..n], &ARP_FRAME);
        assert_eq!(hex.read_frame(&mut buf).unwrap(), 0);
    }
}

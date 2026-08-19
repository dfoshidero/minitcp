// Classic libpcap file: a global header, then timestamped Ethernet frames.
// Same format tcpdump/Wireshark write. No extra crate; we only speak little-endian
// magic 0xa1b2c3d4 and link type 1 (Ethernet). See docs/GLOSSARY.md ("pcap").

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::FrameSource;

const MAGIC_LE: u32 = 0xa1b2_c3d4;
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
const SNAPLEN: u32 = 65535;
const LINKTYPE_ETHERNET: u32 = 1;

pub struct PcapWriter {
    file: File,
    path: std::path::PathBuf,
}

impl PcapWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut file = File::create(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot create pcap {}: {error}", path.display()),
            )
        })?;
        write_u32(&mut file, MAGIC_LE)?;
        write_u16(&mut file, VERSION_MAJOR)?;
        write_u16(&mut file, VERSION_MINOR)?;
        write_u32(&mut file, 0)?; // thiszone
        write_u32(&mut file, 0)?; // sigfigs
        write_u32(&mut file, SNAPLEN)?;
        write_u32(&mut file, LINKTYPE_ETHERNET)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        let (sec, usec) = now_stamp();
        let len = frame.len() as u32;
        let result = (|| {
            write_u32(&mut self.file, sec)?;
            write_u32(&mut self.file, usec)?;
            write_u32(&mut self.file, len)?;
            write_u32(&mut self.file, len)?;
            self.file.write_all(frame)
        })();
        result.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot write pcap {}: {error}", self.path.display()),
            )
        })
    }
}

pub struct PcapReader {
    file: File,
    path: std::path::PathBuf,
}

impl PcapReader {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot open pcap {}: {error}", path.display()),
            )
        })?;
        let magic = read_u32(&mut file).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot read pcap header from {}: {error}", path.display()),
            )
        })?;
        if magic != MAGIC_LE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported pcap magic (want classic little-endian 0xa1b2c3d4)",
            ));
        }
        let network = (|| {
            let _major = read_u16(&mut file)?;
            let _minor = read_u16(&mut file)?;
            let _zone = read_u32(&mut file)?;
            let _sigfigs = read_u32(&mut file)?;
            let _snaplen = read_u32(&mut file)?;
            read_u32(&mut file)
        })()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot read pcap header from {}: {error}", path.display()),
            )
        })?;
        if network != LINKTYPE_ETHERNET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pcap link type {network} is not Ethernet (1)"),
            ));
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }
}

impl FrameSource for PcapReader {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        read_record(&mut self.file, buffer).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot read pcap {}: {error}", self.path.display()),
            )
        })
    }
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

/// Read the next captured frame, or report that the file has ended.
///
/// A pcap file is a 24-byte header followed by records, each of which is a
/// 16-byte record header and then the captured bytes:
///
/// ```text
/// 0        4        8        12       16
/// | ts_sec | ts_usec| incl_len| orig_len|  ...incl_len bytes of frame...
/// ```
///
/// `Ok(0)` from this function means one thing only: the file ended cleanly on a
/// record boundary. It deliberately does *not* also mean "a record of length
/// zero", because the caller treats 0 as end-of-input — so a single bogus
/// `incl_len` would silently swallow the whole rest of the file and look like a
/// successful replay. There is no such thing as a zero-byte Ethernet frame, so
/// that is corruption, and corruption should be said out loud.
fn read_record(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut header = [0u8; 16];
    if file.read(&mut header[..1])? == 0 {
        return Ok(0);
    }
    // We have part of a record header, so the rest of it must be there too.
    // Anything else is a file that was cut off mid-record.
    file.read_exact(&mut header[1..]).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return io::Error::new(
                io::ErrorKind::InvalidData,
                "pcap ends in the middle of a record header; the file is truncated",
            );
        }
        error
    })?;
    let incl = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if incl == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pcap record claims a zero-byte frame, which cannot exist on Ethernet",
        ));
    }
    if incl > SNAPLEN as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pcap frame is {incl} bytes; maximum is {SNAPLEN}"),
        ));
    }
    if incl > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "pcap frame is {incl} bytes but the receive buffer holds {}",
                buffer.len()
            ),
        ));
    }
    file.read_exact(&mut buffer[..incl]).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pcap record claims {incl} bytes but the file ends before them"),
            );
        }
        error
    })?;
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
    fn partial_record_is_reported_as_corrupt_not_clean_eof() {
        let path = unique_pcap();
        {
            let _writer = PcapWriter::create(&path).unwrap();
        }
        {
            let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[1, 2, 3]).unwrap();
        }
        let mut reader = PcapReader::open(&path).unwrap();
        let error = reader.read_frame(&mut [0u8; 2048]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("cannot read pcap"), "{error}");
        assert!(error.to_string().contains("truncated"), "{error}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_zero_length_record_is_corruption_not_the_end_of_the_file() {
        // The bug this guards: read_frame returns 0 for end-of-file, so if a
        // zero-length record also returned 0, one bogus length field would end
        // the replay early and report success. Two frames go in; the reader
        // must not quietly claim the file was over after the first.
        let path = unique_pcap();
        {
            let mut writer = PcapWriter::create(&path).unwrap();
            writer.write_frame(&ARP_FRAME).unwrap();
        }
        {
            // A record header claiming incl_len = orig_len = 0.
            let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[0u8; 16]).unwrap();
        }
        let mut reader = PcapReader::open(&path).unwrap();
        let mut buffer = [0u8; 2048];
        assert_eq!(reader.read_frame(&mut buffer).unwrap(), ARP_FRAME.len());

        let error = reader.read_frame(&mut buffer).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("zero-byte"), "{error}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_record_cut_off_mid_frame_names_what_was_expected() {
        let path = unique_pcap();
        {
            let mut writer = PcapWriter::create(&path).unwrap();
            writer.write_frame(&ARP_FRAME).unwrap();
        }
        {
            // A header promising 42 bytes, followed by only 3 of them.
            let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
            let mut header = [0u8; 16];
            header[8..12].copy_from_slice(&42u32.to_le_bytes());
            header[12..16].copy_from_slice(&42u32.to_le_bytes());
            file.write_all(&header).unwrap();
            file.write_all(&[1, 2, 3]).unwrap();
        }
        let mut reader = PcapReader::open(&path).unwrap();
        let mut buffer = [0u8; 2048];
        assert_eq!(reader.read_frame(&mut buffer).unwrap(), ARP_FRAME.len());

        let error = reader.read_frame(&mut buffer).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("42 bytes"), "{error}");
        let _ = fs::remove_file(path);
    }
}

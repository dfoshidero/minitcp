// Ethernet frames typed as hex, one per line.
//
// The point is to be able to feed the stack a frame by hand — paste the bytes
// of an ARP request and watch what comes back — without a TAP, a capture file,
// or anything else in the way. Blank lines and `#` comments are skipped so a
// file of examples can explain itself.

use std::io::{self, BufRead};

use super::FrameSource;

pub struct HexReader<R> {
    inner: R,
}

impl<R: BufRead> HexReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: BufRead> FrameSource for HexReader<R> {
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
}

pub fn decode_hex_line(line: &str) -> Result<Vec<u8>, String> {
    let hex: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    if !hex.len().is_multiple_of(2) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const ARP_FRAME: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];

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
        let line = ARP_FRAME
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            + "\n";
        let mut hex = HexReader::new(std::io::Cursor::new(line));
        let mut buf = [0u8; 2048];
        let n = hex.read_frame(&mut buf).unwrap();
        assert_eq!(&buf[..n], &ARP_FRAME);
        assert_eq!(hex.read_frame(&mut buf).unwrap(), 0);
    }
}

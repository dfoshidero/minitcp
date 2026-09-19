// src/proto/udp.rs

use super::error::ParseError;
use super::checksum::transport_checksum_ipv4;

pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, ParseError> {
        if input.len() < 8 {
            return Err(ParseError::TruncatedUdp);
        }
        let src_port = u16::from_be_bytes([input[0], input[1]]);
        let dst_port = u16::from_be_bytes([input[2], input[3]]);
        let length = u16::from_be_bytes([input[4], input[5]]) as usize;
        if length < 8 || length > input.len() {
            return Err(ParseError::InvalidUdpLength);
        }
        let checksum = u16::from_be_bytes([input[6], input[7]]);
        let payload = &input[8..length];
        Ok(Self {
            src_port,
            dst_port,
            checksum,
            payload,
        })
    }
}

pub fn checksum_ok(src: [u8; 4], dst: [u8; 4], datagram: &[u8]) -> bool {
    let checksum = u16::from_be_bytes([datagram[6], datagram[7]]);
    if checksum == 0 {
        return true; // IPv4 0 checksum is valid - means it skipped checksum calculation
    }
    transport_checksum_ipv4(src, dst, 17, datagram) == 00
}

pub fn write(
    out: &mut Vec<u8>,
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) {
    let start = out.len();
    let length = (8 + payload.len()) as u16;
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(payload);

    let mut csum = transport_checksum_ipv4(src, dst, 17, &out[start..]);
    if csum == 0 {
        csum = 0xffff;
    }
    out[start + 6..start + 8].copy_from_slice(&csum.to_be_bytes());
}
#[cfg(test)]
mod tests {
    use super::*;

    const SRC: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [10, 0, 0, 2];

    /// A datagram straight from `write`: length and checksum are already correct.
    fn datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut out, SRC, DST, src_port, dst_port, payload);
        out
    }

    #[test]
    fn rejects_truncated() {
        // Seven bytes cannot hold the 8-byte header, so there is nothing to read.
        assert_eq!(
            UdpDatagram::parse(&[0; 7]).err(),
            Some(ParseError::TruncatedUdp)
        );
    }

    #[test]
    fn rejects_length_below_header() {
        // Length counts the header too, so anything under 8 is self-contradictory.
        let mut bytes = datagram(1, 2, b"hi");
        bytes[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            UdpDatagram::parse(&bytes).err(),
            Some(ParseError::InvalidUdpLength)
        );
    }

    #[test]
    fn rejects_length_past_end() {
        // Length claiming more than we hold would slice out of bounds.
        let mut bytes = datagram(1, 2, b"hi");
        bytes[4..6].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(
            UdpDatagram::parse(&bytes).err(),
            Some(ParseError::InvalidUdpLength)
        );
    }

    #[test]
    fn zero_checksum_is_accepted() {
        // A sender may opt out over IPv4 by leaving the field zero.
        let mut bytes = datagram(1, 2, b"hi");
        bytes[6..8].copy_from_slice(&[0, 0]);
        assert!(checksum_ok(SRC, DST, &bytes));
    }

    #[test]
    fn rejects_flipped_checksum() {
        let bytes = datagram(0x1234, 0x5678, b"hello");
        assert!(checksum_ok(SRC, DST, &bytes));

        // Corrupting the payload must break verification.
        let mut flipped = bytes.clone();
        flipped[8] ^= 0xff;
        assert!(!checksum_ok(SRC, DST, &flipped));

        // So must corrupting the checksum itself — as long as we do not land on
        // zero, which would take the opted-out path instead.
        let mut flipped = bytes.clone();
        flipped[6] ^= 0x0f;
        assert_ne!(&flipped[6..8], &[0, 0]);
        assert!(!checksum_ok(SRC, DST, &flipped));
    }

    #[test]
    fn write_then_parse_round_trips() {
        let bytes = datagram(0x1234, 0x5678, b"hello");
        let parsed = UdpDatagram::parse(&bytes).unwrap();
        assert_eq!(parsed.src_port, 0x1234);
        assert_eq!(parsed.dst_port, 0x5678);
        assert_eq!(parsed.payload, b"hello");
        assert_eq!(parsed.checksum, u16::from_be_bytes([bytes[6], bytes[7]]));
    }

    #[test]
    fn writes_at_the_end_of_a_non_empty_buffer() {
        // The IPv4 header comes first in real use, so `write` must respect `start`.
        let mut out = vec![0xaa; 20];
        write(&mut out, SRC, DST, 0x1234, 0x5678, b"hello");
        assert_eq!(&out[..20], &[0xaa; 20]);
        assert!(checksum_ok(SRC, DST, &out[20..]));
        assert_eq!(UdpDatagram::parse(&out[20..]).unwrap().payload, b"hello");
    }

    #[test]
    fn computed_zero_checksum_is_stored_as_ffff() {
        // Crafted so the one's-complement sum comes out to 0: storing that 0 would
        // read back as "no checksum", so it has to go on the wire as 0xffff.
        let payload = [0x83, 0x2b];
        let segment = [0x12, 0x34, 0x56, 0x78, 0, 10, 0, 0, 0x83, 0x2b];
        assert_eq!(transport_checksum_ipv4(SRC, DST, 17, &segment), 0);

        let bytes = datagram(0x1234, 0x5678, &payload);
        assert_eq!(&bytes[6..8], &[0xff, 0xff]);
        assert!(checksum_ok(SRC, DST, &bytes));
    }

    #[test]
    fn outgoing_checksum_is_never_zero() {
        for len in 0..64 {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let bytes = datagram(0x1234, 0x5678, &payload);
            assert_ne!(&bytes[6..8], &[0, 0], "zero checksum at payload len {len}");
        }
    }
}

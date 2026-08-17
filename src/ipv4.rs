// src/ipv4.rs

use std::net::Ipv4Addr;

use crate::checksum::internet_checksum;

const MINIMUM_IPV4_HEADER_SIZE: usize = 20;
// Bytes 6-7 pack 3 flag bits + a 13-bit fragment offset.
const MORE_FRAGMENTS: u16 = 0x2000; // bit 13: more pieces follow
const FRAGMENT_OFFSET: u16 = 0x1FFF; // low 13 bits: where this piece starts

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Icmp,
    Udp,
    Tcp,
    Unknown(u8),
}

impl Protocol {
    pub fn from_number(n: u8) -> Self {
        // IANA protocol numbers in byte 9. 1 ICMP, 6 TCP, 17 UDP.
        match n {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            _ => Self::Unknown(n),
        }
    }

    pub fn number(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Unknown(n) => n,
        }
    }
}

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub ttl: u8,
    pub protocol: Protocol,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < MINIMUM_IPV4_HEADER_SIZE {
            return Err("truncated ipv4 header");
        }

        // Byte 0 packs two 4-bit fields.
        // >> 4 moves the high nibble down → version. & 0x0F keeps the low nibble → IHL.
        let version = input[0] >> 4;
        // IHL is in 32-bit words; * 4 converts to bytes. 5 → 20, the header with no options.
        let ihl_bytes = ((input[0] & 0x0F) as usize) * 4;

        if version != 4 || ihl_bytes < MINIMUM_IPV4_HEADER_SIZE || input.len() < ihl_bytes {
            return Err("invalid ipv4 header");
        }

        // [2..4] Total Length = header + payload. Ethernet may pad, so do not use input.len().
        let total_length = u16::from_be_bytes([input[2], input[3]]) as usize;
        if total_length < ihl_bytes || total_length > input.len() {
            return Err("invalid ipv4 total length");
        }

        let frag = u16::from_be_bytes([input[6], input[7]]);
        // & isolates each part of the packed field. Either set means a split packet; v1 drops it.
        if (frag & FRAGMENT_OFFSET) !=0 || (frag & MORE_FRAGMENTS) !=0{
            return Err("ipv4 fragmentation unsupported");
        }

        // Checksum covers the header, including bytes 10-11. A correct header sums to 0.
        if internet_checksum(&input[..ihl_bytes]) != 0 {
            return Err("bad ipv4 checksum");
        }

        Ok(Self {
            ttl: input[8], // hops remaining; routers decrement this
            protocol: Protocol::from_number(input[9]),
            source: Ipv4Addr::new(input[12], input[13], input[14], input[15]),
            destination: Ipv4Addr::new(input[16], input[17], input[18], input[19]),
            payload: &input[ihl_bytes..total_length],
        })
    }

    /// 20-byte header with no options. Checksum is computed with bytes 10-11 zeroed.
    pub fn write(
        out: &mut Vec<u8>,
        ttl: u8,
        protocol: Protocol,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        payload: &[u8],
    ) {
        let total_length =(MINIMUM_IPV4_HEADER_SIZE + payload.len()) as u16;
        let header_start = out.len();

        out.push((4 << 4) | 5); // high nibble version=4, low nibble IHL=5 → byte 0x45
        out.push(0); // DSCP/ECN, unused here
        out.extend_from_slice(&total_length.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // identification
        out.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        out.push(ttl);
        out.push(protocol.number());
        out.extend_from_slice(&0u16.to_be_bytes()); // checksum field must be 0 while we compute it
        out.extend_from_slice(&source.octets());
        out.extend_from_slice(&destination.octets());
        out.extend_from_slice(payload);

        let checksum = internet_checksum(&out[header_start..header_start+MINIMUM_IPV4_HEADER_SIZE]);
        out[header_start + 10..header_start + 12].copy_from_slice(&checksum.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ping-sized IPv4 + 8-byte ICMP echo from 10.0.0.1 → 10.0.0.2
    const PING: [u8; 28] = [
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x01, 0x66, 0xdf, 0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_rejects_truncated() {
        assert_eq!(Ipv4Packet::parse(&[0u8; 19]).err(), Some("truncated ipv4 header"));
    }

    #[test]
    fn parse_rejects_invalid_version_and_ihl() {
        let mut bad_ver = PING;
        bad_ver[0] = 0x65; // version 6, IHL 5
        assert_eq!(Ipv4Packet::parse(&bad_ver).err(), Some("invalid ipv4 header"));

        let mut bad_ihl = PING;
        bad_ihl[0] = 0x44; // version 4, IHL 4 → 16 bytes
        assert_eq!(Ipv4Packet::parse(&bad_ihl).err(), Some("invalid ipv4 header"));
    }

    #[test]
    fn parse_rejects_invalid_total_length() {
        // smaller than the 20-byte header
        let mut too_small = PING;
        too_small[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(
            Ipv4Packet::parse(&too_small).err(),
            Some("invalid ipv4 total length")
        );
        // claims to be longer than the buffer we actually have
        let mut too_big = PING;
        too_big[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(
            Ipv4Packet::parse(&too_big).err(),
            Some("invalid ipv4 total length")
        );
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        let mut bad = PING;
        bad[10] ^= 0xff;
        assert_eq!(Ipv4Packet::parse(&bad).err(), Some("bad ipv4 checksum"));
    }

    #[test]
    fn parse_rejects_fragments() {
        let mut mf = PING;
        mf[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // More Fragments
        mf[10..12].copy_from_slice(&[0, 0]);
        let csum = crate::checksum::internet_checksum(&mf[..20]);
        mf[10..12].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(
            Ipv4Packet::parse(&mf).err(),
            Some("ipv4 fragmentation unsupported")
        );
        let mut offset = PING;
        offset[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        offset[10..12].copy_from_slice(&[0, 0]);
        let csum = crate::checksum::internet_checksum(&offset[..20]);
        offset[10..12].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(
            Ipv4Packet::parse(&offset).err(),
            Some("ipv4 fragmentation unsupported")
        );
    }
    #[test]
    fn parse_ping() {
        let pkt = Ipv4Packet::parse(&PING).unwrap();
        assert_eq!(pkt.ttl, 64);
        assert_eq!(pkt.protocol, Protocol::Icmp);
        assert_eq!(pkt.source, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(pkt.destination, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(pkt.payload, &PING[20..]);
    }
    #[test]
    fn ethernet_padding_is_ignored() {
        let mut padded = PING.to_vec();
        padded.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let pkt = Ipv4Packet::parse(&padded).unwrap();
        assert_eq!(pkt.payload.len(), 8);
    }

    #[test]
    fn write_then_parse_roundtrip() {
        let payload = [0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x02];
        let mut bytes = Vec::new();
        Ipv4Packet::write(
            &mut bytes,
            64,
            Protocol::Icmp,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            &payload,
        );
        assert_eq!(bytes.len(), 28);
        assert_eq!(internet_checksum(&bytes[..20]), 0);
        let pkt = Ipv4Packet::parse(&bytes).unwrap();
        assert_eq!(pkt.protocol, Protocol::Icmp);
        assert_eq!(pkt.source, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(pkt.destination, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(pkt.payload, &payload);
    }
}
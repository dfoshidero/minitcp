// src/proto/ipv4.rs

use std::net::Ipv4Addr;

use super::checksum::internet_checksum;

const MINIMUM_IPV4_HEADER_SIZE: usize = 20;
// Bytes 6-7 hold two facts at once: "are more pieces coming?" and "where does this piece start?"
const MORE_FRAGMENTS: u16 = 0x2000; // the "more pieces" flag inside that field
const FRAGMENT_OFFSET: u16 = 0x1FFF; // the "where it starts" bits; zero means this is the whole packet

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Icmp,
    Udp,
    Tcp,
    Unknown(u8),
}

impl Protocol {
    pub fn from_number(n: u8) -> Self {
        // Same numbers main.rs matches on after parse.
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

        // Version and header length share byte 0 to save space.
        // Shift right 4 drops the length bits and leaves version.
        let version = input[0] >> 4;
        // AND keeps only the length bits. IHL counts 4-byte chunks, so * 4 is the header size
        // we need to slice payload (and to checksum only the header, not the rest).
        let ihl_bytes = ((input[0] & 0x0F) as usize) * 4;

        if version != 4 || ihl_bytes < MINIMUM_IPV4_HEADER_SIZE || input.len() < ihl_bytes {
            return Err("invalid ipv4 header");
        }

        // How long the IP letter is. Ethernet may pad the frame, so input.len() can be bigger.
        let total_length = u16::from_be_bytes([input[2], input[3]]) as usize;
        if total_length < ihl_bytes || total_length > input.len() {
            return Err("invalid ipv4 total length");
        }

        let frag = u16::from_be_bytes([input[6], input[7]]);
        // AND peels one fact out of the packed field (see MORE_FRAGMENTS / FRAGMENT_OFFSET).
        // Either one set means a torn packet; v1 drops it rather than reassembling.
        if (frag & FRAGMENT_OFFSET) !=0 || (frag & MORE_FRAGMENTS) !=0{
            return Err("ipv4 fragmentation unsupported");
        }

        // checksum.rs: including the checksum field, a correct header sums to 0.
        // write() zeros that field, computes, then fills it so this check can pass.
        if internet_checksum(&input[..ihl_bytes]) != 0 {
            return Err("bad ipv4 checksum");
        }

        Ok(Self {
            ttl: input[8], // hops remaining; each router subtracts 1
            protocol: Protocol::from_number(input[9]),
            source: Ipv4Addr::new(input[12], input[13], input[14], input[15]),
            destination: Ipv4Addr::new(input[16], input[17], input[18], input[19]),
            // Skip the header; stop at Total Length so Ethernet padding is not part of ICMP/UDP/TCP.
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

        out.push((4 << 4) | 5); // version 4, IHL 5 (20 bytes)
        out.push(0); // DSCP/ECN, unused here
        out.extend_from_slice(&total_length.to_be_bytes()); // total length
        out.extend_from_slice(&0u16.to_be_bytes()); // identification
        out.extend_from_slice(&0u16.to_be_bytes()); // flags and fragment offset
        out.push(ttl); // TTL
        out.push(protocol.number()); // protocol
        out.extend_from_slice(&0u16.to_be_bytes()); // checksum (placeholder)
        out.extend_from_slice(&source.octets()); // source address
        out.extend_from_slice(&destination.octets()); // destination address
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
        let csum = internet_checksum(&mf[..20]);
        mf[10..12].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(
            Ipv4Packet::parse(&mf).err(),
            Some("ipv4 fragmentation unsupported")
        );
        let mut offset = PING;
        offset[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        offset[10..12].copy_from_slice(&[0, 0]);
        let csum = internet_checksum(&offset[..20]);
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

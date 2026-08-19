// src/proto/ethernet.rs

// Address on this cable only. IPv4 (10.0.0.2) is a different address, inside the payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacAddress(pub [u8; 6]);

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0;
        // Always two digits per byte so this matches `ip` / tcpdump (`02:00:…`, not `2:0:…`).
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

// Bytes 12-13: which parser should see the payload. stack.rs matches on this.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EthernetType {
    Ipv4,
    Arp,
    Unknown(u16),
}

pub struct EthernetFrame<'a> {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ethertype: EthernetType,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, &'static str> {
        // Ethernet II header is 14 bytes: dst MAC [0..6], src MAC [6..12], EtherType [12..14].
        if input.len() < 14 {
            return Err("truncated ethernet frame");
        }

        let destination = MacAddress(input[0..6].try_into().unwrap());
        let source = MacAddress(input[6..12].try_into().unwrap());
        // Same "high byte first" order ARP and IPv4 use. to_be_bytes below writes it back that way.
        let raw = u16::from_be_bytes(input[12..14].try_into().unwrap());
        let ethertype = match raw {
            0x0800 => EthernetType::Ipv4,
            0x0806 => EthernetType::Arp,
            unknown => EthernetType::Unknown(unknown),
        };

        Ok(Self {
            destination,
            source,
            ethertype,
            payload: &input[14..], // handed to arp.rs or ipv4.rs
        })
    }
    pub fn write_ethernet(
        out: &mut Vec<u8>,
        dst: MacAddress,
        src: MacAddress,
        ethertype: u16,
        payload: &[u8],
    ) {
        // Same layout parse() reads. A Rust struct may pad or use CPU byte order; the cable cannot.
        out.extend_from_slice(&dst.0);
        out.extend_from_slice(&src.0);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ethernet II + ARP request equivalent to:
    // "who has 10.0.0.2, tell 10.0.0.1"
    // Written as raw bytes so the parser is not tested against its own serializer.
    const ARP_REQUEST: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination: broadcast
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // source
        0x08, 0x06, // EtherType ARP
        0x00, 0x01, // hardware type: Ethernet
        0x08, 0x00, // protocol type: IPv4
        0x06, 0x04, // hardware len, protocol len
        0x00, 0x01, // opcode: request
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // sender MAC
        0x0a, 0x00, 0x00, 0x01, // sender IP 10.0.0.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC
        0x0a, 0x00, 0x00, 0x02, // target IP 10.0.0.2
    ];

    const IPV4_FRAME: [u8; 16] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08,
        0x00, // EtherType IPv4
        0x45, 0x00, // start of an IPv4 header; opaque to this module
    ];

    const UNKNOWN_FRAME: [u8; 14] = [
        0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86,
        0xdd, // IPv6; not Ipv4 or Arp, so Unknown
    ];

    #[test]
    fn parse_rejects_truncated_frame() {
        assert_eq!(
            EthernetFrame::parse(&[0u8; 13]).err(),
            Some("truncated ethernet frame")
        );
        assert_eq!(
            EthernetFrame::parse(&[]).err(),
            Some("truncated ethernet frame")
        );
    }

    #[test]
    fn parse_arp_request() {
        let frame = EthernetFrame::parse(&ARP_REQUEST).unwrap();
        assert_eq!(frame.destination, MacAddress([0xff; 6]));
        assert_eq!(
            frame.source,
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        assert_eq!(frame.ethertype, EthernetType::Arp);
        assert_eq!(frame.payload, &ARP_REQUEST[14..]);
    }

    #[test]
    fn parse_ipv4() {
        let frame = EthernetFrame::parse(&IPV4_FRAME).unwrap();
        assert_eq!(
            frame.destination,
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
        );
        assert_eq!(
            frame.source,
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        assert_eq!(frame.ethertype, EthernetType::Ipv4);
        assert_eq!(frame.payload, &[0x45, 0x00]);
    }

    #[test]
    fn parse_unknown_ethertype() {
        let frame = EthernetFrame::parse(&UNKNOWN_FRAME).unwrap();
        assert_eq!(frame.ethertype, EthernetType::Unknown(0x86dd));
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn parse_then_write_reproduces_arp_bytes() {
        let frame = EthernetFrame::parse(&ARP_REQUEST).unwrap();
        let mut out = Vec::new();
        EthernetFrame::write_ethernet(
            &mut out,
            frame.destination,
            frame.source,
            0x0806,
            frame.payload,
        );
        assert_eq!(out.as_slice(), &ARP_REQUEST[..]);
    }

    #[test]
    fn write_then_parse_roundtrip() {
        let dst = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let src = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let payload = [0xde, 0xad, 0xbe, 0xef];

        let mut bytes = Vec::new();
        EthernetFrame::write_ethernet(&mut bytes, dst, src, 0x0800, &payload);

        let frame = EthernetFrame::parse(&bytes).unwrap();
        assert_eq!(frame.destination, dst);
        assert_eq!(frame.source, src);
        assert_eq!(frame.ethertype, EthernetType::Ipv4);
        assert_eq!(frame.payload, &payload);
    }

    #[test]
    fn mac_address_display() {
        assert_eq!(
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).to_string(),
            "02:00:00:00:00:01"
        );
        assert_eq!(MacAddress([0xff; 6]).to_string(), "ff:ff:ff:ff:ff:ff");
    }
}

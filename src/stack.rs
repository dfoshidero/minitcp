//! The stack itself: bytes in, [`Outcome`] out.
//!
//! [`Stack::handle`] is deliberately *sans-io*. It opens no sockets, reads no
//! clock, and prints nothing — it takes one Ethernet frame and returns what it
//! made of it. That is what lets the same code run against a TAP device, a pcap
//! file, a hex dump, or a `Vec<u8>` in a unit test.

use std::net::Ipv4Addr;

use crate::event::{
    ArpOperation, DropReason, Dropped, Echo, Endpoints, Layer, Outcome, Scope, Step,
};
use crate::proto::arp::{OUR_IP, OUR_MAC, reply_for};
use crate::proto::ethernet::{EthernetFrame, EthernetType, MacAddress};
use crate::proto::icmp::{make_echo_reply, set_echo_id};
use crate::proto::ipv4::{Ipv4Packet, Protocol};

/// A kind of traffic to discard on purpose, so you can watch what breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropKind {
    Arp,
    Icmp,
    Ip,
}

impl DropKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Icmp => "icmp",
            Self::Ip => "ip",
        }
    }
}

/// Who the stack is on the wire, and which packets it should deliberately lose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackConfig {
    /// The IPv4 address this stack answers for.
    pub addr: Ipv4Addr,
    /// The MAC address it advertises in ARP replies.
    pub mac: MacAddress,
    /// TTL written on outgoing IPv4 packets.
    pub ttl: u8,
    /// Override the ICMP echo identifier on replies instead of echoing it back.
    pub icmp_id: Option<u16>,
    /// Protocols to discard on arrival.
    pub drop: Vec<DropKind>,
    /// Percentage of frames to discard at random, before anything is decoded.
    pub drop_pct: u8,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::from(OUR_IP),
            mac: OUR_MAC,
            ttl: 64,
            icmp_id: None,
            drop: Vec::new(),
            drop_pct: 0,
        }
    }
}

pub struct Stack {
    config: StackConfig,
    rng: SeededRng,
}

impl Stack {
    pub fn new(config: StackConfig) -> Self {
        Self {
            config,
            rng: SeededRng::from_entropy(),
        }
    }

    /// Same stack with a fixed random seed, so `drop_pct` is reproducible.
    pub fn with_seed(config: StackConfig, seed: u64) -> Self {
        Self {
            config,
            rng: SeededRng::new(seed),
        }
    }

    pub fn config(&self) -> &StackConfig {
        &self.config
    }

    /// Decode one Ethernet frame and decide what, if anything, to send back.
    pub fn handle(&mut self, bytes: &[u8]) -> Outcome {
        let mut out = Outcome::default();
        let our_ip = self.config.addr.octets();
        let our_mac = self.config.mac;

        let frame = match EthernetFrame::parse(bytes) {
            Ok(frame) => frame,
            Err(e) => {
                out.drop_at("ethernet", "L2", Scope::Link, e);
                return out;
            }
        };
        out.link = Some(Endpoints::new(frame.source, frame.destination));

        if drop_pct_hit(self.config.drop_pct, &mut self.rng) {
            out.drop_at("ethernet", "L2", Scope::Link, DropReason::RandomLoss);
            return out;
        }
        if self.drops(DropKind::Arp) && frame.ethertype == EthernetType::Arp {
            out.drop_at("arp", "L2", Scope::Link, DropReason::Filtered);
            return out;
        }
        if self.drops(DropKind::Ip) && frame.ethertype == EthernetType::Ipv4 {
            out.drop_at("ipv4", "L3", Scope::Link, DropReason::Filtered);
            return out;
        }

        match frame.ethertype {
            EthernetType::Arp => self.handle_arp(&mut out, &frame, our_ip, our_mac),
            EthernetType::Ipv4 => self.handle_ipv4(&mut out, &frame, our_ip, our_mac),
            EthernetType::Unknown(_) => out.step_in(ethernet_layer(&frame)),
        }
        out
    }

    fn drops(&self, kind: DropKind) -> bool {
        self.config.drop.contains(&kind)
    }

    fn handle_arp(
        &self,
        out: &mut Outcome,
        frame: &EthernetFrame<'_>,
        our_ip: [u8; 4],
        our_mac: MacAddress,
    ) {
        let addresses = arp_addresses(frame.payload);
        let operation = arp_operation(frame.payload);

        let Some(reply) = reply_for(frame.payload, our_ip, our_mac) else {
            // Not for us, or not a request. Report what arrived and stop.
            out.step_in(ethernet_layer(frame));
            out.step_in(Layer::Arp {
                operation,
                addresses,
                sender_mac: None,
            });
            return;
        };

        let Some(asked) = addresses else {
            out.drop_at("arp", "L2", Scope::Link, DropReason::TruncatedArp);
            return;
        };

        let mut ethernet_reply = Vec::new();
        EthernetFrame::write_ethernet(&mut ethernet_reply, frame.source, our_mac, 0x0806, &reply);

        out.step_in(ethernet_layer(frame));
        out.step_in(Layer::Arp {
            operation,
            addresses,
            sender_mac: None,
        });
        out.steps.push(Step::Out(Layer::Ethernet {
            source: our_mac,
            destination: frame.source,
            ethertype: 0x0806,
        }));
        out.steps.push(Step::Out(Layer::Arp {
            operation: ArpOperation::Reply,
            addresses: Some(Endpoints::new(Ipv4Addr::from(our_ip), asked.source)),
            sender_mac: Some(our_mac),
        }));
        out.reply = Some(ethernet_reply);
    }

    fn handle_ipv4(
        &self,
        out: &mut Outcome,
        frame: &EthernetFrame<'_>,
        our_ip: [u8; 4],
        our_mac: MacAddress,
    ) {
        let packet = match Ipv4Packet::parse(frame.payload) {
            Ok(packet) => packet,
            Err(e) => {
                out.step_in(ethernet_layer(frame));
                out.drop_at("ipv4", "L3", Scope::Network, e);
                return;
            }
        };
        out.network = Some(Endpoints::new(packet.source, packet.destination));
        out.step_in(ethernet_layer(frame));
        out.step_in(Layer::Ipv4 {
            source: packet.source,
            destination: packet.destination,
            ttl: packet.ttl,
            protocol: packet.protocol,
            payload_len: packet.payload.len(),
        });

        match packet.protocol {
            Protocol::Icmp => {
                if packet.destination.octets() != our_ip {
                    out.drop_at("icmp", "L3", Scope::Payload, DropReason::NotForUs);
                    return;
                }
                if self.drops(DropKind::Icmp) {
                    out.drop_at("icmp", "L3", Scope::Payload, DropReason::Filtered);
                    return;
                }
                out.step_in(icmp_layer(packet.payload));

                let mut icmp_reply = match make_echo_reply(packet.payload) {
                    Ok(reply) => reply,
                    Err(e) => {
                        out.drop_at("icmp", "L3", Scope::Payload, e);
                        return;
                    }
                };
                if let Some(id) = self.config.icmp_id {
                    set_echo_id(&mut icmp_reply, id);
                }

                let mut ip_packet = Vec::new();
                Ipv4Packet::write(
                    &mut ip_packet,
                    self.config.ttl,
                    Protocol::Icmp,
                    Ipv4Addr::from(our_ip),
                    packet.source,
                    &icmp_reply,
                );
                let mut ethernet_reply = Vec::new();
                EthernetFrame::write_ethernet(
                    &mut ethernet_reply,
                    frame.source,
                    our_mac,
                    0x0800,
                    &ip_packet,
                );

                out.steps.push(Step::Out(Layer::Ethernet {
                    source: our_mac,
                    destination: frame.source,
                    ethertype: 0x0800,
                }));
                out.steps.push(Step::Out(Layer::Ipv4 {
                    source: Ipv4Addr::from(our_ip),
                    destination: packet.source,
                    ttl: self.config.ttl,
                    protocol: Protocol::Icmp,
                    payload_len: icmp_reply.len(),
                }));
                out.steps.push(Step::Out(icmp_layer(&icmp_reply)));
                out.reply = Some(ethernet_reply);
            }
            // Milestones 7-14 replace these with real handlers.
            Protocol::Udp | Protocol::Tcp => {
                let layer = if packet.protocol == Protocol::Udp {
                    "udp"
                } else {
                    "tcp"
                };
                out.drop_at(layer, "L4", Scope::Payload, DropReason::NotImplemented);
            }
            Protocol::Unknown(n) => {
                out.drop_at("ipv4", "L3", Scope::Network, DropReason::UnknownProtocol(n));
            }
        }
    }
}

impl Outcome {
    fn step_in(&mut self, layer: Layer) {
        self.steps.push(Step::In(layer));
    }

    fn drop_at(
        &mut self,
        layer: &'static str,
        osi: &'static str,
        scope: Scope,
        reason: impl Into<DropReason>,
    ) {
        self.steps.push(Step::Drop(Dropped {
            layer,
            osi,
            scope,
            reason: reason.into(),
        }));
    }
}

fn ethernet_layer(frame: &EthernetFrame<'_>) -> Layer {
    Layer::Ethernet {
        source: frame.source,
        destination: frame.destination,
        ethertype: match frame.ethertype {
            EthernetType::Ipv4 => 0x0800,
            EthernetType::Arp => 0x0806,
            EthernetType::Unknown(n) => n,
        },
    }
}

fn icmp_layer(message: &[u8]) -> Layer {
    Layer::Icmp {
        kind: if message.is_empty() { 0 } else { message[0] },
        code: if message.len() < 2 { 0 } else { message[1] },
        echo: (message.len() >= 8).then(|| Echo {
            id: u16::from_be_bytes([message[4], message[5]]),
            sequence: u16::from_be_bytes([message[6], message[7]]),
        }),
        len: message.len(),
    }
}

fn arp_addresses(payload: &[u8]) -> Option<Endpoints<Ipv4Addr>> {
    if payload.len() < 28 {
        return None;
    }
    Some(Endpoints::new(
        Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]),
        Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]),
    ))
}

fn arp_operation(payload: &[u8]) -> ArpOperation {
    if payload.len() < 8 {
        return ArpOperation::Other(0);
    }
    ArpOperation::from_number(u16::from_be_bytes([payload[6], payload[7]]))
}

/// xorshift64. Not cryptographic — it only decides which packets to lose, and
/// being reproducible from a seed is the point.
struct SeededRng {
    state: u64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn from_entropy() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        Self::new(nanos)
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x >> 32) as u32
    }
}

fn drop_pct_hit(pct: u8, rng: &mut SeededRng) -> bool {
    if pct == 0 {
        return false;
    }
    if pct >= 100 {
        return true;
    }
    (rng.next_u32() % 100) < u32::from(pct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::checksum::internet_checksum;

    const ARP_REQUEST: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];

    pub(crate) fn ping_frame() -> Vec<u8> {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, b'h', b'i'];
        let sum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut ip = Vec::new();
        Ipv4Packet::write(
            &mut ip,
            64,
            Protocol::Icmp,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            &icmp,
        );
        let mut eth = Vec::new();
        EthernetFrame::write_ethernet(
            &mut eth,
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            0x0800,
            &ip,
        );
        eth
    }

    fn reply(config: StackConfig, frame: &[u8]) -> Option<Vec<u8>> {
        Stack::with_seed(config, 1).handle(frame).reply
    }

    #[test]
    fn handle_replies_to_arp() {
        let config = StackConfig::default();
        let mac = config.mac;
        let out = reply(config, &ARP_REQUEST).expect("arp reply");
        assert_eq!(&out[0..6], &ARP_REQUEST[6..12]);
        assert_eq!(&out[6..12], &mac.0);
        assert_eq!(&out[12..14], &[0x08, 0x06]);
    }

    #[test]
    fn outcome_describes_the_arp_exchange() {
        let out = Stack::with_seed(StackConfig::default(), 1).handle(&ARP_REQUEST);
        assert!(!out.dropped());
        assert_eq!(
            out.link.unwrap().source,
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        let asked = out
            .inbound(|l| matches!(l, Layer::Arp { .. }))
            .copied()
            .unwrap();
        let Layer::Arp {
            operation,
            addresses,
            ..
        } = asked
        else {
            panic!("expected arp");
        };
        assert_eq!(operation, ArpOperation::Request);
        assert_eq!(addresses.unwrap().destination, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn drop_arp_produces_no_write_icmp_still_replies() {
        let config = StackConfig {
            drop: vec![DropKind::Arp],
            ..StackConfig::default()
        };
        assert!(reply(config.clone(), &ARP_REQUEST).is_none());
        assert!(reply(config, &ping_frame()).is_some());
    }

    #[test]
    fn drop_icmp_produces_no_write_arp_still_replies() {
        let config = StackConfig {
            drop: vec![DropKind::Icmp],
            ..StackConfig::default()
        };
        assert!(reply(config.clone(), &ping_frame()).is_none());
        assert!(reply(config, &ARP_REQUEST).is_some());
    }

    #[test]
    fn drop_ip_ignores_ipv4_but_not_arp() {
        let config = StackConfig {
            drop: vec![DropKind::Ip],
            ..StackConfig::default()
        };
        assert!(reply(config.clone(), &ping_frame()).is_none());
        assert!(reply(config, &ARP_REQUEST).is_some());
    }

    #[test]
    fn drop_arp_and_icmp_together() {
        let config = StackConfig {
            drop: vec![DropKind::Arp, DropKind::Icmp],
            ..StackConfig::default()
        };
        assert!(reply(config.clone(), &ARP_REQUEST).is_none());
        assert!(reply(config, &ping_frame()).is_none());
    }

    #[test]
    fn drop_pct_zero_never_hundred_always_fifty_is_deterministic() {
        let mut rng = SeededRng::new(42);
        for _ in 0..32 {
            assert!(!drop_pct_hit(0, &mut rng));
        }
        let mut rng = SeededRng::new(42);
        for _ in 0..32 {
            assert!(drop_pct_hit(100, &mut rng));
        }
        let mut a = SeededRng::new(7);
        let mut b = SeededRng::new(7);
        let seq_a: Vec<bool> = (0..20).map(|_| drop_pct_hit(50, &mut a)).collect();
        let seq_b: Vec<bool> = (0..20).map(|_| drop_pct_hit(50, &mut b)).collect();
        assert_eq!(seq_a, seq_b);
        assert!(seq_a.iter().any(|h| *h) && seq_a.iter().any(|h| !*h));
    }

    #[test]
    fn ttl_and_id_on_icmp_reply() {
        let config = StackConfig {
            ttl: 32,
            icmp_id: Some(0x9999),
            ..StackConfig::default()
        };
        let out = reply(config, &ping_frame()).expect("icmp reply");
        let frame = EthernetFrame::parse(&out).unwrap();
        let ip = Ipv4Packet::parse(frame.payload).unwrap();
        assert_eq!(ip.ttl, 32);
        assert_eq!(&ip.payload[4..6], &[0x99, 0x99]);
        assert_eq!(internet_checksum(ip.payload), 0);

        let default = reply(StackConfig::default(), &ping_frame()).unwrap();
        let default_ip =
            Ipv4Packet::parse(EthernetFrame::parse(&default).unwrap().payload).unwrap();
        assert_eq!(default_ip.ttl, 64);
        assert_eq!(&default_ip.payload[4..6], &[0x12, 0x34]);
    }

    #[test]
    fn unhandled_transports_are_reported_not_answered() {
        let mut ip = Vec::new();
        Ipv4Packet::write(
            &mut ip,
            64,
            Protocol::Tcp,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            &[0u8; 20],
        );
        let mut eth = Vec::new();
        EthernetFrame::write_ethernet(
            &mut eth,
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            0x0800,
            &ip,
        );
        let out = Stack::with_seed(StackConfig::default(), 1).handle(&eth);
        assert!(out.reply.is_none());
        assert!(out.dropped());
        let Some(Step::Drop(dropped)) = out.steps.last() else {
            panic!("expected a drop");
        };
        assert_eq!(dropped.layer, "tcp");
        assert_eq!(dropped.reason, DropReason::NotImplemented);
    }

    #[test]
    fn truncated_frame_drops_before_any_endpoints_are_known() {
        let out = Stack::with_seed(StackConfig::default(), 1).handle(&[0u8; 13]);
        assert!(out.link.is_none());
        assert!(out.dropped());
    }

    #[test]
    fn echo_id_helper_rewrites_checksum() {
        let frame = ping_frame();
        let eth = EthernetFrame::parse(&frame).unwrap();
        let ip = Ipv4Packet::parse(eth.payload).unwrap();
        let mut reply = make_echo_reply(ip.payload).unwrap();
        set_echo_id(&mut reply, 7);
        assert_eq!(&reply[4..6], &[0x00, 0x07]);
        assert_eq!(internet_checksum(&reply), 0);
    }
}

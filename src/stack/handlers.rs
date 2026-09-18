//! Per-protocol handlers: what to do with a decoded IPv4 payload.
//!
//! [`crate::stack::Stack::handle`] decodes down to IPv4 and then dispatches
//! here. Each handler owns one protocol end to end — its own "is this for us?"
//! and filter checks, its reply, and the [`Step`]s describing both. They take
//! `&StackConfig` rather than `&Stack` so they stay plain functions: no state,
//! no I/O, callable directly from a test.

use std::net::Ipv4Addr;

use crate::event::{DropReason, Echo, Layer, Outcome, Scope, Step};
use crate::proto::ethernet::EthernetFrame;
use crate::proto::icmp::{make_echo_reply, set_echo_id};
use crate::proto::ipv4::{Ipv4Packet, Protocol};
use crate::stack::{DropKind, StackConfig};

/// Answer an ICMP echo request addressed to us.
///
/// The caller has already pushed the inbound Ethernet and IPv4 steps; this adds
/// the ICMP step, then either a drop or the full outbound trio plus the reply.
pub(crate) fn handle_icmp(
    out: &mut Outcome,
    config: &StackConfig,
    frame: &EthernetFrame<'_>,
    packet: &Ipv4Packet<'_>,
) {
    let our_ip = config.addr.octets();
    let our_mac = config.mac;

    if packet.destination.octets() != our_ip {
        out.drop_at("icmp", "L3", Scope::Payload, DropReason::NotForUs);
        return;
    }
    if config.drop.contains(&DropKind::Icmp) {
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
    if let Some(id) = config.icmp_id {
        set_echo_id(&mut icmp_reply, id);
    }

    let mut ip_packet = Vec::new();
    Ipv4Packet::write(
        &mut ip_packet,
        config.ttl,
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
        ttl: config.ttl,
        protocol: Protocol::Icmp,
        payload_len: icmp_reply.len(),
    }));
    out.steps.push(Step::Out(icmp_layer(&icmp_reply)));
    out.reply = Some(ethernet_reply);
}

/// Describe an ICMP message for the step log, tolerating short ones.
pub(crate) fn icmp_layer(message: &[u8]) -> Layer {
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

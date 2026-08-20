// The stack itself: one frame in, at most one frame out.
//
// `handle_frame` is where minitcp decides what it is looking at and what, if
// anything, to say back — Ethernet header first, then ARP or IPv4, then ICMP
// inside that. Everything it needs to parse or build lives in `proto`; this
// file is the dispatch and the narration, not the wire formats.
//
// It is deliberately a pure function of (config, bytes) plus the RNG: no
// sockets, no files, no clock. That is what makes the whole stack testable by
// handing it a byte array.

use std::net::Ipv4Addr;

use crate::cli::{Config, DropKind};
use crate::log::{self, Verb};
use crate::proto::arp::reply_for;
use crate::proto::ethernet::{EthernetFrame, EthernetType};
use crate::proto::icmp::{make_echo_reply, set_echo_id};
use crate::proto::ipv4::{Ipv4Packet, Protocol};

use super::rng::{SeededRng, drop_pct_hit};

fn protocol_name(protocol: Protocol) -> String {
    match protocol {
        Protocol::Icmp => "icmp".into(),
        Protocol::Udp => "udp".into(),
        Protocol::Tcp => "tcp".into(),
        Protocol::Unknown(n) => format!("protocol {n}"),
    }
}

fn icmp_id_seq(message: &[u8]) -> Option<(u16, u16)> {
    if message.len() < 8 {
        return None;
    }
    Some((
        u16::from_be_bytes([message[4], message[5]]),
        u16::from_be_bytes([message[6], message[7]]),
    ))
}

fn icmp_quiet(message: &[u8]) -> String {
    let (id, seq) = icmp_id_seq(message).unwrap_or((0, 0));
    format!("echo id={id} seq={seq}  len={}", message.len())
}

fn icmp_decode(message: &[u8]) -> String {
    let Some((id, seq)) = icmp_id_seq(message) else {
        return "truncated".into();
    };
    format!(
        "type={} code={} id={id} seq={seq}  len={}",
        message[0],
        message[1],
        message.len()
    )
}

fn arp_addrs(payload: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if payload.len() < 28 {
        return None;
    }
    Some((
        Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]),
        Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]),
    ))
}

fn ip_pair(src: Ipv4Addr, dst: Ipv4Addr) -> String {
    format!("{src} -> {dst}")
}

pub(super) fn handle_frame(cfg: &Config, bytes: &[u8], rng: &mut SeededRng) -> Option<Vec<u8>> {
    let verbose = cfg.verbose();
    let our_ip = cfg.our_ip_bytes();
    let our_mac = cfg.mac;
    let when = log::now();

    let frame = match EthernetFrame::parse(bytes) {
        Ok(frame) => frame,
        Err(e) => {
            log::emit_at(&when, Verb::Drop, "ethernet", "L2", "", e);
            return None;
        }
    };

    let macs = format!("{} -> {}", frame.source, frame.destination);

    if drop_pct_hit(cfg.drop_pct, rng) {
        log::emit_at(&when, Verb::Drop, "ethernet", "L2", &macs, "random drop");
        return None;
    }
    if cfg.drop.contains(&DropKind::Arp) && frame.ethertype == EthernetType::Arp {
        log::emit_at(&when, Verb::Drop, "arp", "L2", &macs, "dropped");
        return None;
    }
    if cfg.drop.contains(&DropKind::Ip) && frame.ethertype == EthernetType::Ipv4 {
        log::emit_at(&when, Verb::Drop, "ipv4", "L3", &macs, "dropped");
        return None;
    }

    match frame.ethertype {
        EthernetType::Arp => {
            let Some(reply) = reply_for(frame.payload, our_ip, our_mac) else {
                if verbose {
                    log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0806");
                    let arp_addrs = arp_addrs(frame.payload)
                        .map(|(spa, tpa)| ip_pair(spa, tpa))
                        .unwrap_or_default();
                    log::emit_cont(&when, Verb::More, "arp", "L2", &arp_addrs, "who-has");
                }
                return None;
            };

            let Some((spa, tpa)) = arp_addrs(frame.payload) else {
                log::emit_at(
                    &when,
                    Verb::Drop,
                    "arp",
                    "L2",
                    &macs,
                    "truncated ARP payload",
                );
                return None;
            };
            let mut ethernet_reply = Vec::new();
            EthernetFrame::write_ethernet(
                &mut ethernet_reply,
                frame.source,
                our_mac,
                0x0806,
                &reply,
            );

            if verbose {
                log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0806");
                log::emit_cont(
                    &when,
                    Verb::More,
                    "arp",
                    "L2",
                    &ip_pair(spa, tpa),
                    "who-has",
                );
                log::emit_cont(
                    &when,
                    Verb::Out,
                    "ethernet",
                    "L2",
                    &format!("{} -> {}", our_mac, frame.source),
                    "ethertype 0x0806",
                );
                log::emit_cont(
                    &when,
                    Verb::More,
                    "arp",
                    "L2",
                    &ip_pair(Ipv4Addr::from(our_ip), spa),
                    &format!("is-at {our_mac}"),
                );
            } else {
                log::emit_quiet(&when, "arp", &ip_pair(spa, tpa), "who-has");
            }
            return Some(ethernet_reply);
        }
        EthernetType::Ipv4 => match Ipv4Packet::parse(frame.payload) {
            Ok(packet) => {
                let ip_addrs = ip_pair(packet.source, packet.destination);
                if verbose {
                    log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0800");
                    log::emit_cont(
                        &when,
                        Verb::More,
                        "ipv4",
                        "L3",
                        &ip_addrs,
                        &format!(
                            "ttl={} proto={} payload={}",
                            packet.ttl,
                            protocol_name(packet.protocol),
                            packet.payload.len()
                        ),
                    );
                }

                match packet.protocol {
                    Protocol::Icmp => {
                        if packet.destination.octets() != our_ip {
                            if verbose {
                                log::emit_inside(&when, Verb::Drop, "icmp", "L3", "not for us");
                            } else {
                                log::emit_at(
                                    &when,
                                    Verb::Drop,
                                    "icmp",
                                    "L3",
                                    &ip_addrs,
                                    "not for us",
                                );
                            }
                            return None;
                        }
                        if cfg.drop.contains(&DropKind::Icmp) {
                            if verbose {
                                log::emit_inside(&when, Verb::Drop, "icmp", "L3", "dropped");
                            } else {
                                log::emit_at(&when, Verb::Drop, "icmp", "L3", &ip_addrs, "dropped");
                            }
                            return None;
                        }
                        if verbose {
                            log::emit_inside(
                                &when,
                                Verb::More,
                                "icmp",
                                "L3",
                                &icmp_decode(packet.payload),
                            );
                        }

                        match make_echo_reply(packet.payload) {
                            Ok(mut icmp_reply) => {
                                if let Some(id) = cfg.icmp_id {
                                    set_echo_id(&mut icmp_reply, id);
                                }
                                let mut ip_packet = Vec::new();
                                Ipv4Packet::write(
                                    &mut ip_packet,
                                    cfg.ttl,
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
                                if verbose {
                                    log::emit_cont(
                                        &when,
                                        Verb::Out,
                                        "ethernet",
                                        "L2",
                                        &format!("{} -> {}", our_mac, frame.source),
                                        "ethertype 0x0800",
                                    );
                                    log::emit_cont(
                                        &when,
                                        Verb::More,
                                        "ipv4",
                                        "L3",
                                        &ip_pair(Ipv4Addr::from(our_ip), packet.source),
                                        &format!(
                                            "ttl={} proto=icmp payload={}",
                                            cfg.ttl,
                                            icmp_reply.len()
                                        ),
                                    );
                                    log::emit_inside(
                                        &when,
                                        Verb::More,
                                        "icmp",
                                        "L3",
                                        &icmp_decode(&icmp_reply),
                                    );
                                } else {
                                    log::emit_quiet(
                                        &when,
                                        "icmp",
                                        &ip_addrs,
                                        &icmp_quiet(packet.payload),
                                    );
                                }
                                return Some(ethernet_reply);
                            }
                            Err(e) => {
                                if verbose {
                                    log::emit_inside(&when, Verb::Drop, "icmp", "L3", e);
                                } else {
                                    log::emit_at(&when, Verb::Drop, "icmp", "L3", &ip_addrs, e);
                                }
                            }
                        }
                    }
                    Protocol::Udp => {
                        if verbose {
                            log::emit_inside(&when, Verb::Drop, "udp", "L4", "not implemented");
                        } else {
                            log::emit_at(
                                &when,
                                Verb::Drop,
                                "udp",
                                "L4",
                                &ip_addrs,
                                "not implemented",
                            );
                        }
                    }
                    Protocol::Tcp => {
                        if verbose {
                            log::emit_inside(&when, Verb::Drop, "tcp", "L4", "not implemented");
                        } else {
                            log::emit_at(
                                &when,
                                Verb::Drop,
                                "tcp",
                                "L4",
                                &ip_addrs,
                                "not implemented",
                            );
                        }
                    }
                    Protocol::Unknown(n) => {
                        let reason = format!("unknown protocol {n}");
                        if verbose {
                            log::emit_cont(&when, Verb::Drop, "ipv4", "L3", "", &reason);
                        } else {
                            log::emit_at(&when, Verb::Drop, "ipv4", "L3", &ip_addrs, &reason);
                        }
                    }
                }
            }
            Err(e) => {
                if verbose {
                    log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0800");
                    log::emit_cont(&when, Verb::Drop, "ipv4", "L3", "", e);
                } else {
                    log::emit_at(&when, Verb::Drop, "ipv4", "L3", "", e);
                }
            }
        },
        EthernetType::Unknown(n) => {
            if verbose {
                log::emit_at(
                    &when,
                    Verb::In,
                    "ethernet",
                    "L2",
                    &macs,
                    &format!("ethertype 0x{n:04x}"),
                );
            }
        }
    }
    None
}

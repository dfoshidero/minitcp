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
use crate::proto::arp::{self, reply_for};
use crate::proto::ethernet::{EthernetFrame, EthernetType};
use crate::proto::icmp::{self, make_echo_reply, set_echo_id};
use crate::proto::ipv4::{Ipv4Packet, Protocol};

use super::rng::{SeededRng, drop_pct_hit};

fn icmp_quiet(message: &[u8]) -> String {
    let (id, seq) = icmp::id_seq(message).unwrap_or((0, 0));
    format!("echo id={id} seq={seq}  len={}", message.len())
}

fn icmp_decode(message: &[u8]) -> String {
    let Some((id, seq)) = icmp::id_seq(message) else {
        return "truncated".into();
    };
    format!(
        "type={} code={} id={id} seq={seq}  len={}",
        message[0],
        message[1],
        message.len()
    )
}

fn ip_pair(src: Ipv4Addr, dst: Ipv4Addr) -> String {
    format!("{src} -> {dst}")
}

/// A drop of something carried inside an IPv4 packet, in whichever shape the
/// trace is using: a leaf under the ipv4 line when verbose, where the addresses
/// are already on screen, or a line of its own carrying them when not.
fn drop_in_packet(when: &str, verbose: bool, layer: &str, osi: &str, addrs: &str, reason: &str) {
    if verbose {
        log::emit_inside(when, Verb::Drop, layer, osi, reason);
    } else {
        log::emit_at(when, Verb::Drop, layer, osi, addrs, reason);
    }
}

/// The two verbose lines every incoming ARP frame produces, whether or not we
/// end up answering it. `addrs` is `None` when the payload was too short to
/// hold them.
fn trace_arp_request(when: &str, macs: &str, addrs: Option<(Ipv4Addr, Ipv4Addr)>) {
    log::emit_at(when, Verb::In, "ethernet", "L2", macs, "ethertype 0x0806");
    let addrs = addrs
        .map(|(spa, tpa)| ip_pair(spa, tpa))
        .unwrap_or_default();
    log::emit_cont(when, Verb::More, "arp", "L2", &addrs, "who-has");
}

pub(super) fn handle_frame(cfg: &Config, bytes: &[u8], rng: &mut SeededRng) -> Option<Vec<u8>> {
    let verbose = cfg.verbose;
    let our_ip = cfg.addr;
    let our_mac = cfg.mac;
    let when = log::timestamp();

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
            let addrs = arp::addresses(frame.payload);
            let Some(reply) = reply_for(frame.payload, our_ip, our_mac) else {
                if verbose {
                    trace_arp_request(&when, &macs, addrs);
                }
                return None;
            };

            // `reply_for` already read these, so this cannot fail here.
            let Some((spa, tpa)) = addrs else {
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
                trace_arp_request(&when, &macs, addrs);
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
                    &ip_pair(our_ip, spa),
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
                            packet.protocol,
                            packet.payload.len()
                        ),
                    );
                }

                match packet.protocol {
                    Protocol::Icmp => {
                        if packet.destination != our_ip {
                            drop_in_packet(&when, verbose, "icmp", "L3", &ip_addrs, "not for us");
                            return None;
                        }
                        if cfg.drop.contains(&DropKind::Icmp) {
                            drop_in_packet(&when, verbose, "icmp", "L3", &ip_addrs, "dropped");
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
                                    our_ip,
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
                                        &ip_pair(our_ip, packet.source),
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
                            Err(e) => drop_in_packet(&when, verbose, "icmp", "L3", &ip_addrs, e),
                        }
                    }
                    Protocol::Udp => {
                        drop_in_packet(&when, verbose, "udp", "L4", &ip_addrs, "not implemented");
                    }
                    Protocol::Tcp => {
                        drop_in_packet(&when, verbose, "tcp", "L4", &ip_addrs, "not implemented");
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

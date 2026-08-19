// src/stack.rs

use std::net::Ipv4Addr;
use std::path::Path;

use crate::interface::tap::TapInterface;
use crate::log::{self, Verb};
use crate::proto::arp::{reply_for, OUR_IP, OUR_MAC};
use crate::proto::ethernet::{EthernetFrame, EthernetType};
use crate::proto::icmp::make_echo_reply;
use crate::proto::ipv4::{Ipv4Packet, Protocol};

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
    if message.len() < 8 {
        return "truncated".into();
    }
    let (id, seq) = icmp_id_seq(message).unwrap();
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

fn open_tap0() -> TapInterface {
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("cannot open /dev/net/tun. Reopen this folder in the Dev Container.");
        std::process::exit(1);
    }

    if !Path::new("/sys/class/net/tap0").exists() {
        eprintln!("tap0 is not up yet. Create it first:");
        eprintln!("  ./scripts/setup-tap.sh");
        std::process::exit(1);
    }

    match TapInterface::open("tap0") {
        Ok(tap) => tap,
        Err(e) => {
            eprintln!("cannot attach to tap0: {e}");
            eprintln!("Try:  ./scripts/setup-tap.sh");
            std::process::exit(1);
        }
    }
}

pub fn run_stack(verbose: bool) -> std::io::Result<()> {
    let mut tap = open_tap0();
    let mut buffer = [0u8; 2048];
    loop {
        let n = tap.read_frame(&mut buffer)?;
        let when = log::now();

        let frame = match EthernetFrame::parse(&buffer[..n]) {
            Ok(frame) => frame,
            Err(e) => {
                log::emit_at(&when, Verb::Drop, "ethernet", "L2", "", e);
                continue;
            }
        };

        let macs = format!("{} -> {}", frame.source, frame.destination);

        match frame.ethertype {
            EthernetType::Arp => {
                let Some(reply) = reply_for(frame.payload) else {
                    if verbose {
                        log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0806");
                        let arp_addrs = arp_addrs(frame.payload)
                            .map(|(spa, tpa)| ip_pair(spa, tpa))
                            .unwrap_or_default();
                        log::emit_cont(&when, Verb::More, "arp", "L2", &arp_addrs, "who-has");
                    }
                    continue;
                };

                let (spa, tpa) = arp_addrs(frame.payload).unwrap();
                let mut ethernet_reply = Vec::new();
                EthernetFrame::write_ethernet(
                    &mut ethernet_reply,
                    frame.source,
                    OUR_MAC,
                    0x0806,
                    &reply,
                );
                tap.write_frame(&ethernet_reply)?;

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
                        &format!("{} -> {}", OUR_MAC, frame.source),
                        "ethertype 0x0806",
                    );
                    log::emit_cont(
                        &when,
                        Verb::More,
                        "arp",
                        "L2",
                        &ip_pair(Ipv4Addr::from(OUR_IP), spa),
                        &format!("is-at {OUR_MAC}"),
                    );
                } else {
                    log::emit_quiet(&when, "arp", &ip_pair(spa, tpa), "who-has");
                }
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
                            if packet.destination.octets() != OUR_IP {
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
                                continue;
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
                                Ok(icmp_reply) => {
                                    let mut ip_packet = Vec::new();
                                    Ipv4Packet::write(
                                        &mut ip_packet,
                                        64,
                                        Protocol::Icmp,
                                        Ipv4Addr::from(OUR_IP),
                                        packet.source,
                                        &icmp_reply,
                                    );
                                    let mut ethernet_reply = Vec::new();
                                    EthernetFrame::write_ethernet(
                                        &mut ethernet_reply,
                                        frame.source,
                                        OUR_MAC,
                                        0x0800,
                                        &ip_packet,
                                    );
                                    tap.write_frame(&ethernet_reply)?;

                                    if verbose {
                                        log::emit_cont(
                                            &when,
                                            Verb::Out,
                                            "ethernet",
                                            "L2",
                                            &format!("{} -> {}", OUR_MAC, frame.source),
                                            "ethertype 0x0800",
                                        );
                                        log::emit_cont(
                                            &when,
                                            Verb::More,
                                            "ipv4",
                                            "L3",
                                            &ip_pair(Ipv4Addr::from(OUR_IP), packet.source),
                                            &format!(
                                                "ttl=64 proto=icmp payload={}",
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
    }
}

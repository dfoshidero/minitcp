// src/stack.rs

use std::io::{self, BufReader};
use std::net::Ipv4Addr;
use std::path::Path;

use crate::cli::{Command, Config};
use crate::interface::pcap::{CaptureIo, HexReader, PcapReader, PcapWriter};
use crate::interface::tap::TapInterface;
use crate::interface::FrameIo;
use crate::log::{self, Verb};
use crate::proto::arp::reply_for;
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

fn open_tap(cfg: &Config) -> TapInterface {
    if !cfg.tun.exists() {
        eprintln!(
            "cannot open {}. Reopen this folder in the Dev Container.",
            cfg.tun.display()
        );
        std::process::exit(1);
    }

    let sys = format!("/sys/class/net/{}", cfg.iface);
    if !Path::new(&sys).exists() {
        eprintln!("{} is not up yet. Create it first:", cfg.iface);
        eprintln!("  ./scripts/setup-tap.sh");
        std::process::exit(1);
    }

    match TapInterface::open_at(&cfg.tun, &cfg.iface) {
        Ok(tap) => tap,
        Err(e) => {
            eprintln!("cannot attach to {}: {e}", cfg.iface);
            eprintln!("Try:  ./scripts/setup-tap.sh");
            std::process::exit(1);
        }
    }
}

pub fn run_stack(cfg: Config) -> std::io::Result<()> {
    if let Command::Replay(path) = &cfg.command {
        let reader = PcapReader::open(path)?;
        return run_io(cfg, reader);
    }
    if cfg.hex {
        return run_io(cfg, HexReader::new(BufReader::new(io::stdin())));
    }
    let tap = open_tap(&cfg);
    eprintln!("listening {} as {} ({})", cfg.iface, cfg.addr, cfg.mac);
    run_io(cfg, tap)
}

fn run_io<I: FrameIo>(cfg: Config, inner: I) -> std::io::Result<()> {
    let capture = match &cfg.write {
        Some(path) => Some(PcapWriter::create(path)?),
        None => None,
    };
    let mut frames = CaptureIo::new(inner, capture);
    let mut buffer = [0u8; 2048];
    loop {
        let n = frames.read_frame(&mut buffer)?;
        if n == 0 {
            return Ok(());
        }
        if let Some(reply) = handle_frame(&cfg, &buffer[..n]) {
            frames.write_frame(&reply)?;
        }
    }
}

fn handle_frame(cfg: &Config, bytes: &[u8]) -> Option<Vec<u8>> {
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

                let (spa, tpa) = arp_addrs(frame.payload).unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Config;
    use crate::interface::pcap::{pcap_info, PcapReader, PcapWriter};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ARP_REQUEST: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];

    fn tmp(name: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("minitcp-{name}-{n}.pcap"))
    }

    #[test]
    fn handle_frame_replies_to_arp() {
        let cfg = Config::defaults();
        let reply = handle_frame(&cfg, &ARP_REQUEST).expect("arp reply");
        assert_eq!(&reply[0..6], &ARP_REQUEST[6..12]);
        assert_eq!(&reply[6..12], &cfg.mac.0);
        assert_eq!(&reply[12..14], &[0x08, 0x06]);
    }

    #[test]
    fn pcap_write_replay_roundtrip_through_reader() {
        let path = tmp("round");
        {
            let mut w = PcapWriter::create(&path).unwrap();
            w.write_frame(&ARP_REQUEST).unwrap();
        }
        let mut r = PcapReader::open(&path).unwrap();
        let mut buf = [0u8; 2048];
        let n = r.read_frame(&mut buf).unwrap();
        assert_eq!(&buf[..n], &ARP_REQUEST);
        let info = pcap_info(&path).unwrap();
        assert!(info.contains("0x0806"));
        assert!(info.contains("1 frames"));
        let _ = fs::remove_file(path);
    }
}

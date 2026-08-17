// src/stack.rs

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::interface::tap::TapInterface;
use crate::proto::arp::{reply_for, OUR_IP, OUR_MAC};
use crate::proto::ethernet::{EthernetFrame, EthernetType};
use crate::proto::icmp::make_echo_reply;
use crate::proto::ipv4::{Ipv4Packet, Protocol};

fn open_tap0() -> TapInterface {
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("cannot open /dev/net/tun. Reopen this folder in the Dev Container.");
        std::process::exit(1);
    }

    if !Path::new("/sys/class/net/tap0").exists() {
        eprintln!("tap0 is not up yet. Create it first:");
        eprintln!("  ./setup-tap.sh");
        std::process::exit(1);
    }

    match TapInterface::open("tap0") {
        Ok(tap) => tap,
        Err(e) => {
            eprintln!("cannot attach to tap0: {e}");
            eprintln!("Try:  ./setup-tap.sh");
            std::process::exit(1);
        }
    }
}

fn log_line(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

pub fn run_stack() -> std::io::Result<()> {
    let mut tap = open_tap0();
    let mut buffer = [0u8; 2048];

    loop {
        let n = tap.read_frame(&mut buffer)?;

        let frame = match EthernetFrame::parse(&buffer[..n]) {
            Ok(frame) => frame,
            Err(e) => {
                log_line(&format!("bad ethernet frame: {e}"));
                continue;
            }
        };

        match frame.ethertype {
            EthernetType::Arp => {
                if let Some(reply) = reply_for(frame.payload) {
                    let mut ethernet_reply = Vec::new();
                    EthernetFrame::write_ethernet(
                        &mut ethernet_reply,
                        frame.source,
                        OUR_MAC,
                        0x0806,
                        &reply,
                    );
                    tap.write_frame(&ethernet_reply)?;
                    log_line("arp who-has -> is-at");
                }
            }
            EthernetType::Ipv4 => match Ipv4Packet::parse(frame.payload) {
                Ok(packet) => match packet.protocol {
                    Protocol::Icmp => {
                        if packet.destination.octets() != OUR_IP {
                            log_line("icmp not for us");
                            continue;
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
                                log_line(&format!(
                                    "icmp echo {} -> {}",
                                    packet.source, packet.destination
                                ));
                            }
                            Err(e) => log_line(&format!("icmp drop: {e}")),
                        }
                    }
                    Protocol::Udp => log_line("UDP (to be implemented)"),
                    Protocol::Tcp => log_line("TCP (to be implemented)"),
                    Protocol::Unknown(n) => log_line(&format!("unknown IP protocol {n}")),
                },
                Err(e) => log_line(&format!("bad ipv4 packet: {e}")),
            },
            EthernetType::Unknown(_) => {}
        }
    }
}

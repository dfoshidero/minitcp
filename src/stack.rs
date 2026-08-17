// src/stack.rs

use std::io::Write;
use std::path::Path;

use crate::interface::tap::TapInterface;
use crate::proto::arp::{reply_for, OUR_MAC};
use crate::proto::ethernet::{EthernetFrame, EthernetType};
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
    // Comfortably larger than a typical 1500-byte Ethernet MTU plus headers.
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

        log_line(&format!(
            "{} -> {} {:?}",
            frame.source, frame.destination, frame.ethertype
        ));

        match frame.ethertype {
            EthernetType::Arp => {
                if let Some(arp_reply) = reply_for(frame.payload) {
                    let mut ethernet_reply = Vec::new();

                    EthernetFrame::write_ethernet(
                        &mut ethernet_reply,
                        frame.source, // their MAC from the Ethernet header (same as ARP SHA)
                        OUR_MAC,
                        0x0806, // same EtherType ethernet.rs maps to Arp
                        &arp_reply,
                    );

                    tap.write_frame(&ethernet_reply)?;
                }
            }
            EthernetType::Ipv4 => match Ipv4Packet::parse(frame.payload) {
                Ok(packet) => {
                    log_line(&format!(
                        "ipv4 {} -> {} ttl={} {:?}",
                        packet.source, packet.destination, packet.ttl, packet.protocol
                    ));
                    match packet.protocol {
                        Protocol::Icmp => log_line("ICMP (to be implemented)"),
                        Protocol::Udp => log_line("UDP (to be implemented)"),
                        Protocol::Tcp => log_line("TCP (to be implemented)"),
                        Protocol::Unknown(n) => log_line(&format!("unknown IP protocol {n}")),
                    }
                }
                Err(e) => log_line(&format!("bad ipv4 packet: {e}")),
            },
            EthernetType::Unknown(_) => {}
        }
    }
}

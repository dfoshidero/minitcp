// src/main.rs

mod arp;
mod checksum;
mod ethernet;
mod interface;
mod ipv4;

use std::path::Path;

use arp::{reply_for, OUR_MAC};
use ethernet::{EthernetFrame, EthernetType};
use interface::tap::TapInterface;
use ipv4::{Ipv4Packet, Protocol};

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

fn main() -> std::io::Result<()> {
    let mut tap = open_tap0();
    // Comfortably larger than a typical 1500-byte Ethernet MTU plus headers.
    let mut buffer = [0u8; 2048];

    loop {
        let n = tap.read_frame(&mut buffer)?;

        let frame = match EthernetFrame::parse(&buffer[..n]) {
            Ok(frame) => frame,
            Err(e) => {
                println!("bad ethernet frame: {e}");
                continue;
            }
        };
        
        println!(
            "{} -> {} {:?}",
            frame.source,
            frame.destination,
            frame.ethertype
        );

        match frame.ethertype{
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
                    println!("ipv4 {} -> {} ttl={} {:?}",
                    packet.source, packet.destination, packet.ttl, packet.protocol
                );
                // Inner dispatch: ipv4.rs already parsed byte 9. ICMP is ping; we don't reply yet.
                match packet.protocol {
                    Protocol::Icmp => println!("ICMP (to be implemented)"),
                    Protocol::Udp => println!("UDP (to be implemented)"),
                    Protocol::Tcp => println!("TCP (to be implemented)"),
                    Protocol::Unknown(n) => println!("unknown IP protocol {n}"),
                }
            }
            Err(e) => println!("bad ipv4 packet: {e}"),
        },
        EthernetType::Unknown(_) => {}
        }
    }
}

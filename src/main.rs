// src/main.rs

mod arp;
mod ethernet;
mod interface;

use arp::{reply_for, OUR_MAC};
use ethernet::{EthernetFrame, EthernetType};
use interface::tap::TapInterface;

fn main() -> std::io::Result<()> {
    let mut tap = TapInterface::open("tap0")?;
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

        if frame.ethertype != EthernetType::Arp {
            continue;
        }

        if let Some(arp_reply) = reply_for(frame.payload) {
            let mut ethernet_reply = Vec::new();

            EthernetFrame::write_ethernet(
                &mut ethernet_reply,
                frame.source,
                OUR_MAC,
                0x0806, // ARP type
                &arp_reply
            );

            tap.write_frame(&ethernet_reply)?;
        }
    }
}

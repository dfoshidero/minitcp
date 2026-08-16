// src/main.rs

mod ethernet;
mod interface;

use ethernet::EthernetFrame;
use interface::tap::TapInterface;

fn main() -> std::io::Result<()> {
    let mut tap = TapInterface::open("tap0")?;
    let mut buffer = [0u8; 2048];

    loop {
        let n = tap.read_frame(&mut buffer)?;
        match EthernetFrame::parse(&buffer[..n]) {
            Ok(frame) => println!(
                "{} -> {} {:?}",
                frame.source, frame.destination, frame.ethertype
            ),
            Err(e) => println!("bad frame ({n} bytes): {e}"),
        }
    }
}

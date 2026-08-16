// src/main.rs

mod interface;

use interface::tap::TapInterface;

fn main() {
    let mut tap = TapInterface::open("tap0")?;
    let mut buffer = [0u8; 2048];

    loop {
        let n = tap.read_frame(&mut buffer)?;
        println!("received {n} bytes");

        for byte in &buffer[..n.min(32)] {
            print!("{byte:02x} ");
        }
        println!();
    }
}
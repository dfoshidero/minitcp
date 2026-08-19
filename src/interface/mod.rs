// src/interface/mod.rs
pub mod pcap;
pub mod tap;

use std::io;

pub trait FrameIo {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()>;
}

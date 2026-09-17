// The seam between "where frames come from" and the protocol code.
// Everything here is dependency-free except the Linux TAP binding.

pub mod pcap;
#[cfg(feature = "tap")]
pub mod tap;

use std::io;

/// A source and sink of raw Ethernet frames: a TAP device, a pcap file, a hex
/// dump on stdin, a socket, or a test fixture. `stack` is written against this
/// alone, which is why the whole stack runs without root or a real interface.
pub trait FrameIo {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()>;
}

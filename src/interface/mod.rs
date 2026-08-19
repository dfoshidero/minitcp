//! How frames get in and out of the stack.
//!
//! Everything under here carries Ethernet frames: a real TAP device, a TCP
//! connection to the sidecar, a pcap file, hex on stdin. The stack never learns
//! which one it got — it asks for a frame and hands back a reply.

pub mod capture;
pub mod fwd;
pub mod hex;
pub mod pcap;
pub mod tap;

use std::io;

/// Somewhere frames come from.
///
/// `read_frame` fills `buffer` with exactly one frame and returns its length.
/// `Ok(0)` means the source has ended — file exhausted, peer hung up — never
/// "nothing right now"; an idle source must block. The stack stops on a zero.
pub trait FrameSource {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
}

/// Somewhere frames go.
pub trait FrameSink {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()>;
}

/// Both ends of a real conversation. The halves are separate traits because a
/// pcap file on disk genuinely cannot answer back, and should not pretend to.
pub trait FrameIo: FrameSource + FrameSink {}

impl<T: FrameSource + FrameSink> FrameIo for T {}

/// A source with nowhere to reply to. Replaying a capture, the stack still
/// composes its answers — that is the point — but there is no wire to put them
/// on, so this is where they visibly stop.
pub struct ReadOnly<S>(pub S);

impl<S: FrameSource> FrameSource for ReadOnly<S> {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read_frame(buffer)
    }
}

impl<S> FrameSink for ReadOnly<S> {
    fn write_frame(&mut self, _frame: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

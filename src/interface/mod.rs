// How frames get in and out of the stack.
//
// Everything under here is a way of carrying Ethernet frames: a real TAP
// device, a TCP connection to the sidecar, a pcap file, hex on stdin. The stack
// itself never learns which one it got — it asks for the next frame and hands
// back a reply, and that is the whole contract.

pub mod capture;
pub mod fwd;
pub mod hex;
pub mod pcap;
pub mod tap;

use std::io;

/// Somewhere frames come from.
///
/// `read_frame` fills `buffer` with exactly one frame and returns its length.
/// Returning `Ok(0)` means the source has genuinely ended — the file ran out,
/// the peer hung up — and never "nothing right now"; a source with nothing to
/// say yet must block instead. The stack relies on that: a zero is the signal
/// to stop, so a source that returned one casually would look like a clean end
/// of session.
pub trait FrameSource {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
}

/// Somewhere frames go.
pub trait FrameSink {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()>;
}

/// Both ends of a real conversation.
///
/// The two halves are separate traits because plenty of things are honestly
/// only one of them — a pcap file on disk has no way to answer back. Keeping
/// them apart means those types no longer have to pretend, with a `write_frame`
/// that quietly throws the reply away.
pub trait FrameIo: FrameSource + FrameSink {}

impl<T: FrameSource + FrameSink> FrameIo for T {}

/// A source with nowhere to reply to.
///
/// Replaying a capture is a one-way conversation: the stack still composes its
/// answers — that is the point of watching a replay — but there is no wire to
/// put them on. This wrapper is where those replies stop, named so that the
/// discarding is visible rather than hidden inside a reader.
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

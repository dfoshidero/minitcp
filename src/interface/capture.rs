// Record everything that crosses the wire, without changing what crosses it.
//
// `CaptureIo` wraps any other carrier and tees both directions into a pcap
// file, so `--write out.pcap` produces something Wireshark can open. Frames
// still go where they were going; this only listens in. With no writer
// attached it is pure pass-through, which is why the stack can wrap
// unconditionally and not care whether --write was given.

use std::io;

use super::pcap::PcapWriter;
use super::{FrameSink, FrameSource};

pub struct CaptureIo<I> {
    inner: I,
    capture: Option<PcapWriter>,
}

impl<I> CaptureIo<I> {
    pub fn new(inner: I, capture: Option<PcapWriter>) -> Self {
        Self { inner, capture }
    }
}

impl<I: FrameSource> FrameSource for CaptureIo<I> {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read_frame(buffer)?;
        if n > 0
            && let Some(w) = &mut self.capture
        {
            w.write_frame(&buffer[..n])?;
        }
        Ok(n)
    }
}

impl<I: FrameSink> FrameSink for CaptureIo<I> {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        if let Some(w) = &mut self.capture {
            w.write_frame(frame)?;
        }
        self.inner.write_frame(frame)
    }
}

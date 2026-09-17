//! MiniTCP — a userspace TCP/IP stack you can read in an afternoon.
//!
//! The library half of the `minitcp` command. It is deliberately small and, with
//! default features off, carries **no dependencies at all**:
//!
//! ```toml
//! minitcp = { version = "1", default-features = false }
//! ```
//!
//! * [`proto`] — the wire formats (Ethernet, ARP, IPv4, ICMP, the Internet
//!   checksum). Pure parsing and serialization: no I/O, no clock, no globals.
//! * [`interface`] — [`interface::FrameIo`], the one trait everything else is
//!   written against, plus a dependency-free pcap reader/writer and (behind the
//!   `tap` feature) the Linux TAP binding.
//! * [`stack`] — [`stack::Stack`], which turns one frame into an
//!   [`event::Outcome`]: what was decoded, what was dropped and why, and the
//!   reply to send. It performs no I/O and prints nothing.
//!
//! Parsers take a byte slice and return a borrowed view; nothing is copied and
//! malformed input is an error rather than a panic.
//!
//! ```
//! use minitcp::proto::ethernet::{EthernetFrame, EthernetType};
//!
//! let frame = EthernetFrame::parse(&[
//!     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination: broadcast
//!     0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // source
//!     0x08, 0x06, // EtherType: ARP
//! ])?;
//! assert_eq!(frame.ethertype, EthernetType::Arp);
//! # Ok::<(), &'static str>(())
//! ```
//!
//! Driving the stack is the same shape: hand it a frame, read back what it made
//! of it. Nothing is printed, so the caller decides what to do with the story.
//!
//! ```
//! use minitcp::stack::{Stack, StackConfig};
//! use minitcp::event::{Layer, Step};
//!
//! # const WHO_HAS: [u8; 42] = [
//! #     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
//! #     0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
//! #     0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
//! # ];
//! let mut stack = Stack::new(StackConfig::default()); // 10.0.0.2 by default
//! let outcome = stack.handle(&WHO_HAS);               // "who has 10.0.0.2?"
//!
//! // It answered, and it can tell you what it saw on the way.
//! assert!(outcome.reply.is_some());
//! assert!(!outcome.dropped());
//! for step in &outcome.steps {
//!     if let Step::In(Layer::Ipv4 { source, .. }) = step {
//!         println!("from {source}");
//!     }
//! }
//! ```

pub mod event;
pub mod interface;
pub mod proto;
pub mod stack;

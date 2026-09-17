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

pub mod interface;
pub mod proto;

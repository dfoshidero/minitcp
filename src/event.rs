//! What the stack saw, and what it did about it.
//!
//! [`crate::stack::Stack::handle`] returns one [`Outcome`] per frame instead of
//! printing anything. That is the whole point of this module: the decision and
//! the presentation are separate, so a caller can log the steps, draw them,
//! count them, or ignore them entirely.

use std::net::Ipv4Addr;

use crate::proto::error::ParseError;
use crate::proto::ethernet::MacAddress;
use crate::proto::ipv4::Protocol;

/// The result of feeding one Ethernet frame to the stack.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The Ethernet endpoints, once the frame header parsed.
    pub link: Option<Endpoints<MacAddress>>,
    /// The IPv4 endpoints, once an IPv4 header parsed.
    pub network: Option<Endpoints<Ipv4Addr>>,
    /// What happened, in the order it happened.
    pub steps: Vec<Step>,
    /// The frame to put back on the wire, if the stack chose to answer.
    pub reply: Option<Vec<u8>>,
}

impl Outcome {
    /// The first inbound layer of this kind, if the frame carried one.
    pub fn inbound(&self, pick: impl Fn(&Layer) -> bool) -> Option<&Layer> {
        self.steps.iter().find_map(|step| match step {
            Step::In(layer) if pick(layer) => Some(layer),
            _ => None,
        })
    }

    /// True when the frame was discarded rather than processed.
    pub fn dropped(&self) -> bool {
        self.steps.iter().any(|step| matches!(step, Step::Drop(_)))
    }
}

/// A source and a destination at one layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoints<T> {
    pub source: T,
    pub destination: T,
}

impl<T> Endpoints<T> {
    pub fn new(source: T, destination: T) -> Self {
        Self {
            source,
            destination,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// A layer decoded from the frame that arrived.
    In(Layer),
    /// A layer written into the reply.
    Out(Layer),
    /// Processing stopped here; nothing below this layer was looked at.
    Drop(Dropped),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Ethernet {
        source: MacAddress,
        destination: MacAddress,
        ethertype: u16,
    },
    Arp {
        operation: ArpOperation,
        /// `None` when the ARP payload was too short to carry addresses.
        addresses: Option<Endpoints<Ipv4Addr>>,
        /// The hardware address being advertised, on a reply we sent.
        sender_mac: Option<MacAddress>,
    },
    Ipv4 {
        source: Ipv4Addr,
        destination: Ipv4Addr,
        ttl: u8,
        protocol: Protocol,
        payload_len: usize,
    },
    Icmp {
        kind: u8,
        code: u8,
        /// `None` when the message was too short to be an echo.
        echo: Option<Echo>,
        len: usize,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        len: usize,
    },
}

/// The identifier and sequence number `ping` uses to match replies to requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    pub id: u16,
    pub sequence: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    Other(u16),
}

impl ArpOperation {
    pub fn from_number(n: u16) -> Self {
        match n {
            1 => Self::Request,
            2 => Self::Reply,
            other => Self::Other(other),
        }
    }
}

/// A frame the stack refused, and how far it got first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dropped {
    /// Protocol name, e.g. `"ipv4"`.
    pub layer: &'static str,
    /// OSI shorthand, e.g. `"L3"`.
    pub osi: &'static str,
    /// Which endpoints describe this drop.
    pub scope: Scope,
    pub reason: DropReason,
}

/// Why a frame was discarded. Match on this rather than on the message text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// A parser refused the bytes.
    Malformed(ParseError),
    /// Addressed to a host that is not us.
    NotForUs,
    /// Discarded on purpose, because the configuration asked for it.
    Filtered,
    /// Discarded by the random-loss simulator.
    RandomLoss,
    /// An ARP payload too short to answer.
    TruncatedArp,
    /// A transport this stack does not speak yet.
    NotImplemented,
    /// An IPv4 protocol number with no handler.
    UnknownProtocol(u8),
}

impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "{e}"),
            Self::NotForUs => f.write_str("not for us"),
            Self::Filtered => f.write_str("dropped"),
            Self::RandomLoss => f.write_str("random drop"),
            Self::TruncatedArp => f.write_str("truncated ARP payload"),
            Self::NotImplemented => f.write_str("not implemented"),
            Self::UnknownProtocol(n) => write!(f, "unknown protocol {n}"),
        }
    }
}

impl From<ParseError> for DropReason {
    fn from(error: ParseError) -> Self {
        Self::Malformed(error)
    }
}

/// How deep the stack was when it gave up, which decides whose addresses
/// describe the drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// At the link layer: described by [`Outcome::link`].
    Link,
    /// The IPv4 header itself: described by [`Outcome::network`].
    Network,
    /// Inside the IPv4 payload (ICMP, UDP, TCP), which sits under the IPv4 line.
    Payload,
}

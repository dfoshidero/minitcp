//! Wire formats MiniTCP speaks, one module per layer.
//!
//! ```text
//! ethernet  L2  every frame arrives inside one
//!   arp     L2  IPv4 address -> MAC
//!   ipv4    L3  addressing beyond this cable
//!     icmp  L4  echo request / echo reply
//! checksum      RFC 1071, shared by IPv4 and (later) TCP
//! ```
//!
//! Nothing here does any I/O or keeps any state: bytes in, meaning out.
//! `stack::handle` is what decides to answer.

pub mod arp;
pub mod checksum;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;

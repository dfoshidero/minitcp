// src/proto/mod.rs
// Wire formats MiniTCP speaks. The TAP loop in stack.rs dispatches to these.

pub mod arp;
pub mod checksum;
pub mod error;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;

pub use error::ParseError;

// src/proto/mod.rs
// Wire formats MiniTCP speaks. The TAP loop in stack.rs dispatches to these.

pub mod arp;
pub mod checksum;
pub mod ethernet;
pub mod ipv4;

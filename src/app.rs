//! The `minitcp` command: everything the library half does not need.
//!
//! [`crate::stack`] and [`crate::proto`] are sans-io and dependency-free; these
//! modules are the parts that talk to the outside world — argument parsing,
//! rendering, TAP orchestration, the TUI. Nothing under [`crate::stack`],
//! [`crate::proto`], [`crate::interface`] or [`crate::event`] may depend on
//! anything in here, which is what keeps the published library small.

pub mod cli;
pub mod fwd;
pub mod log;
pub mod process;
pub mod runner;
pub mod tapcmd;
pub mod tui;
pub mod update;

// Talking to the machine minitcp is running on: child processes, the TAP
// device, and Docker. Nothing in here knows anything about Ethernet frames.

pub mod docker;
pub mod process;
pub mod tapdev;

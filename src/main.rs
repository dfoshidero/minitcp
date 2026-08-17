// src/main.rs

mod arp;
mod checksum;
mod ethernet;
mod interface;
mod ipv4;
mod frontend;
mod stack;

fn usage() {
    eprintln!(
        "minitcp — userspace TCP/IP lab

  minitcp          terminal lab (stack + tcpdump + ping)
  minitcp run      same as minitcp
  minitcp stack    TAP loop only (no UI)
"
    );
}

fn main() -> std::io::Result<()> {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        None | Some("run") => frontend::run_lab(),
        Some("stack") => stack::run_stack(),
        Some("-h" | "--help" | "help") => {
            usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n");
            usage();
            std::process::exit(2);
        }
    }
}

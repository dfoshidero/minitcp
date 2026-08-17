// src/main.rs

mod interface;
mod log;
mod proto;
mod stack;
mod tui;

fn usage() {
    eprintln!(
        "minitcp — userspace TCP/IP lab

  minitcp              terminal UI (stack + tcpdump + ping)
  minitcp run          same as minitcp
  minitcp stack        TAP loop only (decoded headers)
  minitcp stack -q     TAP loop, one line per exchange
"
    );
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("run") => tui::run_lab(),
        Some("stack") => {
            let quiet = args.iter().any(|a| a == "-q" || a == "--quiet");
            stack::run_stack(!quiet)
        }
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

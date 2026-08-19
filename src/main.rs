// src/main.rs

mod cli;
mod interface;
mod log;
mod proto;
mod stack;
mod tui;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match cli::parse(&args) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("minitcp: {err}\n");
            eprint!("{}", cli::usage());
            std::process::exit(2);
        }
    };

    match cfg.command {
        cli::Command::Help => {
            eprint!("{}", cli::usage());
            Ok(())
        }
        cli::Command::Run => tui::run_lab(),
        cli::Command::Stack => stack::run_stack(cfg.verbose()),
        cli::Command::Replay(_) | cli::Command::PcapInfo(_) => {
            eprintln!("minitcp: pcap commands are not wired yet");
            std::process::exit(2);
        }
    }
}

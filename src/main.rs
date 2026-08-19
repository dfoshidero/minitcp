// src/main.rs

mod cli;
mod interface;
mod log;
mod proto;
mod stack;
mod tapcmd;
mod tui;
mod update;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match cli::parse(&args) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprint!("{err}");
            std::process::exit(2);
        }
    };

    let skip_nag = cfg.offline
        || matches!(
            cfg.command,
            cli::Command::Bridge | cli::Command::TapUp | cli::Command::TapDown
        );
    if !skip_nag {
        update::nag_if_outdated();
    }

    match cfg.command {
        cli::Command::Help => {
            eprint!("{}", cli::usage());
            Ok(())
        }
        cli::Command::Run => tui::run_lab(cfg),
        cli::Command::Stack | cli::Command::Replay(_) => stack::run_stack(cfg),
        cli::Command::PcapInfo(path) => {
            print!("{}", crate::interface::pcap::pcap_info(&path)?);
            Ok(())
        }
        cli::Command::Bridge => stack::run_bridge(cfg),
        cli::Command::TapUp => tapcmd::tap_up(&cfg),
        cli::Command::TapDown => tapcmd::tap_down(),
    }
}

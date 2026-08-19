// src/main.rs

mod cli;
mod interface;
mod log;
mod proto;
mod stack;
mod tapcmd;
mod tui;
mod update;

use cli::{Command, HelpTopic};

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
        || !matches!(
            cfg.command,
            Command::Run | Command::Stack | Command::Replay(_)
        );
    if !skip_nag {
        update::nag_if_outdated();
    }

    match cfg.command {
        Command::Help(topic) => {
            eprint!("{}", cli::usage_topic(topic));
            Ok(())
        }
        Command::Run => tui::run_lab(cfg),
        Command::Stack | Command::Replay(_) => stack::run_stack(cfg),
        Command::Pcap(path) => {
            print!("{}", crate::interface::pcap::pcap_info(&path)?);
            Ok(())
        }
        Command::Bridge => stack::run_bridge(cfg),
        Command::TapUp => tapcmd::tap_up(&cfg),
        Command::TapDown => tapcmd::tap_down(&cfg),
        Command::TapShow => {
            eprint!("{}", tap_status(&cfg));
            eprint!("{}", cli::usage_topic(HelpTopic::Tap));
            std::process::exit(2);
        }
        Command::TapSetIface(ref name) => write_key(&cfg, "iface", name),
        Command::TapSetAddr(ip) => write_key(&cfg, "linux-addr", &ip.to_string()),
        Command::TapSetTun(ref path) => write_key(&cfg, "tun", &path.display().to_string()),
        Command::IdentityShow => {
            print!("{}", identity_status(&cfg));
            Ok(())
        }
        Command::IdentitySetAddr(ip) => write_key(&cfg, "addr", &ip.to_string()),
        Command::IdentitySetMac(mac) => write_key(&cfg, "mac", &mac.to_string()),
    }
}

fn tap_status(cfg: &cli::Config) -> String {
    format!(
        "iface  {}\naddr   {}\ntun    {}\n\n",
        cfg.iface,
        cfg.linux_addr,
        cfg.tun.display()
    )
}

fn identity_status(cfg: &cli::Config) -> String {
    format!(
        "addr  {}\nmac   {}\n\nminitcp identity addr IP  writes {}\n",
        cfg.addr,
        cfg.mac,
        cfg.config_path.display()
    )
}

fn write_key(cfg: &cli::Config, key: &str, value: &str) -> std::io::Result<()> {
    cli::write_config_key(cfg, key, value).map_err(|e| std::io::Error::other(e.to_string()))?;
    eprintln!("wrote {key} = {value}  ({})", cfg.config_path.display());
    Ok(())
}

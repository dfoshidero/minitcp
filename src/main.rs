// src/main.rs

mod cli;
mod interface;
mod log;
mod proto;
mod release;
mod stack;
mod sys;
mod tui;

use cli::{Command, HelpTopic};

enum AppError {
    Usage(cli::ParseError),
    Config(cli::ParseError),
    Runtime(std::io::Error),
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::Runtime(error)
    }
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(AppError::Usage(error)) => {
            let _ = log::write_stderr(&error.to_string());
            2
        }
        Err(AppError::Config(error)) => {
            let _ = log::write_stderr(&error.to_string());
            1
        }
        Err(AppError::Runtime(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => 0,
        Err(AppError::Runtime(error)) => {
            log::status::error(error.to_string());
            1
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

fn run() -> Result<(), AppError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = cli::parse(&args).map_err(AppError::Usage)?;

    let skip_nag = cfg.offline
        || !matches!(
            cfg.command,
            Command::Run | Command::Stack | Command::Replay(_)
        );
    if !skip_nag {
        release::nag_if_outdated();
    }

    match cfg.command {
        Command::Help(topic) => log::write_stderr(&cli::usage_topic(topic)).map_err(Into::into),
        Command::Version => {
            log::write_stdout(&format!("minitcp {}\n", env!("MINITCP_RELEASE"))).map_err(Into::into)
        }
        Command::Run => tui::run_lab(cfg).map_err(Into::into),
        Command::Stack | Command::Replay(_) => stack::run_stack(cfg).map_err(Into::into),
        Command::Pcap(path) => {
            let output = crate::interface::pcap::pcap_info(&path)?;
            log::write_stdout(&output)?;
            Ok(())
        }
        Command::Bridge => stack::run_bridge(cfg).map_err(Into::into),
        Command::TapUp => sys::tapdev::tap_up(&cfg).map_err(Into::into),
        Command::TapDown => sys::tapdev::tap_down(&cfg).map_err(Into::into),
        Command::TapShow => {
            log::write_stderr(&tap_status(&cfg))?;
            log::write_stderr(&cli::usage_topic(HelpTopic::Tap))?;
            Ok(())
        }
        Command::TapSetIface(ref name) => write_key(&cfg, "iface", name),
        Command::TapSetAddr(ip) => write_key(&cfg, "linux-addr", &ip.to_string()),
        Command::TapSetTun(ref path) => write_key(&cfg, "tun", &path.display().to_string()),
        Command::IdentityShow => {
            log::write_stdout(&identity_status(&cfg))?;
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

fn write_key(cfg: &cli::Config, key: &str, value: &str) -> Result<(), AppError> {
    cli::write_config_key(cfg, key, value).map_err(AppError::Config)?;
    log::status::ok(format!(
        "wrote {key} = {value}  ({})",
        cfg.config_path.display()
    ));
    Ok(())
}

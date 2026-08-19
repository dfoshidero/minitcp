// One command in, one action out.
//
// Parsing above, doing below. One `match`, so the full list of what minitcp
// can do reads in a single screen.
//
// One rule about streams: anything the user asked for — help, a `show` — is
// the result and goes to stdout with exit 0. Usage errors and progress go to
// stderr. That is what makes `minitcp --help | less` and `minitcp tap > tap.txt`
// behave the way anyone would expect them to.

use crate::cli::{self, Command, Config};
use crate::{AppError, log, release, stack, sys, tui};

pub fn run() -> Result<(), AppError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = cli::parse(&args).map_err(AppError::Cli)?;

    for warning in &cfg.warnings {
        log::status::warn(warning);
    }

    let skip_nag = cfg.offline
        || !matches!(
            cfg.command,
            Command::Run | Command::Stack | Command::Replay(_)
        );
    if !skip_nag {
        release::nag_if_outdated();
    }

    match cfg.command {
        Command::Help(topic) => log::write_stdout(&cli::usage_topic(topic)).map_err(Into::into),
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
        Command::TapShow => log::write_stdout(&tap_status(&cfg)).map_err(Into::into),
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

fn tap_status(cfg: &Config) -> String {
    format!(
        "iface  {}\naddr   {}\ntun    {}\n\nminitcp tap iface NAME  writes {}\n",
        cfg.iface,
        cfg.linux_addr,
        cfg.tun.display(),
        cfg.config_path.display()
    )
}

fn identity_status(cfg: &Config) -> String {
    format!(
        "addr  {}\nmac   {}\n\nminitcp identity addr IP  writes {}\n",
        cfg.addr,
        cfg.mac,
        cfg.config_path.display()
    )
}

fn write_key(cfg: &Config, key: &str, value: &str) -> Result<(), AppError> {
    cli::write_config_key(cfg, key, value).map_err(AppError::Cli)?;
    log::status::ok(format!(
        "wrote {key} = {value}  ({})",
        cfg.config_path.display()
    ));
    Ok(())
}

// Flags anywhere. Defaults < minitcp.toml < command line.

mod args;
mod command;
mod error;
mod file;
mod flags;
mod options;
mod usage;

use std::path::{Path, PathBuf};

pub use command::{Command, HelpTopic};
pub use error::ParseError;
pub use options::{Config, DEFAULT_CONFIG, DropKind, Transport};
pub use usage::usage_topic;

use options::{Partial, apply_partial, default_linux_addr};
use usage::USAGE_CONFIG;

fn is_setter(command: &Command) -> bool {
    matches!(
        command,
        Command::TapSetIface(_)
            | Command::TapSetAddr(_)
            | Command::TapSetTun(_)
            | Command::IdentitySetAddr(_)
            | Command::IdentitySetMac(_)
    )
}

/// Parse argv without the program name. `cwd` is where `./minitcp.toml` is sought.
pub fn parse_from(args: &[String], cwd: &Path) -> Result<Config, ParseError> {
    let cli = args::parse_cli(args)?;
    if let Some(command @ (Command::Help(_) | Command::Version)) = &cli.command {
        let mut cfg = Config::defaults();
        cfg.command = command.clone();
        return Ok(cfg);
    }

    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(|| cwd.join(DEFAULT_CONFIG));
    let setter = cli.command.as_ref().is_some_and(is_setter);

    let mut loaded = Partial::default();
    if let Some(path) = &cli.config {
        if path.is_file() {
            file::apply(&mut loaded, &file::load(path)?)?;
        } else if !setter {
            return Err(ParseError::with_usage(
                format!("config file not found: {}", path.display()),
                USAGE_CONFIG,
            ));
        }
    } else {
        let default_path = cwd.join(DEFAULT_CONFIG);
        if default_path.is_file() {
            file::apply(&mut loaded, &file::load(&default_path)?)?;
        }
    }

    let mut cfg = Config::defaults();
    apply_partial(&mut cfg, &loaded);
    apply_partial(&mut cfg, &cli);
    if loaded.linux_addr.is_none() && cli.linux_addr.is_none() {
        cfg.linux_addr = default_linux_addr(cfg.addr);
    }
    cfg.config_path = config_path;
    cfg.command = cli.command.unwrap_or(Command::Run);
    Ok(cfg)
}

pub fn parse(args: &[String]) -> Result<Config, ParseError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    parse_from(args, &cwd)
}

pub(crate) fn write_config_key(cfg: &Config, key: &str, value: &str) -> Result<(), ParseError> {
    file::set_string(&cfg.config_path, key, value)
}

#[cfg(test)]
mod tests;

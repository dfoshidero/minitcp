// Flags anywhere. Defaults < minitcp.toml < command line.

mod args;
mod config;
mod error;
mod file;

use std::path::{Path, PathBuf};

pub use config::{Command, Config, DropKind, DEFAULT_CONFIG};
pub use error::{usage, ParseError};

use config::{apply_partial, default_linux_addr, Partial};
use error::USAGE_CONFIG;

/// Parse argv without the program name. `cwd` is where `./minitcp.toml` is sought.
pub fn parse_from(args: &[String], cwd: &Path) -> Result<Config, ParseError> {
    let cli = args::parse_cli(args)?;
    if matches!(cli.command, Some(Command::Help)) {
        let mut cfg = Config::defaults();
        cfg.command = Command::Help;
        return Ok(cfg);
    }

    let mut loaded = Partial::default();
    if let Some(path) = &cli.config {
        if !path.is_file() {
            return Err(ParseError::with_usage(
                format!("config file not found: {}", path.display()),
                USAGE_CONFIG,
            ));
        }
        file::apply(&mut loaded, &file::load(path)?)?;
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
    cfg.command = cli.command.unwrap_or(Command::Run);
    Ok(cfg)
}

pub fn parse(args: &[String]) -> Result<Config, ParseError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    parse_from(args, &cwd)
}

#[cfg(test)]
mod tests;

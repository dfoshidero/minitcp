// Flags anywhere. Defaults < minitcp.toml < command line.

mod args;
mod command;
mod error;
mod file;
mod flags;
mod options;
mod usage;

use std::path::{Path, PathBuf};

pub use command::Command;
#[cfg(test)]
use command::HelpTopic;
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

/// Flags argv named that this command never reads. Warned about rather than
/// refused: a stale `--ttl` should not stop `tap up` from bringing a TAP up.
fn inert_flags(command: &Command, given: &[&'static str]) -> Vec<String> {
    let scope = command.scope();
    let mut inert: Vec<&str> = given
        .iter()
        .copied()
        .filter(|flag| !flags::applies(flag, scope))
        .collect();
    inert.dedup();
    if inert.is_empty() {
        return Vec::new();
    }
    let named = if inert.len() == 2 {
        inert.join(" and ")
    } else {
        inert.join(", ")
    };
    vec![format!(
        "{named} {} no effect on `{}`",
        if inert.len() == 1 { "has" } else { "have" },
        command.label()
    )]
}

/// Frames reach the stack from exactly one place. Naming two is refused here
/// rather than in `run_stack`, which would otherwise silently honour whichever
/// source it happens to test first.
fn one_frame_source(command: &Command, cli: &Partial) -> Result<(), ParseError> {
    let mut named = Vec::new();
    if matches!(command, Command::Replay(_)) {
        named.push("replay FILE");
    }
    if cli.hex == Some(true) {
        named.push("--hex");
    }
    if cli.fwd.is_some() {
        named.push("--fwd");
    }
    if named.len() > 1 {
        return Err(ParseError::msg(format!(
            "{} name where frames come from; pick one",
            named.join(" and ")
        )));
    }
    Ok(())
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
    cfg.command = cli.command.clone().unwrap_or(Command::Run);
    one_frame_source(&cfg.command, &cli)?;
    cfg.warnings = inert_flags(&cfg.command, &cli.given);
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

// Walking argv.
//
// The shape is `minitcp [family] [subcommand] [flags]`, and flags may appear
// anywhere — before the command, after it, `--iface tap1` or `--iface=tap1`.
// Families (`tap`, `identity`, `pcap`) exist so that related commands read as a
// group and can be helped as a group. Nothing here decides what a flag *means*;
// that is `flags::apply_flag`.

use std::path::PathBuf;

use super::command::{Command, HelpTopic};
use super::error::{ParseError, missing_value};
use super::flags::{self, apply_flag, parse_ipv4, parse_mac};
use super::options::Partial;
use super::usage::{USAGE_COMMANDS, USAGE_IDENTITY, USAGE_PCAP, USAGE_REPLAY, USAGE_TAP};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    None,
    Tap,
    Identity,
    Pcap,
}

fn take_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, ParseError> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or_else(|| missing_value(flag))
}

fn split_eq(arg: &str) -> Option<(&str, &str)> {
    arg.split_once('=')
}

fn peek(args: &[String], i: usize) -> Option<&str> {
    args.get(i + 1).map(String::as_str)
}

fn is_help(s: &str) -> bool {
    s == "-h" || s == "--help"
}

pub(crate) fn parse_cli(args: &[String]) -> Result<Partial, ParseError> {
    let mut partial = Partial::default();
    let mut family = Family::None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if is_help(arg) {
            let topic = match family {
                Family::None => HelpTopic::Full,
                Family::Tap => HelpTopic::Tap,
                Family::Identity => HelpTopic::Identity,
                Family::Pcap => HelpTopic::Pcap,
            };
            set_command(&mut partial, Command::Help(topic))?;
            i += 1;
            continue;
        }
        if let Some((flag, value)) = split_eq(arg).filter(|(f, _)| f.starts_with("--")) {
            apply_flag(&mut partial, flag, Some(value))?;
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            // `--version` is a command rather than an option, so it is the one
            // dash-word the flag table does not describe.
            if arg == "-V" || arg == "--version" {
                set_command(&mut partial, Command::Version)?;
                i += 1;
                continue;
            }
            let name = flags::canonical(arg);
            let value = if flags::takes_value(name) {
                Some(take_value(args, &mut i, arg)?)
            } else {
                None
            };
            apply_flag(&mut partial, name, value)?;
            i += 1;
            continue;
        }
        match arg {
            "help" if partial.command.is_none() => {
                set_command(&mut partial, Command::Help(HelpTopic::Full))?;
            }
            "run" => set_command(&mut partial, Command::Run)?,
            "stack" => set_command(&mut partial, Command::Stack)?,
            "replay" => {
                let file = take_value(args, &mut i, "replay").map_err(|_| {
                    ParseError::with_usage("replay needs a pcap path", USAGE_REPLAY)
                })?;
                set_command(&mut partial, Command::Replay(PathBuf::from(file)))?;
            }
            "pcap" | "pcap-info" => {
                family = Family::Pcap;
                match peek(args, i) {
                    None => return Err(ParseError::usage_only(USAGE_PCAP)),
                    Some(next) if is_help(next) => {}
                    Some(next) if next.starts_with('-') => {
                        return Err(ParseError::usage_only(USAGE_PCAP));
                    }
                    Some(_) => {
                        let file = take_value(args, &mut i, "pcap")
                            .map_err(|_| ParseError::usage_only(USAGE_PCAP))?;
                        set_command(&mut partial, Command::Pcap(PathBuf::from(file)))?;
                    }
                }
            }
            "bridge" => set_command(&mut partial, Command::Bridge)?,
            "tap" => {
                family = Family::Tap;
                parse_tap(args, &mut i, &mut partial)?;
            }
            "identity" => {
                family = Family::Identity;
                parse_identity(args, &mut i, &mut partial)?;
            }
            other => {
                return Err(ParseError::with_usage(
                    format!("unknown command '{other}'"),
                    USAGE_COMMANDS,
                ));
            }
        }
        i += 1;
    }
    Ok(partial)
}

fn parse_tap(args: &[String], i: &mut usize, partial: &mut Partial) -> Result<(), ParseError> {
    match peek(args, *i) {
        None => set_command(partial, Command::TapShow),
        Some(next) if is_help(next) => Ok(()),
        Some(next) if next.starts_with('-') => set_command(partial, Command::TapShow),
        Some("up") => {
            *i += 1;
            set_command(partial, Command::TapUp)
        }
        Some("down") => {
            *i += 1;
            set_command(partial, Command::TapDown)
        }
        Some("iface") => {
            *i += 1;
            let name =
                take_value(args, i, "tap iface").map_err(|_| ParseError::usage_only(USAGE_TAP))?;
            set_command(partial, Command::TapSetIface(name.to_string()))
        }
        Some("addr") => {
            *i += 1;
            let ip =
                take_value(args, i, "tap addr").map_err(|_| ParseError::usage_only(USAGE_TAP))?;
            set_command(partial, Command::TapSetAddr(parse_ipv4(ip)?))
        }
        Some("tun") => {
            *i += 1;
            let path =
                take_value(args, i, "tap tun").map_err(|_| ParseError::usage_only(USAGE_TAP))?;
            set_command(partial, Command::TapSetTun(PathBuf::from(path)))
        }
        Some(_) => {
            *i += 1;
            Err(ParseError::usage_only(USAGE_TAP))
        }
    }
}

fn parse_identity(args: &[String], i: &mut usize, partial: &mut Partial) -> Result<(), ParseError> {
    match peek(args, *i) {
        None => set_command(partial, Command::IdentityShow),
        Some(next) if is_help(next) => Ok(()),
        Some(next) if next.starts_with('-') => set_command(partial, Command::IdentityShow),
        Some("addr") => {
            *i += 1;
            let ip = take_value(args, i, "identity addr")
                .map_err(|_| ParseError::usage_only(USAGE_IDENTITY))?;
            set_command(partial, Command::IdentitySetAddr(parse_ipv4(ip)?))
        }
        Some("mac") => {
            *i += 1;
            let mac = take_value(args, i, "identity mac")
                .map_err(|_| ParseError::usage_only(USAGE_IDENTITY))?;
            set_command(
                partial,
                Command::IdentitySetMac(parse_mac(mac).map_err(ParseError::msg)?),
            )
        }
        Some(_) => {
            *i += 1;
            Err(ParseError::usage_only(USAGE_IDENTITY))
        }
    }
}

fn set_command(partial: &mut Partial, command: Command) -> Result<(), ParseError> {
    match &partial.command {
        None => {
            partial.command = Some(command);
            Ok(())
        }
        Some(Command::Help(_)) => Ok(()),
        Some(_) => Err(ParseError::with_usage(
            "only one command is allowed",
            USAGE_COMMANDS,
        )),
    }
}

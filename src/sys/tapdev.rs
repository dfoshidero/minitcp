// Creating and destroying the TAP device itself.
//
// A TAP is a virtual Ethernet cable: one end is an ordinary network interface
// as far as Linux is concerned, the other end is a file descriptor a program
// reads frames from and writes frames to. This module owns the first end;
// `interface::tap` owns the second.

use std::io;

use crate::cli::Config;
use crate::sys::docker::{self, State};
use crate::sys::process::AllowedFailure;

/// `minitcp tap up` — get a TAP from somewhere, preferring the sidecar.
///
/// Docker first even on Linux: the sidecar needs no host root and behaves the
/// same everywhere. A local TAP is the fallback, not an error.
pub fn tap_up(cfg: &Config) -> io::Result<()> {
    match docker::state()? {
        State::Ready => return docker::up(cfg),
        State::Unavailable(detail) if !cfg!(target_os = "linux") => {
            return Err(io::Error::other(format!(
                "Docker is unavailable; start Docker Desktop and try again: {detail}"
            )));
        }
        State::Unavailable(detail) => {
            crate::log::status::warn(format!(
                "Docker is unavailable ({detail}); using a local Linux TAP"
            ));
        }
        State::Missing => {}
    }
    if cfg!(target_os = "linux") {
        return local_up(cfg);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "docker not found; install Docker Desktop (or Docker Engine) for TAP",
    ))
}

/// `minitcp tap down` — remove whichever kind of TAP is there.
///
/// Both are attempted, since one session can leave one of each behind.
pub fn tap_down(cfg: &Config) -> io::Result<()> {
    let docker = docker::state()?;
    if matches!(&docker, State::Ready) && docker::down()? {
        return Ok(());
    }
    if cfg!(target_os = "linux") {
        if let State::Unavailable(detail) = docker {
            crate::log::status::warn(format!(
                "Docker is unavailable ({detail}); removing only the local Linux TAP"
            ));
        }
        crate::sys::process::run_sudo(
            &["ip", "link", "delete", &cfg.iface],
            AllowedFailure::DoesNotExist,
        )?;
        crate::log::status::ok(format!("removed {} if it existed", cfg.iface));
        return Ok(());
    }
    if let State::Unavailable(detail) = docker {
        return Err(io::Error::other(format!(
            "Docker is unavailable, so the TAP sidecar could not be stopped: {detail}"
        )));
    }
    crate::log::status::info("TAP sidecar was not running");
    Ok(())
}

/// Bring up a TAP on this machine, with no container in the picture.
fn local_up(cfg: &Config) -> io::Result<()> {
    ensure_iface(&cfg.iface, cfg.linux_addr)?;
    crate::log::status::ok(format!(
        "local TAP {} up ({}/24)",
        cfg.iface, cfg.linux_addr
    ));
    Ok(())
}

/// Is this interface present right now? `/sys/class/net` is the kernel's own
/// list, so this is a file lookup rather than a shell-out to `ip`.
pub fn iface_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
}

/// Which uid should own a TAP we are about to create: ourselves, or the person
/// behind `sudo`, or nobody when we are root outright (a container).
///
/// A uid, never `$USER` — that variable is unset in most containers and still
/// names the original user under `sudo`.
#[cfg(target_os = "linux")]
fn owner_uid() -> Option<u32> {
    // Safe: getuid() reads process state and cannot fail.
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        return Some(uid);
    }
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|&invoker| invoker != 0)
}

/// Build the `ip tuntap add` argument list — split out so the owner rule can be
/// tested without creating a device.
#[cfg(target_os = "linux")]
fn tuntap_add_args(name: &str, owner: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = ["tuntap", "add", "dev", name, "mode", "tap"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if let Some(uid) = owner {
        args.push("user".into());
        args.push(uid.into());
    }
    args
}

/// Create the TAP device and give Linux an address on it.
///
/// This is the *only* place minitcp brings a TAP up — the sidecar and `minitcp
/// tap up` on a Linux host both land here. Three `ip` calls, each of which must
/// be safe to repeat:
///
/// ```text
/// ip tuntap add dev tap0 mode tap [user 1000]   create the virtual cable
/// ip addr add 10.0.0.1/24 dev tap0              give Linux an address on it
/// ip link set dev tap0 up                       plug it in
/// ```
///
/// The first two are forgiven when the thing already exists, which is what
/// makes `minitcp tap up` safe to run twice.
pub fn ensure_iface(name: &str, linux_addr: std::net::Ipv4Addr) -> io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, linux_addr);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let uid = owner_uid().map(|uid| uid.to_string());
        let add = tuntap_add_args(name, uid.as_deref());
        let add: Vec<&str> = add.iter().map(String::as_str).collect();
        run_ip(&add, AllowedFailure::AlreadyExists)?;

        let cidr = format!("{linux_addr}/24");
        run_ip(
            &["addr", "add", &cidr, "dev", name],
            AllowedFailure::AlreadyExists,
        )?;
        run_ip(&["link", "set", "dev", name, "up"], AllowedFailure::None)?;
        Ok(())
    }
}

/// Run one `ip` command, retrying under `sudo` only if it is refused. Inside
/// the sidecar we are already root and the image has no sudo to call.
#[cfg(target_os = "linux")]
fn run_ip(args: &[&str], allowed: AllowedFailure) -> io::Result<()> {
    use crate::sys::process::{run_checked, run_sudo};

    match run_checked("ip", args, allowed) {
        Ok(()) => Ok(()),
        Err(direct_error) => {
            let sudo_args: Vec<_> = std::iter::once("ip").chain(args.iter().copied()).collect();
            run_sudo(&sudo_args, allowed).map_err(|sudo_error| {
                io::Error::new(
                    sudo_error.kind(),
                    format!(
                        "could not configure the TAP as this user ({direct_error}); \
                         and with sudo: {sudo_error}"
                    ),
                )
            })
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn a_named_owner_is_handed_the_device() {
        assert_eq!(
            tuntap_add_args("tap0", Some("1000")),
            [
                "tuntap", "add", "dev", "tap0", "mode", "tap", "user", "1000"
            ]
        );
    }

    #[test]
    fn root_creates_the_device_with_no_owner_clause() {
        assert_eq!(
            tuntap_add_args("tap0", None),
            ["tuntap", "add", "dev", "tap0", "mode", "tap"]
        );
    }

    #[test]
    fn the_owner_is_a_uid_not_a_name() {
        if let Some(uid) = owner_uid() {
            assert!(
                uid.to_string().chars().all(|c| c.is_ascii_digit()),
                "owner should be a uid, got {uid}"
            );
        }
    }
}

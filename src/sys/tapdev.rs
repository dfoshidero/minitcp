// Creating and destroying the TAP device itself.
//
// A TAP is a virtual Ethernet cable: one end is an ordinary network interface
// as far as Linux is concerned, the other end is a file descriptor a program
// can read frames from and write frames to. This module owns the first end —
// the `ip` commands that make the interface exist, and the decision of whether
// it should exist here or inside the sidecar. Reading and writing frames on the
// second end is `interface::tap`.

use std::io;

use crate::cli::Config;
use crate::sys::docker::{self, State};
use crate::sys::process::AllowedFailure;

/// `minitcp tap up` — get a TAP from somewhere, preferring the sidecar.
///
/// Docker first even on Linux: the sidecar needs no root on the host and
/// behaves identically everywhere, which makes it the one path worth teaching.
/// A Linux host that has no Docker can still make its own TAP, so that is the
/// fallback rather than an error.
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
/// Both are attempted rather than guessed at, because a machine can easily have
/// had one of each over the course of a session.
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

/// Is this interface present on this machine right now?
///
/// `/sys/class/net` is the kernel's own list of interfaces, so this is a
/// question answered by a file lookup rather than by shelling out to `ip`.
pub fn iface_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
}

/// Which user account should own a TAP device we are about to create.
///
/// `ip tuntap add ... user N` hands the new device to a non-root account, so
/// that account can later open `/dev/net/tun` and attach to it without being
/// root. Deciding who "N" is has three cases:
///
///   * **an ordinary user** — give the device to ourselves, so the stack we are
///     about to run can open it.
///   * **root via `sudo`** — the person who typed the command is not root, and
///     they are who will run the stack. `sudo` tells us who they were in
///     `SUDO_UID`, so hand the device to them rather than to root.
///   * **root outright**, as in a container — there is nobody else to hand it
///     to, and naming an owner would be meaningless. We return `None` and the
///     caller omits the `user` clause entirely, leaving the device root's.
///
/// The answer is always a *number*. The obvious alternative, `$USER`, is a
/// plain environment variable: it is unset in most containers and under many
/// init systems, and `sudo` leaves it pointing at the original user while the
/// process itself is root. Asking the kernel who we are cannot be wrong.
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

/// Build the `ip tuntap add` argument list.
///
/// Split out from `ensure_iface` purely so the "root owns it, so name no owner"
/// rule can be tested without actually creating a device.
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
/// The first two are forgiven if they fail because the thing already exists,
/// which is what makes `minitcp tap up` safe to run twice.
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

/// Run one `ip` command, escalating only if we have to.
///
/// Try it as ourselves first: inside the sidecar we are already root, and
/// invoking `sudo` there would be pointless (and fails outright, since the
/// image has no sudo). Only if that is refused do we retry under `sudo`.
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
        // Running as root outright — in a container, say — there is no other
        // account to hand the device to, so `user` must be left off entirely
        // rather than filled in with a guess like "root" or "netstack".
        assert_eq!(
            tuntap_add_args("tap0", None),
            ["tuntap", "add", "dev", "tap0", "mode", "tap"]
        );
    }

    #[test]
    fn the_owner_is_a_uid_not_a_name() {
        // Whatever owner_uid() returns on this machine, it must be numeric:
        // `ip` accepts either, but a name depends on $USER, which lies under
        // sudo and is missing in most containers.
        if let Some(uid) = owner_uid() {
            assert!(
                uid.to_string().chars().all(|c| c.is_ascii_digit()),
                "owner should be a uid, got {uid}"
            );
        }
    }
}

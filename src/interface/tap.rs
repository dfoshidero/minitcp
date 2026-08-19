// src/interface/tap.rs
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

pub struct TapInterface {
    file: File,
}

impl TapInterface {
    pub fn open_at(tun: &Path, name: &str) -> io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun, name);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TAP is Linux-only; run `minitcp tap up` and use the sidecar",
            ));
        }

        #[cfg(target_os = "linux")]
        {
            linux_open(tun, name)
        }
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_file(file: File) -> Self {
        Self { file }
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for TapInterface {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.file)
    }
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

#[cfg(target_os = "linux")]
/// Build the `ip tuntap add` argument list.
///
/// Split out from `ensure_iface` purely so the "root owns it, so name no owner"
/// rule can be tested without actually creating a device.
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
/// This is the *only* place minitcp brings a TAP up — the sidecar, `minitcp tap
/// up` on a Linux host, and the terminal UI all land here. Three `ip` calls,
/// each of which must be safe to repeat:
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
        use crate::process::AllowedFailure;

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
fn run_ip(args: &[&str], allowed: crate::process::AllowedFailure) -> io::Result<()> {
    use crate::process::{run_checked, run_sudo};

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

#[cfg(target_os = "linux")]
fn linux_open(tun: &Path, name: &str) -> io::Result<TapInterface> {
    use std::os::fd::AsRawFd;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;

    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TAP interface name",
        ));
    }

    let file = OpenOptions::new().read(true).write(true).open(tun)?;

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }

    unsafe {
        ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;
        let rc = libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifr);
        if rc < 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("cannot attach to {name} via {}: {error}", tun.display()),
            ));
        }
    }

    Ok(TapInterface { file })
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

impl crate::interface::FrameIo for TapInterface {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }

    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.file.write_all(frame)
    }
}

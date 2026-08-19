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

/// Create the TAP and give Linux an address (sidecar / local Linux).
pub fn ensure_iface(name: &str, linux_addr: std::net::Ipv4Addr) -> io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, linux_addr);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let _ = std::process::Command::new("ip")
            .args(["tuntap", "add", "dev", name, "mode", "tap", "user", &user])
            .status();
        let _ = std::process::Command::new("sudo")
            .args([
                "ip", "tuntap", "add", "dev", name, "mode", "tap", "user", &user,
            ])
            .status();
        let cidr = format!("{linux_addr}/24");
        let _ = std::process::Command::new("sudo")
            .args(["ip", "addr", "add", &cidr, "dev", name])
            .status();
        let st = std::process::Command::new("sudo")
            .args(["ip", "link", "set", "dev", name, "up"])
            .status()?;
        if !st.success() {
            return Err(io::Error::other(format!("could not bring {name} up")));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn linux_open(tun: &Path, name: &str) -> io::Result<TapInterface> {
    use std::os::fd::AsRawFd;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;

    if name.is_empty() || name.len() >= libc::IFNAMSIZ as usize {
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
            return Err(io::Error::last_os_error());
        }
    }

    Ok(TapInterface { file })
}

impl crate::interface::FrameIo for TapInterface {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }

    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.file.write_all(frame)
    }
}

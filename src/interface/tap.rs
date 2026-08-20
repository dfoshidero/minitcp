// The TAP as a source and sink of Ethernet frames.
//
// Once `sys::tapdev` has made the interface exist, this is the other end of the
// cable: open /dev/net/tun, name the interface we want to attach to, and from
// then on every read is one whole Ethernet frame and every write puts one on
// the wire. Creating and removing the device is deliberately not here.

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

impl crate::interface::FrameSource for TapInterface {
    fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl crate::interface::FrameSink for TapInterface {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.file.write_all(frame)
    }
}

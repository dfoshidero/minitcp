// src/interface/tap.rs
use std::fs::{File, OpenOptions};
use std::io::{self , Read , Write};
use std::os::fd::AsRawFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca; // ioctl: attach this file descriptor to a named TUN/TAP device
const IFF_TAP: libc::c_short = 0x0002; // TAP = Ethernet frames (layer 2). TUN would give raw IP instead.
const IFF_NO_PI: libc::c_short = 0x1000; // skip the kernel's extra 4-byte prefix so we see the frame as-is

pub struct TapInterface {
    file: File,
}

impl TapInterface {
    pub fn open(name: &str) -> io::Result<Self> {

        if name.is_empty() || name.len() >= libc::IFNAMSIZ as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TAP interface name"
            ));
        }

        // /dev/net/tun is a character device: open it like a file, then ioctl to pick tap0.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        // Kernel interface names live in a fixed-size C array (IFNAMSIZ bytes, including NUL).
        for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }

        unsafe {
            // | sets both bits in one flags field: TAP frames, and no packet-info prefix.
            ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;
        }

        let rc = unsafe {
            libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifr)
        };

        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { file })
    }

    pub fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }

    pub fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.file.write_all(frame)
    }
}

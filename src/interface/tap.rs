// src/interface/tap.rs
use std::fs::{File, OpenOptions};
use std::io::{self , Read , Write};
use std::os::fd::AsRawFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca; // system request code flag - tells the Linux kernel you want to attach a virtual TUN/TAP interface
const IFF_TAP: libc::c_short = 0x0002; // interface type flag - tells kernel to create a OSI layer 2 device
const IFF_NO_PI: libc::c_short = 0x1000; // packet information flag - tells kernel to not include packet information in the packet (easier to parse)

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

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(/dev/net/tun)?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }

        unsafe {
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

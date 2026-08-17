// src/interface/tap.rs
use std::fs::{File, OpenOptions};
use std::io::{self , Read , Write};
use std::os::fd::AsRawFd;

// ioctl command: "this open file is the named TAP/TUN device." Opening /dev/net/tun is not enough by itself.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
// TAP gives whole Ethernet frames (MACs, ARP). TUN would skip that and hand us raw IP — MiniTCP needs the Ethernet layer.
const IFF_TAP: libc::c_short = 0x0002;
// The kernel can prepend 4 extra bytes we would have to skip. This flag turns that off.
const IFF_NO_PI: libc::c_short = 0x1000;

pub struct TapInterface {
    file: File,
}

impl TapInterface {
    pub fn open(name: &str) -> io::Result<Self> {

        // The kernel copies the name into a fixed C array that includes a trailing NUL, so `>=` is too long.
        if name.is_empty() || name.len() >= libc::IFNAMSIZ as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TAP interface name"
            ));
        }

        // Character device: a file you read/write frames on. ioctl below attaches it to tap0.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        // Kernel reads the interface name from this C struct, not from the path we opened.
        for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }

        unsafe {
            // Two independent yes/no options share one flags field. OR turns both on.
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

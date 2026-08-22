// src/stack.rs

use std::io::{self, BufReader};
use std::net::Ipv4Addr;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::cli::{Command, Config, DropKind};
use crate::interface::FrameIo;
use crate::interface::pcap::{CaptureIo, HexReader, PcapReader, PcapWriter};
use crate::interface::tap::TapInterface;
use crate::log::{self, Verb};
use crate::proto::arp::reply_for;
use crate::proto::ethernet::{EthernetFrame, EthernetType};
use crate::proto::icmp::{make_echo_reply, set_echo_id};
use crate::proto::ipv4::{Ipv4Packet, Protocol};

fn protocol_name(protocol: Protocol) -> String {
    match protocol {
        Protocol::Icmp => "icmp".into(),
        Protocol::Udp => "udp".into(),
        Protocol::Tcp => "tcp".into(),
        Protocol::Unknown(n) => format!("protocol {n}"),
    }
}

fn icmp_id_seq(message: &[u8]) -> Option<(u16, u16)> {
    if message.len() < 8 {
        return None;
    }
    Some((
        u16::from_be_bytes([message[4], message[5]]),
        u16::from_be_bytes([message[6], message[7]]),
    ))
}

fn icmp_quiet(message: &[u8]) -> String {
    let (id, seq) = icmp_id_seq(message).unwrap_or((0, 0));
    format!("echo id={id} seq={seq}  len={}", message.len())
}

fn icmp_decode(message: &[u8]) -> String {
    let Some((id, seq)) = icmp_id_seq(message) else {
        return "truncated".into();
    };
    format!(
        "type={} code={} id={id} seq={seq}  len={}",
        message[0],
        message[1],
        message.len()
    )
}

fn arp_addrs(payload: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if payload.len() < 28 {
        return None;
    }
    Some((
        Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]),
        Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]),
    ))
}

fn ip_pair(src: Ipv4Addr, dst: Ipv4Addr) -> String {
    format!("{src} -> {dst}")
}

pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    pub fn from_entropy() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        Self::new(nanos)
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x >> 32) as u32
    }
}

pub fn drop_pct_hit(pct: u8, rng: &mut SeededRng) -> bool {
    if pct == 0 {
        return false;
    }
    if pct >= 100 {
        return true;
    }
    (rng.next_u32() % 100) < u32::from(pct)
}

fn open_tap(cfg: &Config) -> io::Result<TapInterface> {
    if !cfg.tun.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cannot open {}; reopen this folder in the Dev Container",
                cfg.tun.display()
            ),
        ));
    }

    let sys = format!("/sys/class/net/{}", cfg.iface);
    if !Path::new(&sys).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is not up yet; try `minitcp tap up`", cfg.iface),
        ));
    }

    const ATTEMPTS: usize = 5;
    for attempt in 1..=ATTEMPTS {
        match TapInterface::open_at(&cfg.tun, &cfg.iface) {
            Ok(tap) => return Ok(tap),
            Err(error) if attempt < ATTEMPTS && retryable_tap_attach(&error) => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "cannot attach to {}; try `minitcp tap up`: {error}",
                        cfg.iface
                    ),
                ));
            }
        }
    }
    Err(io::Error::other("TAP attach retry loop ended unexpectedly"))
}

fn retryable_tap_attach(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || matches!(error.raw_os_error(), Some(libc::ENODEV) | Some(libc::EBUSY))
}

pub fn run_bridge(cfg: Config) -> std::io::Result<()> {
    crate::interface::tap::ensure_iface(&cfg.iface, cfg.linux_addr)?;
    let tap = open_tap(&cfg)?;
    crate::interface::fwd::run_bridge(&cfg.listen, tap)
}

pub fn run_stack(cfg: Config) -> std::io::Result<()> {
    if let Command::Replay(path) = &cfg.command {
        let reader = PcapReader::open(path)?;
        return run_io(cfg, reader, EofBehavior::Success);
    }
    if cfg.hex {
        return run_io(
            cfg,
            HexReader::new(BufReader::new(io::stdin())),
            EofBehavior::Success,
        );
    }
    match cfg.transport() {
        crate::cli::Transport::Forwarded(addr) => {
            let frames = crate::interface::fwd::TcpFrames::connect(&addr).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot connect to TAP sidecar at {addr}; try `minitcp tap up`: {error}"
                    ),
                )
            })?;
            log::status::info(format!(
                "listening {} via {addr} as {} ({})",
                cfg.iface, cfg.addr, cfg.mac
            ));
            run_io(cfg, frames, EofBehavior::Failure)
        }
        crate::cli::Transport::LocalTap => {
            let tap = open_tap(&cfg)?;
            log::status::info(format!(
                "listening {} as {} ({})",
                cfg.iface, cfg.addr, cfg.mac
            ));
            run_io(cfg, tap, EofBehavior::Failure)
        }
    }
}

#[derive(Clone, Copy)]
enum EofBehavior {
    Success,
    Failure,
}

fn run_io<I: FrameIo>(cfg: Config, inner: I, eof_behavior: EofBehavior) -> std::io::Result<()> {
    let capture = match &cfg.write {
        Some(path) => Some(PcapWriter::create(path)?),
        None => None,
    };
    let mut frames = CaptureIo::new(inner, capture);
    let mut buffer = [0u8; 2048];
    let mut rng = SeededRng::from_entropy();
    let mut seen = 0u64;
    let _ = log::take_output_error();
    loop {
        if let Some(limit) = cfg.count
            && seen >= limit
        {
            return Ok(());
        }
        let n = frames.read_frame(&mut buffer).map_err(|error| {
            io::Error::new(error.kind(), format!("cannot read next frame: {error}"))
        })?;
        if n == 0 {
            return match eof_behavior {
                EofBehavior::Success => Ok(()),
                EofBehavior::Failure => Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "frame source closed unexpectedly",
                )),
            };
        }
        seen += 1;
        if let Some(reply) = handle_frame(&cfg, &buffer[..n], &mut rng) {
            frames.write_frame(&reply).map_err(|error| {
                io::Error::new(error.kind(), format!("cannot write reply frame: {error}"))
            })?;
        }
        if let Some(error) = log::take_output_error() {
            if error.kind() == io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(io::Error::new(
                error.kind(),
                format!("cannot write protocol output: {error}"),
            ));
        }
    }
}

fn handle_frame(cfg: &Config, bytes: &[u8], rng: &mut SeededRng) -> Option<Vec<u8>> {
    let verbose = cfg.verbose();
    let our_ip = cfg.our_ip_bytes();
    let our_mac = cfg.mac;
    let when = log::now();

    let frame = match EthernetFrame::parse(bytes) {
        Ok(frame) => frame,
        Err(e) => {
            log::emit_at(&when, Verb::Drop, "ethernet", "L2", "", e);
            return None;
        }
    };

    let macs = format!("{} -> {}", frame.source, frame.destination);

    if drop_pct_hit(cfg.drop_pct, rng) {
        log::emit_at(&when, Verb::Drop, "ethernet", "L2", &macs, "random drop");
        return None;
    }
    if cfg.drop.contains(&DropKind::Arp) && frame.ethertype == EthernetType::Arp {
        log::emit_at(&when, Verb::Drop, "arp", "L2", &macs, "dropped");
        return None;
    }
    if cfg.drop.contains(&DropKind::Ip) && frame.ethertype == EthernetType::Ipv4 {
        log::emit_at(&when, Verb::Drop, "ipv4", "L3", &macs, "dropped");
        return None;
    }

    match frame.ethertype {
        EthernetType::Arp => {
            let Some(reply) = reply_for(frame.payload, our_ip, our_mac) else {
                if verbose {
                    log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0806");
                    let arp_addrs = arp_addrs(frame.payload)
                        .map(|(spa, tpa)| ip_pair(spa, tpa))
                        .unwrap_or_default();
                    log::emit_cont(&when, Verb::More, "arp", "L2", &arp_addrs, "who-has");
                }
                return None;
            };

            let Some((spa, tpa)) = arp_addrs(frame.payload) else {
                log::emit_at(
                    &when,
                    Verb::Drop,
                    "arp",
                    "L2",
                    &macs,
                    "truncated ARP payload",
                );
                return None;
            };
            let mut ethernet_reply = Vec::new();
            EthernetFrame::write_ethernet(
                &mut ethernet_reply,
                frame.source,
                our_mac,
                0x0806,
                &reply,
            );

            if verbose {
                log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0806");
                log::emit_cont(
                    &when,
                    Verb::More,
                    "arp",
                    "L2",
                    &ip_pair(spa, tpa),
                    "who-has",
                );
                log::emit_cont(
                    &when,
                    Verb::Out,
                    "ethernet",
                    "L2",
                    &format!("{} -> {}", our_mac, frame.source),
                    "ethertype 0x0806",
                );
                log::emit_cont(
                    &when,
                    Verb::More,
                    "arp",
                    "L2",
                    &ip_pair(Ipv4Addr::from(our_ip), spa),
                    &format!("is-at {our_mac}"),
                );
            } else {
                log::emit_quiet(&when, "arp", &ip_pair(spa, tpa), "who-has");
            }
            return Some(ethernet_reply);
        }
        EthernetType::Ipv4 => match Ipv4Packet::parse(frame.payload) {
            Ok(packet) => {
                let ip_addrs = ip_pair(packet.source, packet.destination);
                if verbose {
                    log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0800");
                    log::emit_cont(
                        &when,
                        Verb::More,
                        "ipv4",
                        "L3",
                        &ip_addrs,
                        &format!(
                            "ttl={} proto={} payload={}",
                            packet.ttl,
                            protocol_name(packet.protocol),
                            packet.payload.len()
                        ),
                    );
                }

                match packet.protocol {
                    Protocol::Icmp => {
                        if packet.destination.octets() != our_ip {
                            if verbose {
                                log::emit_inside(&when, Verb::Drop, "icmp", "L3", "not for us");
                            } else {
                                log::emit_at(
                                    &when,
                                    Verb::Drop,
                                    "icmp",
                                    "L3",
                                    &ip_addrs,
                                    "not for us",
                                );
                            }
                            return None;
                        }
                        if cfg.drop.contains(&DropKind::Icmp) {
                            if verbose {
                                log::emit_inside(&when, Verb::Drop, "icmp", "L3", "dropped");
                            } else {
                                log::emit_at(&when, Verb::Drop, "icmp", "L3", &ip_addrs, "dropped");
                            }
                            return None;
                        }
                        if verbose {
                            log::emit_inside(
                                &when,
                                Verb::More,
                                "icmp",
                                "L3",
                                &icmp_decode(packet.payload),
                            );
                        }

                        match make_echo_reply(packet.payload) {
                            Ok(mut icmp_reply) => {
                                if let Some(id) = cfg.icmp_id {
                                    set_echo_id(&mut icmp_reply, id);
                                }
                                let mut ip_packet = Vec::new();
                                Ipv4Packet::write(
                                    &mut ip_packet,
                                    cfg.ttl,
                                    Protocol::Icmp,
                                    Ipv4Addr::from(our_ip),
                                    packet.source,
                                    &icmp_reply,
                                );
                                let mut ethernet_reply = Vec::new();
                                EthernetFrame::write_ethernet(
                                    &mut ethernet_reply,
                                    frame.source,
                                    our_mac,
                                    0x0800,
                                    &ip_packet,
                                );
                                if verbose {
                                    log::emit_cont(
                                        &when,
                                        Verb::Out,
                                        "ethernet",
                                        "L2",
                                        &format!("{} -> {}", our_mac, frame.source),
                                        "ethertype 0x0800",
                                    );
                                    log::emit_cont(
                                        &when,
                                        Verb::More,
                                        "ipv4",
                                        "L3",
                                        &ip_pair(Ipv4Addr::from(our_ip), packet.source),
                                        &format!(
                                            "ttl={} proto=icmp payload={}",
                                            cfg.ttl,
                                            icmp_reply.len()
                                        ),
                                    );
                                    log::emit_inside(
                                        &when,
                                        Verb::More,
                                        "icmp",
                                        "L3",
                                        &icmp_decode(&icmp_reply),
                                    );
                                } else {
                                    log::emit_quiet(
                                        &when,
                                        "icmp",
                                        &ip_addrs,
                                        &icmp_quiet(packet.payload),
                                    );
                                }
                                return Some(ethernet_reply);
                            }
                            Err(e) => {
                                if verbose {
                                    log::emit_inside(&when, Verb::Drop, "icmp", "L3", e);
                                } else {
                                    log::emit_at(&when, Verb::Drop, "icmp", "L3", &ip_addrs, e);
                                }
                            }
                        }
                    }
                    Protocol::Udp => {
                        if verbose {
                            log::emit_inside(&when, Verb::Drop, "udp", "L4", "not implemented");
                        } else {
                            log::emit_at(
                                &when,
                                Verb::Drop,
                                "udp",
                                "L4",
                                &ip_addrs,
                                "not implemented",
                            );
                        }
                    }
                    Protocol::Tcp => {
                        if verbose {
                            log::emit_inside(&when, Verb::Drop, "tcp", "L4", "not implemented");
                        } else {
                            log::emit_at(
                                &when,
                                Verb::Drop,
                                "tcp",
                                "L4",
                                &ip_addrs,
                                "not implemented",
                            );
                        }
                    }
                    Protocol::Unknown(n) => {
                        let reason = format!("unknown protocol {n}");
                        if verbose {
                            log::emit_cont(&when, Verb::Drop, "ipv4", "L3", "", &reason);
                        } else {
                            log::emit_at(&when, Verb::Drop, "ipv4", "L3", &ip_addrs, &reason);
                        }
                    }
                }
            }
            Err(e) => {
                if verbose {
                    log::emit_at(&when, Verb::In, "ethernet", "L2", &macs, "ethertype 0x0800");
                    log::emit_cont(&when, Verb::Drop, "ipv4", "L3", "", e);
                } else {
                    log::emit_at(&when, Verb::Drop, "ipv4", "L3", "", e);
                }
            }
        },
        EthernetType::Unknown(n) => {
            if verbose {
                log::emit_at(
                    &when,
                    Verb::In,
                    "ethernet",
                    "L2",
                    &macs,
                    &format!("ethertype 0x{n:04x}"),
                );
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Config, DropKind};
    use crate::interface::pcap::{PcapReader, PcapWriter, pcap_info};
    use crate::proto::checksum::internet_checksum;
    use crate::proto::ethernet::MacAddress;
    use crate::proto::icmp::make_echo_reply;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    const ARP_REQUEST: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];

    struct MockIo {
        reads: Rc<RefCell<VecDeque<Vec<u8>>>>,
        writes: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl FrameIo for MockIo {
        fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.reads.borrow_mut().pop_front() {
                None => Ok(0),
                Some(frame) => {
                    buffer[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
            }
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            self.writes.borrow_mut().push(frame.to_vec());
            Ok(())
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("minitcp-{name}-{n}.pcap"))
    }

    fn ping_frame() -> Vec<u8> {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, b'h', b'i'];
        let sum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut ip = Vec::new();
        Ipv4Packet::write(
            &mut ip,
            64,
            Protocol::Icmp,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            &icmp,
        );
        let mut eth = Vec::new();
        EthernetFrame::write_ethernet(
            &mut eth,
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            0x0800,
            &ip,
        );
        eth
    }

    fn reply(cfg: &Config, frame: &[u8]) -> Option<Vec<u8>> {
        handle_frame(cfg, frame, &mut SeededRng::new(1))
    }

    #[test]
    fn handle_frame_replies_to_arp() {
        let cfg = Config::defaults();
        let out = reply(&cfg, &ARP_REQUEST).expect("arp reply");
        assert_eq!(&out[0..6], &ARP_REQUEST[6..12]);
        assert_eq!(&out[6..12], &cfg.mac.0);
        assert_eq!(&out[12..14], &[0x08, 0x06]);
    }

    #[test]
    fn drop_arp_produces_no_write_icmp_still_replies() {
        let mut cfg = Config::defaults();
        cfg.drop = vec![DropKind::Arp];
        assert!(reply(&cfg, &ARP_REQUEST).is_none());
        assert!(reply(&cfg, &ping_frame()).is_some());
    }

    #[test]
    fn drop_icmp_produces_no_write_arp_still_replies() {
        let mut cfg = Config::defaults();
        cfg.drop = vec![DropKind::Icmp];
        assert!(reply(&cfg, &ping_frame()).is_none());
        assert!(reply(&cfg, &ARP_REQUEST).is_some());
    }

    #[test]
    fn drop_ip_ignores_ipv4_but_not_arp() {
        let mut cfg = Config::defaults();
        cfg.drop = vec![DropKind::Ip];
        assert!(reply(&cfg, &ping_frame()).is_none());
        assert!(reply(&cfg, &ARP_REQUEST).is_some());
    }

    #[test]
    fn drop_arp_and_icmp_together() {
        let mut cfg = Config::defaults();
        cfg.drop = vec![DropKind::Arp, DropKind::Icmp];
        assert!(reply(&cfg, &ARP_REQUEST).is_none());
        assert!(reply(&cfg, &ping_frame()).is_none());
    }

    #[test]
    fn drop_pct_zero_never_hundred_always_fifty_is_deterministic() {
        let mut rng = SeededRng::new(42);
        for _ in 0..32 {
            assert!(!drop_pct_hit(0, &mut rng));
        }
        let mut rng = SeededRng::new(42);
        for _ in 0..32 {
            assert!(drop_pct_hit(100, &mut rng));
        }
        let mut a = SeededRng::new(7);
        let mut b = SeededRng::new(7);
        let seq_a: Vec<bool> = (0..20).map(|_| drop_pct_hit(50, &mut a)).collect();
        let seq_b: Vec<bool> = (0..20).map(|_| drop_pct_hit(50, &mut b)).collect();
        assert_eq!(seq_a, seq_b);
        assert!(seq_a.iter().any(|h| *h) && seq_a.iter().any(|h| !*h));
    }

    #[test]
    fn ttl_and_id_on_icmp_reply() {
        let mut cfg = Config::defaults();
        cfg.ttl = 32;
        cfg.icmp_id = Some(0x9999);
        let out = reply(&cfg, &ping_frame()).expect("icmp reply");
        let frame = EthernetFrame::parse(&out).unwrap();
        let ip = Ipv4Packet::parse(frame.payload).unwrap();
        assert_eq!(ip.ttl, 32);
        assert_eq!(&ip.payload[4..6], &[0x99, 0x99]);
        assert_eq!(internet_checksum(ip.payload), 0);
        let default = reply(&Config::defaults(), &ping_frame()).unwrap();
        let default_ip =
            Ipv4Packet::parse(EthernetFrame::parse(&default).unwrap().payload).unwrap();
        assert_eq!(default_ip.ttl, 64);
        assert_eq!(&default_ip.payload[4..6], &[0x12, 0x34]);
    }

    #[test]
    fn count_stops_before_extra_reads() {
        let mut cfg = Config::defaults();
        cfg.count = Some(2);
        let reads = Rc::new(RefCell::new(VecDeque::from([
            ARP_REQUEST.to_vec(),
            ARP_REQUEST.to_vec(),
            ARP_REQUEST.to_vec(),
        ])));
        let writes = Rc::new(RefCell::new(Vec::new()));
        let io = MockIo {
            reads: reads.clone(),
            writes: writes.clone(),
        };
        run_io(cfg, io, EofBehavior::Success).unwrap();
        assert_eq!(writes.borrow().len(), 2);
        assert_eq!(reads.borrow().len(), 1);
    }

    #[test]
    fn unexpected_live_eof_is_a_runtime_failure() {
        let io = MockIo {
            reads: Rc::new(RefCell::new(VecDeque::new())),
            writes: Rc::new(RefCell::new(Vec::new())),
        };
        let error = run_io(Config::defaults(), io, EofBehavior::Failure).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(error.to_string().contains("closed unexpectedly"), "{error}");
    }

    #[test]
    fn pcap_write_replay_roundtrip_through_reader() {
        let path = tmp("round");
        {
            let mut w = PcapWriter::create(&path).unwrap();
            w.write_frame(&ARP_REQUEST).unwrap();
        }
        let mut r = PcapReader::open(&path).unwrap();
        let mut buf = [0u8; 2048];
        let n = r.read_frame(&mut buf).unwrap();
        assert_eq!(&buf[..n], &ARP_REQUEST);
        let info = pcap_info(&path).unwrap();
        assert!(info.contains("0x0806"));
        assert!(info.contains("1 frames"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn echo_id_helper_rewrites_checksum() {
        let frame = ping_frame();
        let eth = EthernetFrame::parse(&frame).unwrap();
        let ip = Ipv4Packet::parse(eth.payload).unwrap();
        let mut reply = make_echo_reply(ip.payload).unwrap();
        set_echo_id(&mut reply, 7);
        assert_eq!(&reply[4..6], &[0x00, 0x07]);
        assert_eq!(internet_checksum(&reply), 0);
    }
}

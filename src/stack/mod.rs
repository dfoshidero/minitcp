//! The userspace TCP/IP stack.
//!
//!   rng     deterministic frame dropping, for `--drop-pct`
//!   handle  one frame in, at most one frame out — the protocol logic
//!   run     choosing a carrier and running the loop over it

mod handle;
mod rng;
mod run;

pub use run::{run_bridge, run_stack};

#[cfg(test)]
mod tests {
    use super::handle::handle_frame;
    use super::rng::SeededRng;
    use super::run::{EofBehavior, run_io};
    use crate::cli::{Config, DropKind};
    use crate::interface::pcap::{PcapReader, PcapWriter, pcap_info};
    use crate::interface::{FrameSink, FrameSource};
    use crate::proto::checksum::internet_checksum;
    use crate::proto::ethernet::EthernetFrame;
    use crate::proto::ethernet::MacAddress;
    use crate::proto::icmp::{make_echo_reply, set_echo_id};
    use crate::proto::ipv4::{Ipv4Packet, Protocol};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;
    use std::io;
    use std::net::Ipv4Addr;
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

    impl FrameSource for MockIo {
        fn read_frame(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.reads.borrow_mut().pop_front() {
                None => Ok(0),
                Some(frame) => {
                    buffer[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
            }
        }
    }

    impl FrameSink for MockIo {
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

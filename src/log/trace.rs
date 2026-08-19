//! Narrating a frame as it is taken apart.
//!
//! Quiet:  23:12:05  icmp  10.0.0.1 -> 10.0.0.2  echo id=1 seq=1  len=64
//! Verbose first line:
//!   23:12:05  [IN]   ethernet  L2  02:00:… -> 02:00:…  ethertype 0x0800
//!
//! The verbose form is a small tree, because that is what a frame is: an
//! Ethernet header with an IPv4 packet inside it with an ICMP message inside
//! that. Each layer gets a row. IPv4 and ARP keep their own `src -> dst`, while
//! ICMP, TCP and UDP are drawn indented under the IPv4 line they arrived in —
//! they have no addresses of their own, they borrow the packet's.

use super::emit_protocol_line;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    In,
    Out,
    Drop,
    More,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::In => "IN",
            Self::Out => "OUT",
            Self::Drop => "DROP",
            Self::More => "..",
        }
    }
}

/// One trace line before it is rendered. Private to this module: callers say
/// `emit_at`/`emit_cont`/`emit_inside`, which name the shape of the line.
struct Event<'a> {
    show_time: bool,
    verb: Verb,
    layer: &'a str,
    osi: &'a str,
    address: &'a str,
    reason: &'a str,
}

impl<'a> Event<'a> {
    fn format_with(&self, when: &str) -> String {
        let when_col = if self.show_time {
            when.to_string()
        } else {
            " ".repeat(when.len())
        };
        let verb = format!("[{}]", self.verb.as_str());
        let detail = if self.address.is_empty() {
            self.reason.to_string()
        } else if self.reason.is_empty() {
            self.address.to_string()
        } else {
            format!("{}  {}", self.address, self.reason)
        };
        format!(
            "{when_col}  {verb:<6}  {:<8}  {}  {detail}",
            self.layer, self.osi,
        )
    }

    fn emit(&self, when: &str) {
        emit_protocol_line(&self.format_with(when));
    }
}

/// One-line quiet summary: time, layer, addresses, reason. No IN/OUT.
pub fn format_quiet(when: &str, layer: &str, address: &str, reason: &str) -> String {
    format!("{when}  {layer}  {address}  {reason}")
}

pub fn emit_quiet(when: &str, layer: &str, address: &str, reason: &str) {
    emit_protocol_line(&format_quiet(when, layer, address, reason));
}

pub fn emit_at(when: &str, verb: Verb, layer: &str, osi: &str, address: &str, reason: &str) {
    Event {
        show_time: true,
        verb,
        layer,
        osi,
        address,
        reason,
    }
    .emit(when);
}

pub fn emit_cont(when: &str, verb: Verb, layer: &str, osi: &str, address: &str, reason: &str) {
    Event {
        show_time: false,
        verb,
        layer,
        osi,
        address,
        reason,
    }
    .emit(when);
}

/// Protocol carried inside IPv4 (ICMP, UDP, TCP). Tree-child of the ipv4 line.
pub fn emit_inside(when: &str, verb: Verb, layer: &str, osi: &str, reason: &str) {
    let layer = format!("└── {layer}");
    Event {
        show_time: false,
        verb,
        layer: &layer,
        osi,
        address: "",
        reason,
    }
    .emit(when);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_line_is_one_row() {
        assert_eq!(
            format_quiet(
                "23:12:05",
                "icmp",
                "10.0.0.1 -> 10.0.0.2",
                "echo id=1 seq=1  len=64"
            ),
            "23:12:05  icmp  10.0.0.1 -> 10.0.0.2  echo id=1 seq=1  len=64"
        );
    }

    #[test]
    fn verbose_in_keeps_address() {
        let line = Event {
            show_time: true,
            verb: Verb::In,
            layer: "ethernet",
            osi: "L2",
            address: "02:00:00:00:00:01 -> 02:00:00:00:00:02",
            reason: "ethertype 0x0800",
        }
        .format_with("23:12:05");
        assert_eq!(
            line,
            "23:12:05  [IN]    ethernet  L2  02:00:00:00:00:01 -> 02:00:00:00:00:02  ethertype 0x0800"
        );
    }

    #[test]
    fn verbose_ipv4_has_no_address_gap() {
        let line = Event {
            show_time: false,
            verb: Verb::More,
            layer: "ipv4",
            osi: "L3",
            address: "10.0.0.1 -> 10.0.0.2",
            reason: "ttl=64 proto=icmp payload=64",
        }
        .format_with("23:12:05");
        assert_eq!(
            line,
            "          [..]    ipv4      L3  10.0.0.1 -> 10.0.0.2  ttl=64 proto=icmp payload=64"
        );
    }

    #[test]
    fn verbose_icmp_sits_inside_ipv4() {
        let line = Event {
            show_time: false,
            verb: Verb::More,
            layer: "└── icmp",
            osi: "L3",
            address: "",
            reason: "type=8 code=0 id=1 seq=1  len=64",
        }
        .format_with("23:12:05");
        assert_eq!(
            line,
            "          [..]    └── icmp  L3  type=8 code=0 id=1 seq=1  len=64"
        );
    }
}

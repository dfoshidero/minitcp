// src/proto/error.rs
//
// Why a parser refused a packet. This is a public contract: callers should be
// able to match on the reason, not string-match on a message. The `Display`
// text is what the CLI prints, so it stays stable.

/// A packet this stack will not accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than the 14-byte Ethernet II header needs.
    TruncatedEthernet,
    /// Fewer bytes than the 20-byte IPv4 header needs.
    TruncatedIpv4,
    /// Version is not 4, or IHL claims a header shorter than 20 bytes.
    InvalidIpv4Header,
    /// Total Length disagrees with the header length or the bytes we hold.
    InvalidIpv4TotalLength,
    /// A fragment. v1 rejects these rather than reassembling them.
    Ipv4FragmentUnsupported,
    /// The IPv4 header checksum does not come out to zero.
    BadIpv4Checksum,
    /// Fewer bytes than the 8-byte ICMP echo header needs.
    TruncatedIcmpEcho,
    /// An ICMP message that is not type 8 / code 0.
    NotEchoRequest,
    /// The ICMP checksum does not come out to zero.
    BadIcmpChecksum,
}

impl ParseError {
    /// The layer that rejected the packet: `"ethernet"`, `"ipv4"` or `"icmp"`.
    pub fn layer(self) -> &'static str {
        match self {
            Self::TruncatedEthernet => "ethernet",
            Self::TruncatedIpv4
            | Self::InvalidIpv4Header
            | Self::InvalidIpv4TotalLength
            | Self::Ipv4FragmentUnsupported
            | Self::BadIpv4Checksum => "ipv4",
            Self::TruncatedIcmpEcho | Self::NotEchoRequest | Self::BadIcmpChecksum => "icmp",
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TruncatedEthernet => "truncated ethernet frame",
            Self::TruncatedIpv4 => "truncated ipv4 header",
            Self::InvalidIpv4Header => "invalid ipv4 header",
            Self::InvalidIpv4TotalLength => "invalid ipv4 total length",
            Self::Ipv4FragmentUnsupported => "ipv4 fragmentation unsupported",
            Self::BadIpv4Checksum => "bad ipv4 checksum",
            Self::TruncatedIcmpEcho => "truncated ICMP echo",
            Self::NotEchoRequest => "not echo request",
            Self::BadIcmpChecksum => "bad icmp checksum",
        })
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_the_ones_the_cli_prints() {
        assert_eq!(
            ParseError::TruncatedEthernet.to_string(),
            "truncated ethernet frame"
        );
        assert_eq!(ParseError::BadIcmpChecksum.to_string(), "bad icmp checksum");
        assert_eq!(
            ParseError::Ipv4FragmentUnsupported.to_string(),
            "ipv4 fragmentation unsupported"
        );
    }

    #[test]
    fn each_error_names_the_layer_that_raised_it() {
        assert_eq!(ParseError::TruncatedEthernet.layer(), "ethernet");
        assert_eq!(ParseError::BadIpv4Checksum.layer(), "ipv4");
        assert_eq!(ParseError::NotEchoRequest.layer(), "icmp");
    }
}

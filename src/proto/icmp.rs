// src/proto/icmp.rs

use super::checksum::internet_checksum;

/// ICMP Echo Request is type 8 / code 0. Echo Reply is type 0 / code 0.
/// Checksum covers the entire ICMP message (header + payload) - unlike TCP/UDP which only cover the header.

pub fn make_echo_reply(request: &[u8]) -> Result<Vec<u8>, &'static str> {
    if request.len() < 8 {
        return Err("truncated ICMP echo");
    }
    if request[0] != 8 || request[1] != 0 {
        return Err("not echo request");
    }
    if internet_checksum(request) != 0 {
        return Err("bad icmp checksum");
    }

    let mut reply = request.to_vec(); // copy the request to a new vector
    // we are copying the request to a new vector because we need to modify the header``
    reply[0] = 0; // Echo Reply
    reply[2] = 0; // checksum must be recalculated from scratch
    reply[3] = 0;

    let sum = internet_checksum(&reply); // recalculate the checksum
    reply[2..4].copy_from_slice(&sum.to_be_bytes()); // store the checksum in the header
    Ok(reply) // return the reply
}

pub fn set_echo_id(message: &mut [u8], id: u16) {
    if message.len() < 8 {
        return;
    }
    message[4..6].copy_from_slice(&id.to_be_bytes());
    message[2] = 0;
    message[3] = 0;
    let sum = internet_checksum(message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

     fn echo_request_with_payload(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut req = Vec::with_capacity(8 + payload.len());
        req.push(8); // Echo Request
        req.push(0); // code
        req.extend_from_slice(&[0, 0]); // checksum placeholder
        req.extend_from_slice(&id.to_be_bytes());
        req.extend_from_slice(&seq.to_be_bytes());
        req.extend_from_slice(payload);
        let sum = internet_checksum(&req);
        req[2..4].copy_from_slice(&sum.to_be_bytes());
        req
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(make_echo_reply(&[8, 0, 0, 0, 0, 1, 0]).err(), Some("truncated ICMP echo"));
    }

    #[test]
    fn rejects_non_echo() {
        // type 0 is already a reply; we do not bounce it again
        let mut bytes = echo_request_with_payload(1, 1, b"hi");
        bytes[0] = 0;
        bytes[2] = 0;
        bytes[3] = 0;
        let sum = internet_checksum(&bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(make_echo_reply(&bytes).err(), Some("not echo request"));
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut req = echo_request_with_payload(1, 2, b"payload");
        req[2] ^= 0xff;
        assert_eq!(make_echo_reply(&req).err(), Some("bad icmp checksum"));
    }

    #[test]
    fn reply_preserves_id_seq_payload_and_checksums() {
        let req = echo_request_with_payload(0x1234, 0x0007, b"hello");
        let reply = make_echo_reply(&req).unwrap();
        assert_eq!(reply[0], 0); // Echo Reply
        assert_eq!(reply[1], 0);
        assert_eq!(&reply[4..8], &req[4..8]); // identifier + sequence
        assert_eq!(&reply[8..], b"hello");
        assert_eq!(internet_checksum(&reply), 0);
        assert_ne!(&reply[2..4], &req[2..4]); // type changed, so checksum must change
    }
}

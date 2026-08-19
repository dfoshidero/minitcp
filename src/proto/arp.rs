// src/proto/arp.rs

use super::ethernet::MacAddress;

// We invented this MAC. The leading 02 marks it as "not from a real NIC (Network Interface Card) factory."
pub const OUR_MAC: MacAddress = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
pub const OUR_IP: [u8; 4] = [10, 0, 0, 2];

const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

pub fn reply_for(request: &[u8], our_ip: [u8; 4], our_mac: MacAddress) -> Option<[u8; 28]> {
    // Linux uses ARP to learn our MAC before it can send IPv4 to 10.0.0.2.
    // Ethernet+IPv4 ARP is a fixed 28-byte layout, so we can use constant offsets.
    if request.len() < 28 {
        return None;
    }

    // 16-bit fields are big-endian, same as Ethernet.
    // from_be_bytes: two bytes [hi, lo] become one number. [0x08, 0x00] → 0x0800.

    // select hardware type, protocol type, and operation from the request
    let hardware_type = u16::from_be_bytes(request[0..2].try_into().ok()?); // [0..2] HTYPE: what a "hardware address" is
    let protocol_type = u16::from_be_bytes(request[2..4].try_into().ok()?); // [2..4] PTYPE: what a "protocol address" is
    let operation = u16::from_be_bytes(request[6..8].try_into().ok()?); // [6..8] OPER: question vs answer

    // Only support Ethernet hardware and IPv4 protocol
    // 1 = Ethernet, 0x0800 = IPv4, [4]=6 MAC bytes, [5]=4 IPv4 bytes.
    if hardware_type != 1 || protocol_type != 0x0800 || request[4] != 6 || request[5] != 4 {
        return None;
    }

    let target_ip: [u8; 4] = request[24..28].try_into().ok()?; // [24..28] TPA: "who has this IP?"

    // ignore replies and requests for other IP addresses
    if operation != ARP_REQUEST || target_ip != our_ip {
        return None;
    }

    // store sender hardware address (remember it for later)
    let requester_mac: [u8; 6] = request[8..14].try_into().ok()?; // [8..14] SHA: who asked (sender's hardware address, also Ethernet destination in main.rs)
    let requester_ip: [u8; 4] = request[14..18].try_into().ok()?; // [14..18] SPA: sender's protocol address

    // Same 28-byte layout, roles swapped: we are the sender, they are the target (build the reply)
    let mut reply = [0u8; 28];

    reply[0..2].copy_from_slice(&1u16.to_be_bytes()); // HTYPE: Ethernet
    reply[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // PTYPE: IPv4
    reply[4] = 6; // HLEN: hardware address length
    reply[5] = 4; // PLEN: protocol address length
    reply[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes()); // OPER: operation (reply)

    reply[8..14].copy_from_slice(&our_mac.0); // SHA: our MAC — this is what Linux stores in `ip neigh`
    reply[14..18].copy_from_slice(&our_ip); // SPA: our IP
    reply[18..24].copy_from_slice(&requester_mac); // THA: target's hardware address (their MAC)
    reply[24..28].copy_from_slice(&requester_ip); // TPA: target's protocol address (their IP)

    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHO_HAS_10_0_0_2: [u8; 28] = [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
    ];

    fn who_has(target: [u8; 4]) -> [u8; 28] {
        let mut req = WHO_HAS_10_0_0_2;
        req[24..28].copy_from_slice(&target);
        req
    }

    #[test]
    fn default_identity_still_answers() {
        let reply = reply_for(&WHO_HAS_10_0_0_2, OUR_IP, OUR_MAC).unwrap();
        assert_eq!(&reply[8..14], &OUR_MAC.0);
        assert_eq!(&reply[14..18], &OUR_IP);
        assert_eq!(&reply[24..28], &[10, 0, 0, 1]);
    }

    #[test]
    fn custom_ip_and_mac_are_independent() {
        let ip = [10, 0, 0, 3];
        let mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]);
        assert!(reply_for(&who_has(OUR_IP), ip, mac).is_none());
        let reply = reply_for(&who_has(ip), ip, mac).unwrap();
        assert_eq!(&reply[8..14], &mac.0);
        assert_eq!(&reply[14..18], &ip);

        let default_ip_new_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x09]);
        let reply = reply_for(&WHO_HAS_10_0_0_2, OUR_IP, default_ip_new_mac).unwrap();
        assert_eq!(&reply[8..14], &default_ip_new_mac.0);
        assert_eq!(&reply[14..18], &OUR_IP);
    }
}

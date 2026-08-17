// src/arp.rs

use crate::ethernet::MacAddress;

// 02:... is locally administered (we picked it). Not a burned-in NIC address.
pub const OUR_MAC: MacAddress =
    MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
pub const OUR_IP: [u8; 4] = [10, 0, 0, 2];

const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

pub fn reply_for(request: &[u8]) -> Option<[u8; 28]> {
    // Linux uses ARP to learn our MAC before it can send IPv4 to 10.0.0.2.
    // Ethernet+IPv4 ARP is a fixed 28-byte layout, so we can use constant offsets.
    if request.len() < 28 {
        return None;
    }

    // 16-bit fields are big-endian, same as Ethernet.
    let hardware_type =
        u16::from_be_bytes(request[0..2].try_into().ok()?); // [0..2] HTYPE
    let protocol_type =
        u16::from_be_bytes(request[2..4].try_into().ok()?); // [2..4] PTYPE
    let operation =
        u16::from_be_bytes(request[6..8].try_into().ok()?); // [6..8] OPER

    // 1 = Ethernet, 0x0800 = IPv4, [4]=6 MAC bytes, [5]=4 IPv4 bytes.
    // Anything else would make the later offsets wrong, so drop it.
    if hardware_type != 1
        || protocol_type != 0x0800
        || request[4] != 6
        || request[5] != 4
    {
        return None;
    }

    let target_ip: [u8; 4] = request[24..28].try_into().ok()?; // [24..28] TPA

    // Only answer "who has OUR_IP?" Ignore replies and questions for other hosts.
    if operation != ARP_REQUEST || target_ip != OUR_IP {
        return None;
    }

    let requester_mac: [u8; 6] =
        request[8..14].try_into().ok()?; // [8..14] SHA
    let requester_ip: [u8; 4] =
        request[14..18].try_into().ok()?; // [14..18] SPA

    // Swap roles: we are now the sender, the asker is the target.
    let mut reply = [0u8; 28];

    reply[0..2].copy_from_slice(&1u16.to_be_bytes()); // HTYPE: Ethernet
    reply[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // PTYPE: IPv4
    reply[4] = 6; // HLEN
    reply[5] = 4; // PLEN
    reply[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes()); // OPER: reply

    reply[8..14].copy_from_slice(&OUR_MAC.0); // SHA: our MAC
    reply[14..18].copy_from_slice(&OUR_IP); // SPA: our IP
    reply[18..24].copy_from_slice(&requester_mac); // THA: who asked
    reply[24..28].copy_from_slice(&requester_ip); // TPA: their IP

    Some(reply)

}


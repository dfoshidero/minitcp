// src/arp.rs

use crate::ethernet::MacAddress;

pub const OUR_MAC: MacAddress =
    MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
pub const OUR_IP: [u8; 4] = [10, 0, 0, 2];

const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

pub fn reply_for(request: &[u8]) -> Option<[u8; 28]> {

    // fail early - an Ethernet/IPv4 ARP packet must contain 28 types.
    if request.len() < 28 {
        return None;
    }

    // select hardware type
    let hardware_type = 
        u16::from_be_bytes(request[0..2].try_into().ok()?);

    // select protocol type
    let protocol_type = 
        u16::from_be_bytes(request[2..4].try_into().ok()?);

    // select operation
    let operation = 
        u16::from_be_bytes(request[6..8].try_into().ok()?);

    // Only support Ethernet (1) hardware and IPv4 (0x0800) protocol
    if hardware_type != 1
        || protocol_type != 0x0800 
        || request[4] != 6
        || request[5] != 4
    {
        return None;
    }

    let target_ip = [u8; 4] = request[24..28].try_into().ok()?;

    // ignore replies and requests for other IP addresses
    if operation != ARP_REQUEST || target_ip != OUR_IP {
        return None;
    }

    // store sender hardware address (remember it for later)
    let requester_mac: [u8; 6] =
        request[8..14].try_into().ok()?;

    let requester_ip: [u8; 4] =
        request[14..18].try_into().ok()?;

    // build the reply
    let mut reply = [0u8; 28];
    
    
    reply[0..2].copy_from_slice(&1u16.to_be_bytes()); // Hardware Type (HTYPE): addresses in this ARP packet are Ethernet addresses.
    reply[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // Protocol Type (PTYPE): ARP is resolving addresses for the IPv4 protocol.
    reply[4] = 6; // Hardware Address Length (HLEN) = 6 bytes.
    reply[5] = 4; // Protocol Address Length (PLEN) = 4 bytes.
    reply[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes()); // Operation (OPER): ARP reply (not a request).

    reply[8..14].copy_from_slice(&OUR_MAC.0); // Sender Hardware Address (SHA): MiniTCP's MAC address.
    reply[14..18].copy_from_slice(&OUR_IP); // Sender Protocol Address (SPA): MiniTCP's IPv4 address.

    reply[18..24].copy_from_slice(&requester_mac); // Target Hardware Address (THA): the MAC address of the requester.
    reply[24..28].copy_from_slice(&requester_ip); // Target Protocol Address (TPA): the IPv4 address of the requester.

    Some(reply)

}


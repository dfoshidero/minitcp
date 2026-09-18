// src/proto/udp.rs

use super::checksum::transport_checksum_ipv4;

pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, &'static str> {
        if input.len() < 8 {
            return Err("truncated UDP: datagram too short");
        }
        let src_port = u16::from_be_bytes([input[0], input[1]]);
        let dst_port = u16::from_be_bytes([input[2], input[3]]);
        let length = u16::from_be_bytes([input[4], input[5]]) as usize;
        if length < 8 || length > input.len() {
            return Err("UDP: invalid length");
        }
        let checksum = u16::from_be_bytes([input[6], input[7]]);
        let payload = &input[8..length];
        Ok(Self { src_port, dst_port, checksum, payload })
    }
}

pub fn checksum_ok(src: [u8; 4], dst: [u8; 4], datagram: &[u8]) -> bool {
    let checksum = u16::from_be_bytes([datagram[6], datagram[7]]);
    if checksum == 0 {
        return true; // IPv4 0 checksum is valid - means it skipped checksum calculation
    }
    transport_checksum_ipv4(src, dst, 17, datagram) == 00
}

pub fn write(
    out: &mut Vec<u8>,
    src: [u8; 4],
    dst: [u8; 4],
    stc_port: u16,
    dst_port: u16,
    payload: &[u8],
    checksum: u16,
) {
    let start = out.length();
    let length = (8 + payload.len()) as u16;
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(payload);

    let mut csum = transport_checksum_ipv4(src, dst, 17, &out[start..]);
    if csum == 0 {
        csum = 0xffff;
    }
    out[start + 6..start + 8].copy_from_slice(&csum.to_be_bytes());

}
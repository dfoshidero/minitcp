// src/checksum.rs

/// Internet checksum (RFC 1071). IPv4 uses this on the header; TCP/UDP will reuse it later.
/// Parse checks "checksum of the header, including the checksum field, is 0."
/// Write does the inverse: put 0 in that field, run this, then store the result.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);

    for chunk in &mut chunks {
        // Add 16-bit pieces. u32 is a wider bucket so overflow is not lost — we need it below.
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let [last] = chunks.remainder() {
        // This algorithm always adds two-byte pairs. A leftover byte is treated as a pair
        // whose second byte is zero. Shift left 8 to put the leftover in the first slot of that pair.
        sum += (*last as u32) << 8;
    }

    while (sum >> 16) != 0 {
        // Anything that didn't fit in 16 bits is still part of the sum. Add it back
        // until the total fits — that wraparound is required, not a bug.
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Flip every bit. Together with "valid headers checksum to 0", the stored field
    // is whatever value makes that true.
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc1071_example() {
        let bytes = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&bytes), 0x220d);
    }
    #[test]
    fn odd_byte_is_high_octet() {
        assert_eq!(internet_checksum(&[0xab]), internet_checksum(&[0xab, 0x00]));
    }
    #[test]
    fn valid_header_checksums_to_zero() {
        let header = [
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x01, 0x66, 0xdf, 0x0a, 0x00, 0x00, 0x01,
            0x0a, 0x00, 0x00, 0x02,
        ];
        assert_eq!(internet_checksum(&header), 0);
    }
}

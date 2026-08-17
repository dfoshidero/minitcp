// src/checksum.rs

/// RFC 1071: add 16-bit big-endian words, fold the carry, then ones-complement.
/// A valid IPv4 header (checksum field included) checksums to 0.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);

    for chunk in &mut chunks {
        // Widen to u32 so the running total can hold carry past 16 bits.
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let [last] = chunks.remainder() {
        // Odd leftover byte is the high half of a word: 0xAB → 0xAB00, not 0x00AB.
        sum += (*last as u32) << 8;
    }

    while (sum >> 16) != 0 {
        // >> 16 = bits that overflowed 16-bit addition; & 0xFFFF = the low 16 bits.
        // Adding them back is "end-around carry."
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16 // ones-complement of the folded 16-bit sum
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc1071_example() {
        // 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7 -> folded -> complement 0x220d
        let bytes = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&bytes), 0x220d);
    }
    #[test]
    fn odd_byte_is_high_octet() {
        assert_eq!(internet_checksum(&[0xab]), internet_checksum(&[0xab, 0x00]));
    }
    #[test]
    fn valid_header_checksums_to_zero() {
        // IPv4 header below already contains the correct checksum 0x66df.
        let header = [
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x01, 0x66, 0xdf, 0x0a, 0x00, 0x00, 0x01,
            0x0a, 0x00, 0x00, 0x02,
        ];
        assert_eq!(internet_checksum(&header), 0);
    }
}
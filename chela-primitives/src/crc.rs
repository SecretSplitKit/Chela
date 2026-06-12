//! CRC-11/UMTS (poly 0x307, init 0x000, non-reflected, xorout 0x000) - the per-share
//! transcription checksum for the bip39-wordlist scheme. Chosen for hand-auditability:
//! init 0, no reflection, no final XOR == textbook GF(2) polynomial long division.

/// CRC-11/UMTS over `data`. Non-reflected, MSB-first; returns an 11-bit value (`0..=0x7FF`).
///
/// Bytewise long division by the generator `x¹¹+x⁹+x⁸+x²+x+1` (`0x307`, implicit `x¹¹`).
pub fn crc11_umts(data: &[u8]) -> u16 {
    const POLY: u16 = 0x307;
    const MSB: u16 = 0x400; // bit 10, the high bit of an 11-bit register
    let mut crc: u16 = 0x000;
    for &byte in data {
        // Align the byte's MSB with the register MSB (bits 10..3).
        crc ^= u16::from(byte) << 3;
        for _ in 0..8 {
            crc = if crc & MSB != 0 {
                ((crc << 1) ^ POLY) & 0x7FF
            } else {
                (crc << 1) & 0x7FF
            };
        }
    }
    crc & 0x7FF
}

#[cfg(test)]
mod tests {
    use super::crc11_umts;

    #[test]
    fn catalogue_check_value() {
        // reveng catalogue CRC-11/UMTS check: CRC of ASCII "123456789" == 0x061.
        assert_eq!(crc11_umts(b"123456789"), 0x061);
    }

    #[test]
    fn empty_is_init() {
        assert_eq!(crc11_umts(b""), 0x000);
    }

    #[test]
    fn single_bit_changes_crc() {
        assert_ne!(crc11_umts(&[0x00]), crc11_umts(&[0x01]));
    }

    #[test]
    fn output_is_11_bit() {
        for n in 0u16..=512 {
            let b = n.to_be_bytes();
            assert!(crc11_umts(&b) <= 0x7FF);
        }
    }
}

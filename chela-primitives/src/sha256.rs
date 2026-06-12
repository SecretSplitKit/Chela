//! SHA-256 per FIPS 180-4 § 6.2.

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const BLOCK_BYTES: usize = 64;
const DIGEST_BYTES: usize = 32;

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// `a..h` are the SHA-256 working variables in FIPS 180-4 § 6.2.2 notation; spec names kept
// so audit against the standard is line-by-line.
#[allow(clippy::many_single_char_names, clippy::needless_range_loop)]
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_BYTES]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let off = i * 4;
        w[i] = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
    }
    for i in 16..64 {
        w[i] = small_sigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);

    // Wipe the 256-byte message schedule; it's the largest secret-derived scratch
    // on the stack. The working variables a..h (32 bytes) are left to be overwritten
    // by the next compress call or the next stack frame.
    crate::zeroize::Zeroize::zeroize(&mut w);
}

/// Incremental SHA-256 hasher.
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; BLOCK_BYTES],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buffer_len > 0 {
            let need = BLOCK_BYTES - self.buffer_len;
            let take = data.len().min(need);
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];

            if self.buffer_len == BLOCK_BYTES {
                compress(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }

        while let Some((block, rest)) = data.split_first_chunk::<BLOCK_BYTES>() {
            compress(&mut self.state, block);
            data = rest;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_BYTES] {
        let bit_len = self.total_len.wrapping_mul(8);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        for byte in &mut self.buffer[self.buffer_len..] {
            *byte = 0;
        }

        // If the 8-byte length won't fit in this block, flush and start a clean one.
        if self.buffer_len > BLOCK_BYTES - 8 {
            compress(&mut self.state, &self.buffer);
            self.buffer = [0u8; BLOCK_BYTES];
        }

        self.buffer[BLOCK_BYTES - 8..].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.buffer);

        let mut out = [0u8; DIGEST_BYTES];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[must_use]
    pub fn hash(data: &[u8]) -> [u8; DIGEST_BYTES] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // The buffer holds raw input bytes (for short messages, the entire secret).
        // The state words are non-invertibly derived from input but still secret-bearing.
        crate::zeroize::volatile_set(&mut self.buffer);
        crate::zeroize::Zeroize::zeroize(&mut self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256;

    fn hex32(hex: &str) -> [u8; 32] {
        let bytes = hex.as_bytes();
        assert_eq!(bytes.len(), 64, "hex32 expects 64 hex chars");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = (nibble(bytes[i * 2]) << 4) | nibble(bytes[i * 2 + 1]);
        }
        out
    }

    fn nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex digit: {b}"),
        }
    }

    // FIPS 180-2 / NIST CAVP "Sample Test Vectors" for SHA-256.

    #[test]
    fn nist_empty_string() {
        assert_eq!(
            Sha256::hash(b""),
            hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        );
    }

    #[test]
    fn nist_abc() {
        // FIPS 180-2 Appendix B example 1.
        assert_eq!(
            Sha256::hash(b"abc"),
            hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        );
    }

    #[test]
    fn nist_448_bit_message() {
        // FIPS 180-2 Appendix B example 2.
        assert_eq!(
            Sha256::hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex32("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        );
    }

    #[test]
    fn nist_896_bit_message() {
        // FIPS 180-2 Appendix B example 3.
        let input: &[u8] =
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(input.len(), 112);
        assert_eq!(
            Sha256::hash(input),
            hex32("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
        );
    }

    #[test]
    fn nist_one_million_as() {
        // NIST sample: one million ASCII 'a' bytes.
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            h.finalize(),
            hex32("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        );
    }

    // Streaming/buffering property tests across lengths covering all SHA-256 padding
    // boundaries (55/56, 64, 119/120).

    #[test]
    fn streaming_internal_consistency_lengths_0_through_200() {
        #[allow(clippy::cast_possible_truncation)]
        let pattern: [u8; 200] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(7));
        for len in 0..=pattern.len() {
            let input = &pattern[..len];
            let oneshot = Sha256::hash(input);

            let mut h = Sha256::new();
            for &b in input {
                h.update(&[b]);
            }
            assert_eq!(h.finalize(), oneshot, "byte-by-byte at len={len} differs");

            for split in 0..=len {
                let mut h = Sha256::new();
                h.update(&input[..split]);
                h.update(&input[split..]);
                assert_eq!(
                    h.finalize(),
                    oneshot,
                    "split at offset {split} of len {len} differs",
                );
            }
        }
    }

    #[test]
    fn streaming_matches_oneshot_for_every_split() {
        let data = b"The quick brown fox jumps over the lazy dog. \
                     Sphinx of black quartz, judge my vow. \
                     Pack my box with five dozen liquor jugs.";
        let oneshot = Sha256::hash(data);

        for split in 0..=data.len() {
            let (left, right) = data.split_at(split);
            let mut h = Sha256::new();
            h.update(left);
            h.update(right);
            assert_eq!(
                h.finalize(),
                oneshot,
                "streaming split at offset {split} differs from one-shot",
            );
        }
    }

    #[test]
    fn streaming_many_small_updates() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = Sha256::hash(data);
        let mut h = Sha256::new();
        for &b in data {
            h.update(&[b]);
        }
        assert_eq!(h.finalize(), oneshot);
    }

    #[test]
    fn quick_brown_fox() {
        assert_eq!(
            Sha256::hash(b"The quick brown fox jumps over the lazy dog"),
            hex32("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
        );
        assert_eq!(
            Sha256::hash(b"The quick brown fox jumps over the lazy dog."),
            hex32("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"),
        );
    }
}

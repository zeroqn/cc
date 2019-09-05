use ophelia_hasher::{HashValue, Hasher};

use std::convert::TryFrom;

pub struct Blake2b {
    params: blake2b_simd::Params,
}

impl Blake2b {
    pub fn new(key: &[u8]) -> Self {
        let mut params = blake2b_simd::Params::new();
        params.hash_length(HashValue::LENGTH);
        params.key(key);

        Blake2b { params }
    }
}

impl Hasher for Blake2b {
    fn digest(&self, data: &[u8]) -> HashValue {
        let hash = self.params.hash(data);
        let bytes_slice = hash.as_bytes();

        assert_eq!(bytes_slice.len(), HashValue::LENGTH);

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_slice[..HashValue::LENGTH]);

        HashValue::from_bytes_unchecked(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Blake2b;

    use ophelia_hasher::{HashValue, Hasher};

    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn prop_blake2b_bytes(key: String, msg: String) -> TestResult {
        if key.len() > blake2b_simd::KEYBYTES {
            return TestResult::discard();
        }

        let expect_hash = blake2b_simd::Params::new()
            .hash_length(HashValue::LENGTH)
            .key(&key.as_bytes())
            .hash(msg.as_bytes());

        let bytes = Blake2b::new(key.as_bytes())
            .digest(msg.as_bytes())
            .to_bytes();

        TestResult::from_bool(bytes == expect_hash.as_bytes())
    }
}

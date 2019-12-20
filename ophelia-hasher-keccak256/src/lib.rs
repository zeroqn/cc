use ophelia_hasher::HashValue;

pub struct Keccak256;

impl ophelia_hasher::Hasher for Keccak256 {
    fn digest(&self, data: &[u8]) -> HashValue {
        use tiny_keccak::Hasher;

        let mut bytes = [0u8; HashValue::LENGTH];
        let mut keccak = tiny_keccak::Keccak::v256();

        keccak.update(data);
        keccak.finalize(&mut bytes);

        assert_eq!(bytes.len(), HashValue::LENGTH);

        HashValue::from_bytes_unchecked(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Keccak256;

    use ophelia_hasher::Hasher;

    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn prop_keccak256_bytes(msg: String) -> bool {
        use tiny_keccak::Hasher;

        let mut bytes = [0u8; 32];
        let mut keccak = tiny_keccak::Keccak::v256();

        keccak.update(msg.as_bytes());
        keccak.finalize(&mut bytes);

        Keccak256.digest(msg.as_bytes()).to_bytes() == bytes
    }
}

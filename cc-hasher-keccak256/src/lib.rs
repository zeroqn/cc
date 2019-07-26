use cc_hasher::{HashValue, Hasher};

pub struct Keccak256;

impl Hasher for Keccak256 {
    fn digest(&self, data: &[u8]) -> HashValue {
        let bytes = tiny_keccak::keccak256(data);

        HashValue::from_bytes_unchecked(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Keccak256;

    use cc_hasher::Hasher;

    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn prop_keccak256_bytes(msg: String) -> bool {
        Keccak256.digest(msg.as_bytes()).to_bytes() == tiny_keccak::keccak256(msg.as_bytes())
    }
}

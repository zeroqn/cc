use ophelia_hasher::{HashValue, Hasher};

use libsm::sm3::hash::Sm3Hash;

pub struct Sm3;

impl Hasher for Sm3 {
    fn digest(&self, data: &[u8]) -> HashValue {
        let bytes = Sm3Hash::new(data).get_hash();

        assert_eq!(bytes.len(), HashValue::LENGTH);

        HashValue::from_bytes_unchecked(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Sm3;

    use libsm::sm3::hash::Sm3Hash;

    use ophelia_hasher::Hasher;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn prop_sm3_bytes(msg: String) -> bool {
        Sm3.digest(msg.as_bytes()).to_bytes() == Sm3Hash::new(msg.as_bytes()).get_hash()
    }
}

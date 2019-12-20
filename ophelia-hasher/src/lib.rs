use std::{convert::TryFrom, error::Error};

use derive_more::Display;

pub const HASH_VALUE_LENGTH: usize = 32;

#[derive(Debug, Display)]
#[display(fmt = "wrong length: expect {}, got {}", expect, got)]
pub struct WrongLengthError {
    expect: usize,
    got: usize,
}

impl Error for WrongLengthError {}

pub trait Hasher {
    fn digest(&self, data: &[u8]) -> HashValue;
}

#[derive(Clone, Debug, PartialEq)]
pub struct HashValue([u8; HASH_VALUE_LENGTH]);

impl HashValue {
    pub const LENGTH: usize = HASH_VALUE_LENGTH;

    pub fn from_bytes_unchecked(bytes: [u8; HASH_VALUE_LENGTH]) -> Self {
        HashValue(bytes)
    }

    pub fn to_bytes(&self) -> [u8; HASH_VALUE_LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for HashValue {
    type Error = WrongLengthError;

    fn try_from(bytes: &[u8]) -> Result<HashValue, Self::Error> {
        if bytes.len() != HASH_VALUE_LENGTH {
            return Err(WrongLengthError {
                expect: HASH_VALUE_LENGTH,
                got: bytes.len(),
            });
        }

        let mut hash_bytes = [0u8; HASH_VALUE_LENGTH];
        hash_bytes.copy_from_slice(&bytes[..HASH_VALUE_LENGTH]);

        Ok(HashValue(hash_bytes))
    }
}

impl AsRef<[u8]> for HashValue {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::HashValue;

    use quickcheck_macros::quickcheck;

    use std::convert::TryFrom;

    impl quickcheck::Arbitrary for HashValue {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> HashValue {
            let mut hash = [0u8; 32];

            for byte in &mut hash {
                *byte = u8::arbitrary(g);
            }

            HashValue(hash)
        }
    }

    #[quickcheck]
    fn prop_hash_bytes(hash: HashValue) {
        assert!(HashValue::try_from(hash.as_ref()).is_ok());
    }
}

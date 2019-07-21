use crate::CryptoError;

use std::convert::TryFrom;

pub const LENGTH: usize = 32;

#[derive(Clone, Debug)]
pub struct Hash([u8; LENGTH]);

impl Hash {
    pub fn to_bytes(&self) -> [u8; LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Hash, Self::Error> {
        if bytes.len() != LENGTH {
            return Err(CryptoError::InvalidLength);
        }

        let mut hash_bytes = [0u8; LENGTH];
        hash_bytes.copy_from_slice(&bytes[..LENGTH]);

        Ok(Hash(hash_bytes))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

#[cfg(test)]
// TODO: SeedableRng
impl Arbitrary for Hash {
    fn arbitrary<G: Gen>(g: &mut G) -> Hash {
        let mut hash = [0u8; 32];

        for byte in &mut hash {
            *byte = u8::arbitrary(g);
        }

        Hash(hash)
    }
}

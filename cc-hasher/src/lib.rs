use std::convert::TryFrom;

pub const LENGTH: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct HashValue([u8; LENGTH]);

#[derive(Clone, PartialEq, Debug)]
pub struct InvalidLengthError;

pub trait Hasher {
    fn digest(&self, data: &[u8]) -> HashValue;
}

impl HashValue {
    pub fn to_bytes(&self) -> [u8; LENGTH] {
        self.0
    }
}

impl TryFrom<&[u8]> for HashValue {
    type Error = InvalidLengthError;

    fn try_from(bytes: &[u8]) -> Result<HashValue, Self::Error> {
        if bytes.len() != LENGTH {
            return Err(InvalidLengthError);
        }

        let mut hash_bytes = [0u8; LENGTH];
        hash_bytes.copy_from_slice(&bytes[..LENGTH]);

        Ok(HashValue(hash_bytes))
    }
}

impl AsRef<[u8]> for HashValue {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(any(test, feature = "proptest"))]
impl quickcheck::Arbitrary for HashValue {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> HashValue {
        let mut hash = [0u8; 32];

        for byte in &mut hash {
            *byte = u8::arbitrary(g);
        }

        HashValue(hash)
    }
}

impl InvalidLengthError {
    fn as_str(&self) -> &str {
        "hash value: invalid length"
    }
}

impl std::fmt::Display for InvalidLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for InvalidLengthError {
    fn description(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::HashValue;

    use quickcheck_macros::quickcheck;

    use std::convert::TryFrom;

    #[quickcheck]
    fn prop_hash_bytes(hash: HashValue) {
        assert!(HashValue::try_from(hash.as_ref()).is_ok());
    }
}

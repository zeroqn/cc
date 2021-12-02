use ophelia_hasher::HashValue;

use quickcheck::{Arbitrary, Gen};

#[macro_export]
macro_rules! impl_quickcheck_for_privatekey {
    ($priv_key:ident) => {
        impl quickcheck::Arbitrary for $priv_key {
            fn arbitrary(g: &mut quickcheck::Gen) -> $priv_key {
                let octet32 = ophelia_quickcheck::Octet32::arbitrary(g);

                $priv_key::try_from(octet32.as_ref()).unwrap()
            }
        }
    };
}

// TODO: SeedableRng?
#[derive(Clone, Debug)]
pub struct Octet32([u8; 32]);

impl AsRef<[u8]> for Octet32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Arbitrary for Octet32 {
    fn arbitrary(g: &mut Gen) -> Octet32 {
        let mut octet32 = [0u8; 32];

        for octet in &mut octet32 {
            *octet = u8::arbitrary(g);
        }

        Octet32(octet32)
    }
}

#[derive(Clone, Debug)]
pub struct AHashValue(HashValue);

impl AHashValue {
    pub fn into_inner(self) -> HashValue {
        self.0
    }
}

impl quickcheck::Arbitrary for AHashValue {
    fn arbitrary(g: &mut quickcheck::Gen) -> AHashValue {
        let mut hash = [0u8; 32];

        for byte in &mut hash {
            *byte = u8::arbitrary(g);
        }

        AHashValue(HashValue::from_bytes_unchecked(hash))
    }
}

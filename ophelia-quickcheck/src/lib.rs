use quickcheck::{Arbitrary, Gen};

// TODO: SeedableRng?
#[derive(Clone, Debug)]
pub struct Octet32([u8; 32]);

impl AsRef<[u8]> for Octet32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Arbitrary for Octet32 {
    fn arbitrary<G: Gen>(g: &mut G) -> Octet32 {
        let mut octet32 = [0u8; 32];

        for octet in &mut octet32 {
            *octet = u8::arbitrary(g);
        }

        Octet32(octet32)
    }
}

#[macro_export]
macro_rules! impl_quickcheck_for_privatekey {
    ($priv_key:ident) => {
        impl quickcheck::Arbitrary for $priv_key {
            fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> $priv_key {
                let octet32 = ophelia_quickcheck::Octet32::arbitrary(g);

                $priv_key::try_from(octet32.as_ref()).unwrap()
            }
        }
    };
}

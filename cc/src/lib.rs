#![feature(const_generics)]

pub mod hash;
pub use hash::HashValue;

use std::convert::TryFrom;

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidLength,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    Other(&'static str),
}

pub trait PrivateKey<const LENGTH: usize>: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type PublicKey;
    type Signature;

    fn sign_message(&self, msg: &HashValue) -> Self::Signature;

    fn pub_key(&self) -> Self::PublicKey;

    fn to_bytes(&self) -> [u8; LENGTH];
}

pub trait PublicKey<const LENGTH: usize, const SIG: usize>:
    for<'a> TryFrom<&'a [u8], Error = CryptoError>
{
    type Signature: Signature<{ SIG }, { LENGTH }, PublicKey = Self>;

    fn verify_signature(&self, msg: &HashValue, sig: &Self::Signature) -> Result<(), CryptoError>;

    fn to_bytes(&self) -> [u8; LENGTH];
}

pub trait Signature<const LENGTH: usize, const PK: usize>:
    for<'a> TryFrom<&'a [u8], Error = CryptoError>
{
    type PublicKey: PublicKey<{ PK }, { LENGTH }, Signature = Self>;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), CryptoError>;

    fn to_bytes(&self) -> [u8; LENGTH];
}

pub trait Crypto<const SK: usize, const PK: usize, const SIG: usize> {
    type PrivateKey: PrivateKey<{ SK }>;
    type PublicKey: PublicKey<{ PK }, { SIG }, Signature = Self::Signature>;
    type Signature: Signature<{ SIG }, { PK }, PublicKey = Self::PublicKey>;

    fn verify_signature(msg: &[u8], sig: &[u8], pub_key: &[u8]) -> Result<(), CryptoError> {
        let msg = HashValue::try_from(msg)?;
        let sig = Self::Signature::try_from(sig)?;
        let pub_key = Self::PublicKey::try_from(pub_key)?;

        sig.verify(&msg, &pub_key)?;
        Ok(())
    }
}

#[cfg(feature = "proptest")]
pub use cc_quickcheck_types::Octet32;

#[cfg(feature = "proptest")]
#[macro_export]
macro_rules! impl_quickcheck_arbitrary {
    ($priv_key:ident) => {
        impl Clone for $priv_key {
            fn clone(&self) -> Self {
                Self::try_from(self.to_bytes().as_ref()).unwrap()
            }
        }

        impl quickcheck::Arbitrary for $priv_key {
            fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> $priv_key {
                let octet32 = cc::Octet32::arbitrary(g);

                $priv_key::try_from(octet32.as_ref()).unwrap()
            }
        }
    };
}

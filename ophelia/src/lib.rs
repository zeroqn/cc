pub mod threshold;

pub use bytes::Bytes;
pub use ophelia_hasher::{HashValue, Hasher};

#[cfg(feature = "generate")]
use rand::{CryptoRng, Rng};

use std::convert::TryFrom;

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidLength,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    Other(&'static str),
}

#[cfg(feature = "generate")]
pub trait KeyGenerator {
    type Output;

    fn generate<R: CryptoRng + Rng + ?Sized>(rng: &mut R) -> Self::Output;
}

pub trait PrivateKey: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type PublicKey;
    type Signature;

    fn sign_message(&self, msg: &HashValue) -> Self::Signature;

    fn pub_key(&self) -> Self::PublicKey;

    fn to_bytes(&self) -> Bytes;
}

pub trait PublicKey: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type Signature;

    fn to_bytes(&self) -> Bytes;
}

// TODO: move verify to PublicKey trait
pub trait Signature: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type PublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), CryptoError>;

    fn to_bytes(&self) -> Bytes;
}

pub trait Crypto {
    #[cfg(feature = "generate")]
    type KeyGenerator: KeyGenerator<Output = Self::PrivateKey>;
    type PrivateKey: PrivateKey<PublicKey = Self::PublicKey, Signature = Self::Signature>;
    type PublicKey: PublicKey<Signature = Self::Signature>;
    type Signature: Signature<PublicKey = Self::PublicKey>;

    #[cfg(feature = "generate")]
    fn generate_keypair<R: CryptoRng + Rng + ?Sized>(
        mut rng: &mut R,
    ) -> (Self::PrivateKey, Self::PublicKey) {
        let priv_key = Self::KeyGenerator::generate(&mut rng);
        let pub_key = priv_key.pub_key();

        (priv_key, pub_key)
    }

    fn pub_key(priv_key: &[u8]) -> Result<Self::PublicKey, CryptoError> {
        let priv_key = Self::PrivateKey::try_from(priv_key)?;

        Ok(priv_key.pub_key())
    }

    fn sign_message(msg: &[u8], priv_key: &[u8]) -> Result<Self::Signature, CryptoError> {
        let priv_key = Self::PrivateKey::try_from(priv_key)?;
        let msg = HashValue::try_from(msg)?;

        Ok(priv_key.sign_message(&msg))
    }

    fn verify_signature(msg: &[u8], sig: &[u8], pub_key: &[u8]) -> Result<(), CryptoError> {
        let msg = HashValue::try_from(msg)?;
        let sig = Self::Signature::try_from(sig)?;
        let pub_key = Self::PublicKey::try_from(pub_key)?;

        sig.verify(&msg, &pub_key)?;
        Ok(())
    }
}

impl From<ophelia_hasher::InvalidLengthError> for CryptoError {
    fn from(_: ophelia_hasher::InvalidLengthError) -> CryptoError {
        CryptoError::InvalidLength
    }
}

#[cfg(feature = "proptest")]
pub use ophelia_quickcheck_types::Octet32;

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
                let octet32 = ophelia::Octet32::arbitrary(g);

                $priv_key::try_from(octet32.as_ref()).unwrap()
            }
        }
    };
}

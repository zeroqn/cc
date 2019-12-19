pub mod error;
pub mod threshold;
pub use error::{CryptoError, CryptoKind};

pub use bytes::Bytes;
pub use ophelia_hasher::{HashValue, Hasher};

use std::convert::TryFrom;

pub trait PrivateKey: for<'a> TryFrom<&'a [u8], Error = CryptoError> + Clone {
    type PublicKey;
    type Signature;

    const LENGTH: usize;

    fn sign_message(&self, msg: &HashValue) -> Self::Signature;

    fn pub_key(&self) -> Self::PublicKey;

    fn to_bytes(&self) -> Bytes;
}

pub trait PublicKey: for<'a> TryFrom<&'a [u8], Error = CryptoError> + Clone {
    type Signature;

    const LENGTH: usize;

    fn to_bytes(&self) -> Bytes;
}

pub trait Signature: for<'a> TryFrom<&'a [u8], Error = CryptoError> + Clone {
    type PublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), CryptoError>;

    fn to_bytes(&self) -> Bytes;
}

pub trait Crypto {
    type PrivateKey: PrivateKey<PublicKey = Self::PublicKey, Signature = Self::Signature>;
    type PublicKey: PublicKey<Signature = Self::Signature>;
    type Signature: Signature<PublicKey = Self::PublicKey>;

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

#[cfg(feature = "proptest")]
pub use ophelia_quickcheck_types::Octet32;

#[cfg(feature = "proptest")]
#[macro_export]
macro_rules! impl_quickcheck_arbitrary {
    ($priv_key:ident) => {
        impl quickcheck::Arbitrary for $priv_key {
            fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> $priv_key {
                let octet32 = ophelia::Octet32::arbitrary(g);

                $priv_key::try_from(octet32.as_ref()).unwrap()
            }
        }
    };
}

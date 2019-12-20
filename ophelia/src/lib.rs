pub use anyhow::Error;
pub use bytes::{Buf, BufMut, Bytes, BytesMut};
pub use ophelia_hasher::{HashValue, Hasher};
pub use rand_core::{CryptoRng, RngCore};

use std::convert::TryFrom;

pub trait PrivateKey: for<'a> TryFrom<&'a [u8], Error = Error> + Clone {
    type Signature;

    const LENGTH: usize;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self;

    fn sign_message(&self, msg: &HashValue) -> Self::Signature;

    fn to_bytes(&self) -> Bytes;
}

pub trait ToPublicKey {
    type PublicKey;

    fn pub_key(&self) -> Self::PublicKey;
}

pub trait ToBlsPublicKey {
    type PublicKey;
    type CommonReference;

    fn pub_key(&self, cr: &Self::CommonReference) -> Self::PublicKey;
}

pub trait PublicKey: for<'a> TryFrom<&'a [u8], Error = Error> + Clone {
    type Signature;

    const LENGTH: usize;

    fn to_bytes(&self) -> Bytes;
}

pub trait Signature: for<'a> TryFrom<&'a [u8], Error = Error> + Clone {
    type PublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), Error>;

    fn to_bytes(&self) -> Bytes;
}

pub trait Crypto {
    type PrivateKey: PrivateKey<Signature = Self::Signature>
        + ToPublicKey<PublicKey = Self::PublicKey>;
    type PublicKey: PublicKey<Signature = Self::Signature>;
    type Signature: Signature<PublicKey = Self::PublicKey>;

    fn pub_key(priv_key: &[u8]) -> Result<Self::PublicKey, Error> {
        let priv_key = Self::PrivateKey::try_from(priv_key)?;

        Ok(priv_key.pub_key())
    }

    fn sign_message(msg: &[u8], priv_key: &[u8]) -> Result<Self::Signature, Error> {
        let priv_key = Self::PrivateKey::try_from(priv_key)?;
        let msg = HashValue::try_from(msg)?;

        Ok(priv_key.sign_message(&msg))
    }

    fn verify_signature(msg: &[u8], sig: &[u8], pub_key: &[u8]) -> Result<(), Error> {
        let msg = HashValue::try_from(msg)?;
        let sig = Self::Signature::try_from(sig)?;
        let pub_key = Self::PublicKey::try_from(pub_key)?;

        sig.verify(&msg, &pub_key)?;
        Ok(())
    }
}

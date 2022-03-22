pub use secp256k1;

use ophelia::{Bytes, BytesMut, Error};
use ophelia::{
    Crypto, HashValue, PrivateKey, PublicKey, Signature, SignatureVerify, ToPublicKey,
    UncompressedPublicKey,
};
use ophelia::{CryptoRng, RngCore};
use ophelia_derive::SecretDebug;

use lazy_static::lazy_static;
use secp256k1::{
    constants::{PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE},
    ecdsa::{self, RecoverableSignature, RecoveryId},
    All, Message, ThirtyTwoByteHash,
};

use std::convert::TryFrom;

lazy_static! {
    static ref ENGINE: secp256k1::Secp256k1<All> = secp256k1::Secp256k1::new();
}

pub struct Secp256k1;

impl Crypto for Secp256k1 {
    type PrivateKey = Secp256k1PrivateKey;
    type PublicKey = Secp256k1PublicKey;
    type Signature = Secp256k1Signature;
}

#[derive(SecretDebug, PartialEq, Clone)]
pub struct Secp256k1PrivateKey(secp256k1::SecretKey);

impl TryFrom<&[u8]> for Secp256k1PrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1PrivateKey, Self::Error> {
        let secret_key = secp256k1::SecretKey::from_slice(bytes)?;

        Ok(Secp256k1PrivateKey(secret_key))
    }
}

impl PrivateKey for Secp256k1PrivateKey {
    type Signature = Secp256k1Signature;

    const LENGTH: usize = SECRET_KEY_SIZE;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = [0u8; SECRET_KEY_SIZE];
        rng.fill_bytes(&mut key);

        let new_key = secp256k1::SecretKey::from_slice(key.as_ref()).expect("impossible fail");

        Secp256k1PrivateKey(new_key)
    }

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        let msg = Message::from(HashedMessage(msg));
        let sig = ENGINE.sign_ecdsa(&msg, &self.0);

        Secp256k1Signature(sig)
    }

    fn to_bytes(&self) -> Bytes {
        BytesMut::from(&self.0[..]).freeze()
    }
}

impl ToPublicKey for Secp256k1PrivateKey {
    type PublicKey = Secp256k1PublicKey;

    fn pub_key(&self) -> Self::PublicKey {
        let pub_key = secp256k1::PublicKey::from_secret_key(&ENGINE, &self.0);

        Secp256k1PublicKey(pub_key)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Secp256k1PublicKey(secp256k1::PublicKey);

impl TryFrom<&[u8]> for Secp256k1PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1PublicKey, Self::Error> {
        let pub_key = secp256k1::PublicKey::from_slice(bytes)?;

        Ok(Secp256k1PublicKey(pub_key))
    }
}

impl PublicKey for Secp256k1PublicKey {
    type Signature = Secp256k1Signature;

    const LENGTH: usize = PUBLIC_KEY_SIZE;

    fn to_bytes(&self) -> Bytes {
        BytesMut::from(self.0.serialize().as_ref()).freeze()
    }
}

impl UncompressedPublicKey for Secp256k1PublicKey {
    type Signature = Secp256k1Signature;

    const LENGTH: usize = UNCOMPRESSED_PUBLIC_KEY_SIZE;

    fn to_uncompressed_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.0.serialize_uncompressed())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Secp256k1Signature(ecdsa::Signature);

impl TryFrom<&[u8]> for Secp256k1Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1Signature, Self::Error> {
        let sig = ecdsa::Signature::from_compact(bytes)?;

        Ok(Secp256k1Signature(sig))
    }
}

impl Signature for Secp256k1Signature {
    fn to_bytes(&self) -> Bytes {
        BytesMut::from(self.0.serialize_compact().as_ref()).freeze()
    }
}

impl SignatureVerify for Secp256k1Signature {
    type PublicKey = Secp256k1PublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), Error> {
        let msg = Message::from(HashedMessage(msg));

        Ok(ENGINE.verify_ecdsa(&msg, &self.0, &pub_key.0)?)
    }
}

// ********************************
// Impl recoverable secp256k1 below
// ********************************

pub struct Secp256k1Recoverable;

impl Crypto for Secp256k1Recoverable {
    type PrivateKey = Secp256k1RecoverablePrivateKey;
    type PublicKey = Secp256k1RecoverablePublicKey;
    type Signature = Secp256k1RecoverableSignature;
}

#[derive(SecretDebug, PartialEq, Clone)]
pub struct Secp256k1RecoverablePrivateKey(secp256k1::SecretKey);

impl TryFrom<&[u8]> for Secp256k1RecoverablePrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1RecoverablePrivateKey, Self::Error> {
        let secret_key = secp256k1::SecretKey::from_slice(bytes)?;

        Ok(Secp256k1RecoverablePrivateKey(secret_key))
    }
}

impl PrivateKey for Secp256k1RecoverablePrivateKey {
    type Signature = Secp256k1RecoverableSignature;

    const LENGTH: usize = SECRET_KEY_SIZE;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = [0u8; SECRET_KEY_SIZE];
        rng.fill_bytes(&mut key);

        let new_key = secp256k1::SecretKey::from_slice(key.as_ref()).expect("impossible fail");

        Secp256k1RecoverablePrivateKey(new_key)
    }

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        let msg = Message::from(HashedMessage(msg));
        let sig = ENGINE.sign_ecdsa_recoverable(&msg, &self.0);

        Secp256k1RecoverableSignature(sig)
    }

    fn to_bytes(&self) -> Bytes {
        BytesMut::from(&self.0[..]).freeze()
    }
}

impl ToPublicKey for Secp256k1RecoverablePrivateKey {
    type PublicKey = Secp256k1RecoverablePublicKey;

    fn pub_key(&self) -> Self::PublicKey {
        let pub_key = secp256k1::PublicKey::from_secret_key(&ENGINE, &self.0);

        Secp256k1RecoverablePublicKey(pub_key)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Secp256k1RecoverablePublicKey(secp256k1::PublicKey);

impl TryFrom<&[u8]> for Secp256k1RecoverablePublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1RecoverablePublicKey, Self::Error> {
        let pub_key = secp256k1::PublicKey::from_slice(bytes)?;

        Ok(Secp256k1RecoverablePublicKey(pub_key))
    }
}

impl PublicKey for Secp256k1RecoverablePublicKey {
    type Signature = Secp256k1RecoverableSignature;

    const LENGTH: usize = PUBLIC_KEY_SIZE;

    fn to_bytes(&self) -> Bytes {
        BytesMut::from(self.0.serialize().as_ref()).freeze()
    }
}

impl UncompressedPublicKey for Secp256k1RecoverablePublicKey {
    type Signature = Secp256k1Signature;

    const LENGTH: usize = UNCOMPRESSED_PUBLIC_KEY_SIZE;

    fn to_uncompressed_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.0.serialize_uncompressed())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Secp256k1RecoverableSignature(RecoverableSignature);

impl TryFrom<&[u8]> for Secp256k1RecoverableSignature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1RecoverableSignature, Self::Error> {
        debug_assert!(bytes.len() == 65);
        let sig = RecoverableSignature::from_compact(
            &bytes[0..64],
            RecoveryId::from_i32(*bytes.last().unwrap() as i32)?,
        )?;

        Ok(Secp256k1RecoverableSignature(sig))
    }
}

impl Signature for Secp256k1RecoverableSignature {
    fn to_bytes(&self) -> Bytes {
        let (recid, bytes) = self.0.serialize_compact();
        let mut ret = BytesMut::from(bytes.as_ref());
        ret.extend_from_slice(&[recid.to_i32() as u8]);
        ret.freeze()
    }
}

impl SignatureVerify for Secp256k1RecoverableSignature {
    type PublicKey = Secp256k1RecoverablePublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), Error> {
        let msg = Message::from(HashedMessage(msg));
        let recover_pk = ENGINE.recover_ecdsa(&msg, &self.0)?;

        if recover_pk == pub_key.0 {
            Ok(())
        } else {
            Err(secp256k1::Error::InvalidSignature.into())
        }
    }
}

pub struct HashedMessage<'a>(&'a HashValue);

impl<'a> HashedMessage<'a> {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl<'a> ThirtyTwoByteHash for HashedMessage<'a> {
    fn into_32(self) -> [u8; 32] {
        self.to_bytes()
    }
}

pub fn recover(msg: &[u8], sig: &[u8]) -> Result<secp256k1::PublicKey, Error> {
    let msg = Message::from(HashedMessage(&HashValue::try_from(msg)?));
    let sig = Secp256k1RecoverableSignature::try_from(sig)?;
    let ret = ENGINE.recover_ecdsa(&msg, &sig.0)?;
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::{
        Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1RecoverablePrivateKey,
        Secp256k1RecoverableSignature, Secp256k1Signature,
    };

    use ophelia::{PrivateKey, PublicKey, Signature, SignatureVerify, ToPublicKey};
    use ophelia_quickcheck::{impl_quickcheck_for_privatekey, AHashValue};
    use quickcheck_macros::quickcheck;
    use rand::rngs::OsRng;

    use std::convert::TryFrom;

    impl_quickcheck_for_privatekey!(Secp256k1PrivateKey);
    impl_quickcheck_for_privatekey!(Secp256k1RecoverablePrivateKey);

    #[quickcheck]
    fn should_generate_workable_key(msg: AHashValue) -> bool {
        let msg = msg.into_inner();
        let priv_key = Secp256k1PrivateKey::generate(&mut OsRng);
        let pub_key = priv_key.pub_key();

        let sig = priv_key.sign_message(&msg);
        sig.verify(&msg, &pub_key).is_ok()
    }

    #[quickcheck]
    fn prop_private_key_bytes_serialization(priv_key: Secp256k1PrivateKey) -> bool {
        match Secp256k1PrivateKey::try_from(priv_key.to_bytes().as_ref()) {
            Ok(seckey) => seckey == priv_key,
            Err(_) => false,
        }
    }

    #[quickcheck]
    fn prop_public_key_bytes_serialization(priv_key: Secp256k1PrivateKey) -> bool {
        let pub_key = priv_key.pub_key();

        match Secp256k1PublicKey::try_from(pub_key.to_bytes().as_ref()) {
            Ok(pubkey) => pubkey == pub_key,
            Err(_) => false,
        }
    }

    #[quickcheck]
    fn prop_signature_bytes_serialization(msg: AHashValue, priv_key: Secp256k1PrivateKey) -> bool {
        let sig = priv_key.sign_message(&msg.into_inner());

        match Secp256k1Signature::try_from(sig.to_bytes().as_ref()) {
            Ok(s) => s == sig,
            Err(_) => false,
        }
    }

    #[quickcheck]
    fn prop_recoverable_signature_bytes_serialization(
        msg: AHashValue,
        priv_key: Secp256k1RecoverablePrivateKey,
    ) -> bool {
        let sig = priv_key.sign_message(&msg.into_inner());

        match Secp256k1RecoverableSignature::try_from(sig.to_bytes().as_ref()) {
            Ok(s) => s == sig,
            Err(_) => false,
        }
    }

    #[quickcheck]
    fn prop_message_sign_and_verify(msg: AHashValue, priv_key: Secp256k1PrivateKey) -> bool {
        let msg = msg.into_inner();
        let pub_key = priv_key.pub_key();
        let sig = priv_key.sign_message(&msg);

        sig.verify(&msg, &pub_key).is_ok()
    }

    #[quickcheck]
    fn prop_recoverable_message_sign_and_verify(
        msg: AHashValue,
        priv_key: Secp256k1RecoverablePrivateKey,
    ) -> bool {
        let msg = msg.into_inner();
        let pub_key = priv_key.pub_key();
        let sig = priv_key.sign_message(&msg);

        sig.verify(&msg, &pub_key).is_ok()
    }
}

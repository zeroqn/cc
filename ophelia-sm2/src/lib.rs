use ophelia::{Bytes, Error};
use ophelia::{Crypto, HashValue, PrivateKey, PublicKey, Signature, SignatureVerify, ToPublicKey};
use ophelia::{CryptoRng, RngCore};
use ophelia_derive::SecretDebug;

use lazy_static::lazy_static;
use libsm::sm2::signature::{self as sm2, SigCtx};

use std::convert::TryFrom;

lazy_static! {
    static ref SM2_CONTEXT: SigCtx = SigCtx::new();
}

#[derive(thiserror::Error, Debug)]
enum InternalError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("invalid signature")]
    InvalidSignature,
}

pub struct Sm2;

impl Crypto for Sm2 {
    type PrivateKey = SM2PrivateKey;
    type PublicKey = SM2PublicKey;
    type Signature = SM2Signature;
}

#[derive(SecretDebug, PartialEq, Clone)]
pub struct SM2PrivateKey(sm2::Seckey);

impl TryFrom<&[u8]> for SM2PrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<SM2PrivateKey, Self::Error> {
        let secret_key = SM2_CONTEXT
            .load_seckey(bytes)
            .map_err(|_| InternalError::InvalidPrivateKey)?;

        Ok(SM2PrivateKey(secret_key))
    }
}

impl PrivateKey for SM2PrivateKey {
    type Signature = SM2Signature;

    const LENGTH: usize = 32;

    fn generate<R: RngCore + CryptoRng>(_: &mut R) -> Self {
        let (_pub_key, secret_key) = SM2_CONTEXT.new_keypair();

        SM2PrivateKey(secret_key)
    }

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        let sig = SM2_CONTEXT.sign_raw(msg.as_ref(), &self.0);

        SM2Signature(sig)
    }

    fn to_bytes(&self) -> Bytes {
        let vec_bytes = SM2_CONTEXT.serialize_seckey(&self.0);
        assert_eq!(vec_bytes.len(), Self::LENGTH);

        vec_bytes.into()
    }
}

impl ToPublicKey for SM2PrivateKey {
    type PublicKey = SM2PublicKey;

    fn pub_key(&self) -> Self::PublicKey {
        let pub_key = SM2_CONTEXT.pk_from_sk(&self.0);

        SM2PublicKey(pub_key)
    }
}

#[derive(Clone)]
pub struct SM2PublicKey(sm2::Pubkey);

impl TryFrom<&[u8]> for SM2PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<SM2PublicKey, Self::Error> {
        let pub_key = SM2_CONTEXT
            .load_pubkey(bytes)
            .map_err(|_| InternalError::InvalidPublicKey)?;

        Ok(SM2PublicKey(pub_key))
    }
}

impl PublicKey for SM2PublicKey {
    type Signature = SM2Signature;

    const LENGTH: usize = 33;

    fn to_bytes(&self) -> Bytes {
        let vec_bytes = SM2_CONTEXT.serialize_pubkey(&self.0, true);
        // true for compressed public key
        assert_eq!(vec_bytes.len(), Self::LENGTH);

        vec_bytes.into()
    }
}

pub struct SM2Signature(sm2::Signature);

impl TryFrom<&[u8]> for SM2Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<SM2Signature, Self::Error> {
        let sig = sm2::Signature::der_decode(bytes).map_err(|_| InternalError::InvalidSignature)?;

        Ok(SM2Signature(sig))
    }
}

impl Clone for SM2Signature {
    fn clone(&self) -> Self {
        let sig_r = self.0.get_r();
        let sig_s = self.0.get_s();

        let sig = sm2::Signature::new(&sig_r.to_bytes_be(), &sig_s.to_bytes_be());

        SM2Signature(sig)
    }
}

impl Signature for SM2Signature {
    fn to_bytes(&self) -> Bytes {
        self.0.der_encode().into()
    }
}

impl SignatureVerify for SM2Signature {
    type PublicKey = SM2PublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), Error> {
        if !SM2_CONTEXT.verify_raw(msg.as_ref(), &pub_key.0, &self.0) {
            return Err(InternalError::InvalidSignature)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SM2PrivateKey, SM2PublicKey, SM2Signature};

    use ophelia::{PrivateKey, PublicKey, Signature, SignatureVerify, ToPublicKey};
    use ophelia_quickcheck::{impl_quickcheck_for_privatekey, AHashValue};
    use quickcheck_macros::quickcheck;
    use rand::rngs::OsRng;

    use std::convert::TryFrom;

    impl_quickcheck_for_privatekey!(SM2PrivateKey);

    #[quickcheck]
    fn should_generate_workable_key(msg: AHashValue) -> bool {
        let msg = msg.into_inner();
        let priv_key = SM2PrivateKey::generate(&mut OsRng);
        let pub_key = priv_key.pub_key();

        let sig = priv_key.sign_message(&msg);
        sig.verify(&msg, &pub_key).is_ok()
    }

    #[quickcheck]
    fn prop_private_key_bytes_serialization(priv_key: SM2PrivateKey) -> bool {
        match SM2PrivateKey::try_from(priv_key.to_bytes().as_ref()) {
            Ok(seckey) => seckey == priv_key,
            Err(_) => false,
        }
    }

    #[quickcheck]
    fn prop_public_key_bytes_serialization(priv_key: SM2PrivateKey) -> bool {
        let pub_key = priv_key.pub_key();

        SM2PublicKey::try_from(pub_key.to_bytes().as_ref()).is_ok()
    }

    // FIXME: inconsistent signature serialized bytes
    #[quickcheck]
    fn prop_signature_bytes_serialization(msg: AHashValue, priv_key: SM2PrivateKey) -> bool {
        let sig = priv_key.sign_message(&msg.into_inner());

        SM2Signature::try_from(sig.to_bytes().as_ref()).is_ok()
    }

    #[quickcheck]
    fn prop_message_sign_and_verify(msg: AHashValue, priv_key: SM2PrivateKey) -> bool {
        let msg = msg.into_inner();
        let pub_key = priv_key.pub_key();
        let sig = priv_key.sign_message(&msg);

        sig.verify(&msg, &pub_key).is_ok()
    }
}

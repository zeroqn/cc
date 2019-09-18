use ophelia::{
    Bytes, Crypto, CryptoError, CryptoKind, HashValue, PrivateKey, PublicKey, Signature,
};
use ophelia_derive::SecretDebug;

#[cfg(feature = "generate")]
use rand::{CryptoRng, Rng};

use lazy_static::lazy_static;
use libsm::sm2::signature::{self as sm2, SigCtx};

use std::convert::TryFrom;

lazy_static! {
    static ref SM2_CONTEXT: SigCtx = SigCtx::new();
}

#[derive(SecretDebug, PartialEq)]
pub struct SM2PrivateKey(sm2::Seckey);

pub struct SM2PublicKey(sm2::Pubkey);

pub struct SM2Signature(sm2::Signature);

pub struct Sm2;

impl Crypto for Sm2 {
    #[cfg(feature = "generate")]
    type KeyGenerator = SM2PrivateKey;
    type PrivateKey = SM2PrivateKey;
    type PublicKey = SM2PublicKey;
    type Signature = SM2Signature;
}

#[cfg(any(test, feature = "generate"))]
pub fn generate_keypair() -> (SM2PrivateKey, SM2PublicKey) {
    let (public_key, secret_key) = SM2_CONTEXT.new_keypair();

    (SM2PrivateKey(secret_key), SM2PublicKey(public_key))
}

#[cfg(feature = "generate")]
impl ophelia::KeyGenerator for SM2PrivateKey {
    type Output = SM2PrivateKey;

    fn generate<R: CryptoRng + Rng + ?Sized>(_rng: &mut R) -> Self::Output {
        let (priv_key, _) = generate_keypair();

        priv_key
    }
}

//
// PrivateKey Impl
//

impl TryFrom<&[u8]> for SM2PrivateKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<SM2PrivateKey, Self::Error> {
        let secret_key = SM2_CONTEXT
            .load_seckey(bytes)
            .map_err(|_| CryptoKind::PrivateKey)?;

        Ok(SM2PrivateKey(secret_key))
    }
}

impl PrivateKey for SM2PrivateKey {
    type PublicKey = SM2PublicKey;
    type Signature = SM2Signature;

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        let sig = SM2_CONTEXT.sign_raw(msg.as_ref(), &self.0);

        SM2Signature(sig)
    }

    fn pub_key(&self) -> Self::PublicKey {
        let pub_key = SM2_CONTEXT.pk_from_sk(&self.0);

        SM2PublicKey(pub_key)
    }

    fn to_bytes(&self) -> Bytes {
        let vec_bytes = SM2_CONTEXT.serialize_seckey(&self.0);
        assert_eq!(vec_bytes.len(), 32);

        vec_bytes.into()
    }
}

//
// PublicKey Impl
//

impl TryFrom<&[u8]> for SM2PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<SM2PublicKey, Self::Error> {
        let pub_key = SM2_CONTEXT
            .load_pubkey(bytes)
            .map_err(|_| CryptoKind::PublicKey)?;

        Ok(SM2PublicKey(pub_key))
    }
}

impl PublicKey for SM2PublicKey {
    type Signature = SM2Signature;

    fn to_bytes(&self) -> Bytes {
        let vec_bytes = SM2_CONTEXT.serialize_pubkey(&self.0, true);
        // true for compressed public key
        assert_eq!(vec_bytes.len(), 33);

        vec_bytes.into()
    }
}

//
// Signature Impl
//

impl TryFrom<&[u8]> for SM2Signature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<SM2Signature, Self::Error> {
        let sig = sm2::Signature::der_decode(bytes).map_err(|_| CryptoKind::Signature)?;

        Ok(SM2Signature(sig))
    }
}

impl Signature for SM2Signature {
    type PublicKey = SM2PublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), CryptoError> {
        if !SM2_CONTEXT.verify_raw(msg.as_ref(), &pub_key.0, &self.0) {
            return Err(CryptoKind::Signature.into());
        }

        Ok(())
    }

    fn to_bytes(&self) -> Bytes {
        self.0.der_encode().into()
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_keypair, SM2PrivateKey, SM2PublicKey, SM2Signature};

    use ophelia::{impl_quickcheck_arbitrary, HashValue, PrivateKey, PublicKey, Signature};

    use quickcheck_macros::quickcheck;
    use sha2::{Digest, Sha256};

    use std::convert::TryFrom;

    impl_quickcheck_arbitrary!(SM2PrivateKey);

    #[test]
    fn should_generate_workable_keypair() {
        let (priv_key, pub_key) = generate_keypair();

        let msg = {
            let mut hasher = Sha256::new();
            hasher.input(b"you can(not) redo");
            HashValue::try_from(&hasher.result()[..32]).expect("msg")
        };

        let sig = priv_key.sign_message(&msg);
        assert!(sig.verify(&msg, &pub_key).is_ok());
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
    fn prop_signature_bytes_serialization(msg: HashValue, priv_key: SM2PrivateKey) -> bool {
        let sig = priv_key.sign_message(&msg);

        SM2Signature::try_from(sig.to_bytes().as_ref()).is_ok()
    }

    #[quickcheck]
    fn prop_message_sign_and_verify(msg: HashValue, priv_key: SM2PrivateKey) -> bool {
        let pub_key = priv_key.pub_key();
        let sig = priv_key.sign_message(&msg);

        sig.verify(&msg, &pub_key).is_ok()
    }
}

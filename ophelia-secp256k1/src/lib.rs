use ophelia::{
    Bytes, Crypto, CryptoError, CryptoKind, HashValue, PrivateKey, PublicKey, Signature,
};
use ophelia_derive::SecretDebug;

#[cfg(any(test, feature = "generate"))]
use rand::{CryptoRng, Rng};

use lazy_static::lazy_static;
use secp256k1::{All, Message, ThirtyTwoByteHash};

use std::convert::TryFrom;

lazy_static! {
    static ref ENGINE: secp256k1::Secp256k1<All> = secp256k1::Secp256k1::new();
}

#[derive(SecretDebug, PartialEq)]
pub struct Secp256k1PrivateKey(secp256k1::SecretKey);

#[derive(Debug, PartialEq)]
pub struct Secp256k1PublicKey(secp256k1::PublicKey);

#[derive(Debug, PartialEq)]
pub struct Secp256k1Signature(secp256k1::Signature);

#[derive(Debug, PartialEq)]
pub struct Secp256k1Error(secp256k1::Error);

pub struct HashedMessage<'a>(&'a HashValue);

pub struct Secp256k1;

impl Crypto for Secp256k1 {
    #[cfg(feature = "generate")]
    type KeyGenerator = Secp256k1PrivateKey;
    type PrivateKey = Secp256k1PrivateKey;
    type PublicKey = Secp256k1PublicKey;
    type Signature = Secp256k1Signature;
}

#[cfg(any(test, feature = "generate"))]
pub fn generate_keypair<R: CryptoRng + Rng + ?Sized>(
    rng: &mut R,
) -> (Secp256k1PrivateKey, Secp256k1PublicKey) {
    let (secret_key, public_key) = ENGINE.generate_keypair(rng);

    (
        Secp256k1PrivateKey(secret_key),
        Secp256k1PublicKey(public_key),
    )
}

#[cfg(feature = "generate")]
impl ophelia::KeyGenerator for Secp256k1PrivateKey {
    type Output = Secp256k1PrivateKey;

    fn generate<R: CryptoRng + Rng + ?Sized>(rng: &mut R) -> Self::Output {
        let (priv_key, _) = generate_keypair(rng);

        priv_key
    }
}

//
// PrivateKey Impl
//

impl TryFrom<&[u8]> for Secp256k1PrivateKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1PrivateKey, Self::Error> {
        let secret_key = secp256k1::SecretKey::from_slice(bytes).map_err(Secp256k1Error)?;

        Ok(Secp256k1PrivateKey(secret_key))
    }
}

impl PrivateKey for Secp256k1PrivateKey {
    type PublicKey = Secp256k1PublicKey;
    type Signature = Secp256k1Signature;

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        let msg = Message::from(HashedMessage(msg));
        let sig = ENGINE.sign(&msg, &self.0);

        Secp256k1Signature(sig)
    }

    fn pub_key(&self) -> Self::PublicKey {
        let pub_key = secp256k1::PublicKey::from_secret_key(&ENGINE, &self.0);

        Secp256k1PublicKey(pub_key)
    }

    fn to_bytes(&self) -> Bytes {
        let mut bytes = Bytes::with_capacity(32);
        bytes.extend_from_slice(&self.0[..]);

        bytes
    }
}

//
// PublicKey Impl
//

impl TryFrom<&[u8]> for Secp256k1PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1PublicKey, Self::Error> {
        let pub_key = secp256k1::PublicKey::from_slice(bytes).map_err(Secp256k1Error)?;

        Ok(Secp256k1PublicKey(pub_key))
    }
}

impl PublicKey for Secp256k1PublicKey {
    type Signature = Secp256k1Signature;

    fn to_bytes(&self) -> Bytes {
        self.0.serialize().as_ref().into()
    }
}

//
// Signature Impl
//

impl TryFrom<&[u8]> for Secp256k1Signature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1Signature, Self::Error> {
        let sig = secp256k1::Signature::from_compact(bytes).map_err(Secp256k1Error)?;

        Ok(Secp256k1Signature(sig))
    }
}

impl Signature for Secp256k1Signature {
    type PublicKey = Secp256k1PublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), CryptoError> {
        let msg = Message::from(HashedMessage(msg));

        ENGINE
            .verify(&msg, &self.0, &pub_key.0)
            .map_err(Secp256k1Error)?;

        Ok(())
    }

    fn to_bytes(&self) -> Bytes {
        self.0.serialize_compact().as_ref().into()
    }
}

//
// Error Impl
//

impl From<Secp256k1Error> for CryptoError {
    fn from(err: Secp256k1Error) -> Self {
        use secp256k1::Error;

        let kind = match &err.0 {
            Error::IncorrectSignature => CryptoKind::Signature,
            Error::InvalidPublicKey => CryptoKind::PublicKey,
            Error::InvalidSignature => CryptoKind::Signature,
            Error::InvalidSecretKey => CryptoKind::PrivateKey,
            _ => return CryptoError::Unexpected(Box::new(err.0)),
        };

        CryptoError::from(kind).with_cause(Box::new(err.0))
    }
}

//
// HashedMessage Impl
//

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

#[cfg(test)]
mod tests {
    use super::{generate_keypair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature};

    use ophelia::{impl_quickcheck_arbitrary, HashValue, PrivateKey, PublicKey, Signature};

    use quickcheck_macros::quickcheck;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    use std::convert::TryFrom;

    impl_quickcheck_arbitrary!(Secp256k1PrivateKey);

    #[test]
    fn should_generate_workable_keypair_from_crypto_rng() {
        let mut rng = OsRng::new().expect("OsRng");
        let (priv_key, pub_key) = generate_keypair(&mut rng);

        let msg = {
            let mut hasher = Sha256::new();
            hasher.input(b"you can(not) redo");
            HashValue::try_from(&hasher.result()[..32]).expect("msg")
        };

        let sig = priv_key.sign_message(&msg);
        assert!(sig.verify(&msg, &pub_key).is_ok());
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
    fn prop_signature_bytes_serialization(msg: HashValue, priv_key: Secp256k1PrivateKey) -> bool {
        let sig = priv_key.sign_message(&msg);

        match Secp256k1Signature::try_from(sig.to_bytes().as_ref()) {
            Ok(s) => s == sig,
            Err(_) => false,
        }
    }

    #[quickcheck]
    fn prop_message_sign_and_verify(msg: HashValue, priv_key: Secp256k1PrivateKey) -> bool {
        let pub_key = priv_key.pub_key();
        let sig = priv_key.sign_message(&msg);

        sig.verify(&msg, &pub_key).is_ok()
    }
}

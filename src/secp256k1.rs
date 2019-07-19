use crate::error::CryptoError;
use crate::traits::{PrivateKey, PublicKey, Signature};

use secp256k1::constants::COMPACT_SIGNATURE_SIZE;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::{Secp256k1, SignOnly, VerifyOnly};

use std::convert::TryFrom;

// 1 byte for RecoveryId(0, 1, 2, 3)
// Reference: https://docs.rs/secp256k1/0.14.1/src/secp256k1/recovery/mod.rs.html#40-45
const RECOVERABLE_SIGNATURE_SIZE: usize = COMPACT_SIGNATURE_SIZE + 1;

pub struct Secp256k1PrivateKey {
    secret_key: secp256k1::SecretKey,
    engine: Secp256k1<SignOnly>,
}

pub struct Secp256k1PublicKey {
    pub_key: secp256k1::PublicKey,
    engine: Secp256k1<VerifyOnly>,
}

pub struct Secp256k1Signature {
    rec_sig: RecoverableSignature,
    engine: Secp256k1<VerifyOnly>,
}

//
// PrivateKey Impl
//

impl TryFrom<&[u8]> for Secp256k1PrivateKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1PrivateKey, Self::Error> {
        let secret_key = secp256k1::SecretKey::from_slice(bytes)?;
        let engine = Secp256k1::signing_only();

        Ok(Secp256k1PrivateKey { secret_key, engine })
    }
}

impl PrivateKey for Secp256k1PrivateKey {
    type PublicKey = Secp256k1PublicKey;
    type Signature = Secp256k1Signature;

    fn sign_message(&self, msg: &[u8]) -> Self::Signature {
        // FIXME: New type instead of &[u8]
        let msg = secp256k1::Message::from_slice(msg).unwrap();

        let rec_sig = self.engine.sign_recoverable(&msg, &self.secret_key);
        let engine = Secp256k1::verification_only();

        Secp256k1Signature { rec_sig, engine }
    }

    fn pub_key(&self) -> Self::PublicKey {
        let pub_key = secp256k1::PublicKey::from_secret_key(&self.engine, &self.secret_key);
        let engine = Secp256k1::verification_only();

        Secp256k1PublicKey { pub_key, engine }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.secret_key[..]
    }
}

//
// PublicKey Impl
//

impl TryFrom<&[u8]> for Secp256k1PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1PublicKey, Self::Error> {
        let pub_key = secp256k1::PublicKey::from_slice(bytes)?;
        let engine = Secp256k1::verification_only();

        Ok(Secp256k1PublicKey { pub_key, engine })
    }
}

impl PublicKey<33> for Secp256k1PublicKey {
    type Signature = Secp256k1Signature;

    fn verify_signature(&self, msg: &[u8], sig: &Self::Signature) -> Result<(), CryptoError> {
        // FIXME: New type instead of &[u8]
        let msg = secp256k1::Message::from_slice(msg)?;
        let sig = sig.rec_sig.to_standard();

        self.engine.verify(&msg, &sig, &self.pub_key)?;
        Ok(())
    }

    fn to_bytes(&self) -> [u8; 33] {
        self.pub_key.serialize()
    }
}

//
// Signature Impl
//

impl TryFrom<&[u8]> for Secp256k1Signature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1Signature, Self::Error> {
        if bytes.len() != RECOVERABLE_SIGNATURE_SIZE {
            Err(CryptoError::InvalidLength)?;
        }

        let recovery_id = {
            let i32_id = i32::from(bytes[COMPACT_SIGNATURE_SIZE]);
            RecoveryId::from_i32(i32_id)?
        };

        let rec_sig =
            RecoverableSignature::from_compact(&bytes[..COMPACT_SIGNATURE_SIZE], recovery_id)?;
        let engine = Secp256k1::verification_only();

        Ok(Secp256k1Signature { rec_sig, engine })
    }
}

impl Signature<65> for Secp256k1Signature {
    type PublicKey = Secp256k1PublicKey;

    fn verify(&self, msg: &[u8], pub_key: &Self::PublicKey) -> Result<(), CryptoError> {
        // FIXME: New type instead of &[u8]
        let msg = secp256k1::Message::from_slice(msg)?;
        let sig = self.rec_sig.to_standard();

        self.engine.verify(&msg, &sig, &pub_key.pub_key)?;
        Ok(())
    }

    fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        let (rec_id, serialized) = self.rec_sig.serialize_compact();

        let i32_id = rec_id.to_i32();
        assert!(i32_id >= 0 && i32_id <= 3);

        bytes.copy_from_slice(&serialized[..COMPACT_SIGNATURE_SIZE]);
        bytes[COMPACT_SIGNATURE_SIZE] = i32_id as u8;

        bytes
    }
}

impl From<secp256k1::Error> for CryptoError {
    fn from(err: secp256k1::Error) -> Self {
        use secp256k1::Error;

        match err {
            Error::IncorrectSignature => CryptoError::InvalidSignature,
            Error::InvalidMessage => CryptoError::InvalidLength,
            Error::InvalidPublicKey => CryptoError::InvalidPublicKey,
            Error::InvalidSignature => CryptoError::InvalidSignature,
            Error::InvalidSecretKey => CryptoError::InvalidPrivateKey,
            Error::InvalidRecoveryId => CryptoError::InvalidSignature,
            Error::InvalidTweak => CryptoError::Other("secp256k1: bad tweak"),
            Error::NotEnoughMemory => CryptoError::Other("secp256k1: not enough memory"),
        }
    }
}

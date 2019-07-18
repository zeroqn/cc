use crate::error::CryptoError;
use crate::traits::{PrivateKey, PublicKey, Signature};

use secp256k1::constants::{COMPACT_SIGNATURE_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::{Secp256k1, SignOnly, VerifyOnly};

use std::convert::TryFrom;

const RECOVERY_ID_SIZE: usize = 4;
const RECOVERABLE_SIGNATURE_SIZE: usize = COMPACT_SIGNATURE_SIZE + RECOVERY_ID_SIZE;

pub struct Secp256k1PrivateKey {
    secret_key_bytes: [u8; SECRET_KEY_SIZE],
    ctx: Secp256k1<SignOnly>,
}

pub struct Secp256k1PublicKey {
    pub_key_bytes: [u8; PUBLIC_KEY_SIZE],
    ctx: Secp256k1<VerifyOnly>,
}

pub struct Secp256k1Signature {
    sig_recv_bytes: [u8; RECOVERABLE_SIGNATURE_SIZE],
    ctx: Secp256k1<VerifyOnly>,
}

//
// PrivateKey Impl
//

impl TryFrom<&[u8]> for Secp256k1PrivateKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1PrivateKey, Self::Error> {
        secp256k1::SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidPrivateKeyError)?;

        let mut secret_key_bytes = [0u8; SECRET_KEY_SIZE];
        secret_key_bytes.copy_from_slice(&bytes[..SECRET_KEY_SIZE]);

        let ctx = Secp256k1::signing_only();

        Ok(Secp256k1PrivateKey {
            secret_key_bytes,
            ctx,
        })
    }
}

impl PrivateKey for Secp256k1PrivateKey {
    type PublicKey = Secp256k1PublicKey;
    type Signature = Secp256k1Signature;

    fn sign_message(&self, msg: &[u8]) -> Self::Signature {
        // FIXME: New type instead of &[u8]
        let msg = secp256k1::Message::from_slice(msg).unwrap();
        let secret_key = secp256k1::SecretKey::from_slice(self.as_bytes())
            .expect("invalid secret key is impossible");

        let sig = self.ctx.sign_recoverable(&msg, &secret_key);
        let ctx = Secp256k1::verification_only();

        let (recv_id, sig_bytes) = sig.serialize_compact();
        let recv_id_bytes = recv_id.to_i32().to_be_bytes();

        let mut sig_recv_bytes = [0u8; RECOVERABLE_SIGNATURE_SIZE];
        sig_recv_bytes.copy_from_slice(&sig_bytes);
        sig_recv_bytes[COMPACT_SIGNATURE_SIZE..].copy_from_slice(&recv_id_bytes);

        Secp256k1Signature {
            sig_recv_bytes,
            ctx,
        }
    }

    fn pub_key(&self) -> Self::PublicKey {
        let secret_key = secp256k1::SecretKey::from_slice(self.as_bytes())
            .expect("invalid secret key is impossible");

        let pub_key = secp256k1::PublicKey::from_secret_key(&self.ctx, &secret_key);
        let pub_key_bytes = pub_key.serialize();
        let ctx = Secp256k1::verification_only();

        Secp256k1PublicKey { pub_key_bytes, ctx }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.secret_key_bytes
    }
}

//
// PublicKey Impl
//

impl TryFrom<&[u8]> for Secp256k1PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1PublicKey, Self::Error> {
        let pub_key = secp256k1::PublicKey::from_slice(bytes)
            .map_err(|_| CryptoError::InvalidPublicKeyError)?;

        let pub_key_bytes = pub_key.serialize();
        let ctx = Secp256k1::verification_only();

        Ok(Secp256k1PublicKey { pub_key_bytes, ctx })
    }
}

impl PublicKey for Secp256k1PublicKey {
    type Signature = Secp256k1Signature;

    fn verify_signature(&self, msg: &[u8], sig: &Self::Signature) -> Result<(), CryptoError> {
        // FIXME: New type instead of &[u8]
        let msg = secp256k1::Message::from_slice(msg).unwrap();
        let pub_key = secp256k1::PublicKey::from_slice(&self.pub_key_bytes)
            .expect("invalid publickey is impossible");

        let recovery_id = {
            let mut id_bytes = [0u8; RECOVERY_ID_SIZE];
            id_bytes.copy_from_slice(
                &sig.sig_recv_bytes[COMPACT_SIGNATURE_SIZE..RECOVERABLE_SIGNATURE_SIZE],
            );

            let i32_id = i32::from_be_bytes(id_bytes);
            RecoveryId::from_i32(i32_id).map_err(|_| CryptoError::InvalidSignatureError)?
        };

        let mut sig_bytes = [0u8; COMPACT_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&sig.sig_recv_bytes[..COMPACT_SIGNATURE_SIZE]);

        let recv_sig = RecoverableSignature::from_compact(&sig_bytes, recovery_id)
            .map_err(|_| CryptoError::InvalidSignatureError)?;
        let sig = recv_sig.to_standard();

        self.ctx
            .verify(&msg, &sig, &pub_key)
            .map_err(|_| CryptoError::InvalidSignatureError)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.pub_key_bytes
    }
}

//
// Signature Impl
//

impl TryFrom<&[u8]> for Secp256k1Signature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Secp256k1Signature, Self::Error> {
        if bytes.len() != RECOVERABLE_SIGNATURE_SIZE {
            Err(CryptoError::InvalidLengthError)?;
        }

        let recovery_id = {
            let mut id_bytes = [0u8; RECOVERY_ID_SIZE];
            id_bytes.copy_from_slice(&bytes[COMPACT_SIGNATURE_SIZE..RECOVERABLE_SIGNATURE_SIZE]);

            let i32_id = i32::from_be_bytes(id_bytes);
            RecoveryId::from_i32(i32_id).map_err(|_| CryptoError::InvalidSignatureError)?
        };

        let mut sig_bytes = [0u8; COMPACT_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&bytes[..COMPACT_SIGNATURE_SIZE]);

        RecoverableSignature::from_compact(&sig_bytes, recovery_id)
            .map_err(|_| CryptoError::InvalidSignatureError)?;

        let ctx = Secp256k1::verification_only();
        let mut sig_recv_bytes = [0u8; RECOVERABLE_SIGNATURE_SIZE];
        sig_recv_bytes.copy_from_slice(&bytes[..RECOVERABLE_SIGNATURE_SIZE]);

        Ok(Secp256k1Signature {
            sig_recv_bytes,
            ctx,
        })
    }
}

impl Signature for Secp256k1Signature {
    type PublicKey = Secp256k1PublicKey;

    fn verify(&self, msg: &[u8], _pub_key: &Self::PublicKey) -> Result<(), CryptoError> {
        // FIXME: New type instead of &[u8]
        let msg = secp256k1::Message::from_slice(msg).unwrap();

        let mut sig_bytes = [0u8; COMPACT_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&self.sig_recv_bytes[..COMPACT_SIGNATURE_SIZE]);

        let recovery_id = {
            let mut id_bytes = [0u8; RECOVERY_ID_SIZE];
            id_bytes.copy_from_slice(
                &self.sig_recv_bytes[COMPACT_SIGNATURE_SIZE..RECOVERABLE_SIGNATURE_SIZE],
            );

            let i32_id = i32::from_be_bytes(id_bytes);
            RecoveryId::from_i32(i32_id).map_err(|_| CryptoError::InvalidSignatureError)?
        };

        let mut sig_bytes = [0u8; COMPACT_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&self.sig_recv_bytes[..COMPACT_SIGNATURE_SIZE]);

        let recv_sig = RecoverableSignature::from_compact(&sig_bytes, recovery_id)
            .map_err(|_| CryptoError::InvalidSignatureError)?;
        let sig = recv_sig.to_standard();
        let pub_key = self
            .ctx
            .recover(&msg, &recv_sig)
            .expect("invlid public key is impossible");

        self.ctx
            .verify(&msg, &sig, &pub_key)
            .map_err(|_| CryptoError::InvalidSignatureError)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.sig_recv_bytes.to_vec()
    }
}

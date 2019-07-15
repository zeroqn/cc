// TODO: quick-check tests
// TODO: documents

use crate::error::CryptoError;
use crate::traits::{PrivateKey, PublicKey, Signature};

use curve25519_dalek::scalar::Scalar;

use std::convert::TryFrom;

pub struct Ed25519Keypair(ed25519_dalek::Keypair);
pub struct Ed25519PrivateKey(ed25519_dalek::SecretKey);
pub struct Ed25519PublicKey(ed25519_dalek::PublicKey);
pub struct Ed25519Signature(ed25519_dalek::Signature);

//
// Keypair impl
//

impl Ed25519Keypair {
    pub fn generate<R>(mut csprng: &mut R) -> Self
    where
        R: rand::CryptoRng + rand::Rng,
    {
        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);

        Ed25519Keypair(keypair)
    }

    pub fn pub_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.raw().public)
    }

    fn raw(&self) -> &ed25519_dalek::Keypair {
        &self.0
    }
}

impl Into<Ed25519PrivateKey> for Ed25519Keypair {
    fn into(self) -> Ed25519PrivateKey {
        Ed25519PrivateKey(self.0.secret)
    }
}

//
// PrivateKey Impl
//

impl Ed25519PrivateKey {
    pub fn raw(&self) -> &ed25519_dalek::SecretKey {
        &self.0
    }
}

impl TryFrom<&[u8]> for Ed25519PrivateKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Ed25519PrivateKey, Self::Error> {
        let secret_key = ed25519_dalek::SecretKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidLengthError)?;

        Ok(Ed25519PrivateKey(secret_key))
    }
}

impl PrivateKey for Ed25519PrivateKey {
    type PublicKey = Ed25519PublicKey;
    type Signature = Ed25519Signature;

    fn sign_message(&self, msg: &[u8]) -> Self::Signature {
        let secret_key = self.raw();
        let pub_key = self.pub_key();

        let expanded_secret_key = ed25519_dalek::ExpandedSecretKey::from(secret_key);
        let sig = expanded_secret_key.sign(msg, pub_key.raw());

        Ed25519Signature(sig)
    }

    fn pub_key(&self) -> Self::PublicKey {
        let secret_key = self.raw();
        let pub_key = ed25519_dalek::PublicKey::from(secret_key);

        Ed25519PublicKey(pub_key)
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

//
// PublicKey Impl
//

impl Ed25519PublicKey {
    pub fn raw(&self) -> &ed25519_dalek::PublicKey {
        &self.0
    }
}

/// Deserialize an ed25519 public key from bytes.
//
// Note: According to ed25519-dalek doc, it's our responsibility to make
// sure that the bytes passed actually represent a compressed point, and
// that point is actaul point on the curve. We also check that point
// against small subgroup attack.
impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Ed25519PublicKey, Self::Error> {
        if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(CryptoError::InvalidLengthError);
        }

        let mut bits = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        bits.copy_from_slice(&bytes[..ed25519_dalek::PUBLIC_KEY_LENGTH]);

        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or(CryptoError::InvalidPublicKeyError)?;

        if point.is_small_order() {
            Err(CryptoError::SmallSubgroupError)?;
        }

        let pub_key = ed25519_dalek::PublicKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidLengthError)?;

        Ok(Ed25519PublicKey(pub_key))
    }
}

impl PublicKey for Ed25519PublicKey {
    type Signature = Ed25519Signature;

    fn verify_signature(&self, msg: &[u8], sig: &Self::Signature) -> Result<(), CryptoError> {
        sig.verify(msg, self)
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

//
// Signature Impl
//

impl Ed25519Signature {
    pub fn raw(&self) -> &ed25519_dalek::Signature {
        &self.0
    }
}

// Note: check against small subgroup attack
impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Ed25519Signature, Self::Error> {
        if bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
            Err(CryptoError::InvalidLengthError)?;
        }

        let mut s_bits: [u8; 32] = [0; 32];
        s_bits.copy_from_slice(&bytes[32..]);

        Scalar::from_canonical_bytes(s_bits).ok_or(CryptoError::InvalidSignatureError)?;

        let mut r_bits: [u8; 32] = [0; 32];
        r_bits.copy_from_slice(&bytes[..32]);

        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(r_bits);
        let point = compressed
            .decompress()
            .ok_or(CryptoError::InvalidSignatureError)?;

        if point.is_small_order() {
            Err(CryptoError::SmallSubgroupError)?;
        }

        let sig = ed25519_dalek::Signature::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidSignatureError)?;

        Ok(Ed25519Signature(sig))
    }
}

impl Signature for Ed25519Signature {
    type PublicKey = Ed25519PublicKey;

    fn verify(&self, msg: &[u8], pub_key: &Self::PublicKey) -> Result<(), CryptoError> {
        let pub_key = pub_key.raw();
        let sig = self.raw();

        pub_key
            .verify(msg, sig)
            .map_err(|_| CryptoError::InvalidSignatureError)?;

        Ok(())
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

use cc::{Crypto, CryptoError, HashValue, PrivateKey, PublicKey, Signature};
use cc_derive::SecretDebug;

#[cfg(any(test, feature = "generate"))]
use rand::{CryptoRng, Rng};

#[cfg(any(test, feature = "generate"))]
use rand::distributions::Standard;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{PK_SIZE, SIG_SIZE};

use std::convert::TryFrom;

#[derive(SecretDebug, PartialEq)]
pub struct BLS12381PrivateKey(threshold_crypto::SecretKey);

#[derive(Debug, PartialEq)]
pub struct BLS12381PublicKey(threshold_crypto::PublicKey);

#[derive(Debug, PartialEq)]
pub struct BLS12381Signature(threshold_crypto::Signature);

pub struct BLS12381;

impl Crypto<32, 48> for BLS12381 {
    #[cfg(feature = "generate")]
    type KeyGenerator = BLS12381PrivateKey;
    type PrivateKey = BLS12381PrivateKey;
    type PublicKey = BLS12381PublicKey;
    type Signature = BLS12381Signature;
}

#[cfg(any(test, feature = "generate"))]
pub fn generate_keypair<R: CryptoRng + Rng + ?Sized>(
    rng: &mut R,
) -> (BLS12381PrivateKey, BLS12381PublicKey) {
    let secret_key: threshold_crypto::SecretKey = rng.sample(Standard);
    let pub_key = secret_key.public_key();

    (BLS12381PrivateKey(secret_key), BLS12381PublicKey(pub_key))
}

#[cfg(feature = "generate")]
impl cc::KeyGenerator for BLS12381PrivateKey {
    type Output = BLS12381PrivateKey;

    fn generate<R: CryptoRng + Rng + ?Sized>(mut rng: &mut R) -> Self::Output {
        let (priv_key, _) = generate_keypair(&mut rng);

        priv_key
    }
}

//
// PrivateKey Impl
//

impl TryFrom<&[u8]> for BLS12381PrivateKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<BLS12381PrivateKey, Self::Error> {
        let secret_key = bincode::deserialize::<threshold_crypto::SecretKey>(bytes)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;

        Ok(BLS12381PrivateKey(secret_key))
    }
}

impl PrivateKey<32> for BLS12381PrivateKey {
    type PublicKey = BLS12381PublicKey;
    type Signature = BLS12381Signature;

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        let sig = self.0.sign(msg.as_ref());

        BLS12381Signature(sig)
    }

    fn pub_key(&self) -> Self::PublicKey {
        let pub_key = self.0.public_key();

        BLS12381PublicKey(pub_key)
    }

    fn to_bytes(&self) -> [u8; 32] {
        let ser_secret = {
            let secret = SerdeSecret(&self.0);
            bincode::serialize(&secret).expect("Should serialize secret key")
        };

        assert_eq!(ser_secret.len(), 32);

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(ser_secret.as_slice());

        bytes
    }
}

//
// PublicKey Impl
//

// TODO: Borrow<[u8; 48]>? optimize it.
impl TryFrom<&[u8]> for BLS12381PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<BLS12381PublicKey, Self::Error> {
        if bytes.len() != PK_SIZE {
            return Err(CryptoError::InvalidLength);
        }

        let mut key_bytes = [0u8; PK_SIZE];
        key_bytes.copy_from_slice(bytes);

        let pub_key = threshold_crypto::PublicKey::from_bytes(key_bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(BLS12381PublicKey(pub_key))
    }
}

impl PublicKey<48> for BLS12381PublicKey {
    type Signature = BLS12381Signature;

    fn to_bytes(&self) -> [u8; PK_SIZE] {
        self.0.to_bytes()
    }
}

//
// Signature Impl
//

impl TryFrom<&[u8]> for BLS12381Signature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<BLS12381Signature, Self::Error> {
        if bytes.len() != SIG_SIZE {
            return Err(CryptoError::InvalidLength);
        }

        let mut sig_bytes = [0u8; SIG_SIZE];
        sig_bytes.copy_from_slice(bytes);

        let sig = threshold_crypto::Signature::from_bytes(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;

        Ok(BLS12381Signature(sig))
    }
}

impl Signature for BLS12381Signature {
    type PublicKey = BLS12381PublicKey;

    fn verify(&self, msg: &HashValue, pub_key: &Self::PublicKey) -> Result<(), CryptoError> {
        if pub_key.0.verify(&self.0, msg.as_ref()) {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }

    // TODO: optimize
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_keypair, BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature};

    use cc::{impl_quickcheck_arbitrary, HashValue, PrivateKey, PublicKey, Signature};

    use quickcheck_macros::quickcheck;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    use std::convert::TryFrom;

    impl_quickcheck_arbitrary!(BLS12381PrivateKey);

    #[test]
    fn should_generate_workable_keypair_from_crypto_rng() {
        let mut rng = OsRng::new().expect("OsRng");
        let (priv_key, pub_key) = generate_keypair(&mut rng);

        let msg = {
            let mut hasher = Sha256::new();
            hasher.input(b"let loop again");
            HashValue::try_from(&hasher.result()[..32]).expect("msg")
        };

        let sig = priv_key.sign_message(&msg);
        assert!(sig.verify(&msg, &pub_key).is_ok());
    }

    #[quickcheck]
    fn prop_private_key_bytes_serialization(priv_key: BLS12381PrivateKey) -> bool {
        BLS12381PrivateKey::try_from(priv_key.to_bytes().as_ref()) == Ok(priv_key)
    }

    #[quickcheck]
    fn prop_public_key_bytes_serialization(priv_key: BLS12381PrivateKey) -> bool {
        let pub_key = priv_key.pub_key();

        BLS12381PublicKey::try_from(pub_key.to_bytes().as_ref()) == Ok(pub_key)
    }

    #[quickcheck]
    fn prop_signature_bytes_serialization(msg: HashValue, priv_key: BLS12381PrivateKey) -> bool {
        let sig = priv_key.sign_message(&msg);

        BLS12381Signature::try_from(sig.to_bytes().as_ref()) == Ok(sig)
    }

    #[quickcheck]
    fn prop_message_sign_and_verify(msg: HashValue, priv_key: BLS12381PrivateKey) -> bool {
        let pub_key = priv_key.pub_key();
        let sig = priv_key.sign_message(&msg);

        sig.verify(&msg, &pub_key).is_ok()
    }
}

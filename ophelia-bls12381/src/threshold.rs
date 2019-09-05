use crate::{BLS12381PublicKey, BLS12381Signature};

use ophelia::threshold::{PrivateKeySet, PublicKeySet, ThresholdCrypto};
use ophelia::{Crypto, CryptoError, HashValue, PrivateKey, PublicKey, Signature};
use ophelia_derive::SecretDebug;

#[cfg(any(test, feature = "generate"))]
use rand::{CryptoRng, Rng};

use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{poly::Poly, PK_SIZE, SIG_SIZE};

use std::convert::TryFrom;

#[derive(SecretDebug, PartialEq)]
pub struct BLS12381PrivateKeySet(threshold_crypto::poly::Poly);
#[derive(SecretDebug, PartialEq)]
pub struct BLS12381PrivateKeyShare(threshold_crypto::SecretKeyShare);

#[derive(Debug, PartialEq)]
pub struct BLS12381PublicKeySet(threshold_crypto::PublicKeySet);
#[derive(Debug, PartialEq)]
pub struct BLS12381PublicKeyShare(threshold_crypto::PublicKeyShare);

#[derive(Debug, PartialEq)]
pub struct BLS12381SignatureShare(threshold_crypto::SignatureShare);

pub struct BLS12381Threshold;

impl ThresholdCrypto<72, 104> for BLS12381Threshold {
    #[cfg(feature = "generate")]
    type KeySetGenerator = BLS12381PrivateKeySet;
    type PrivateKeySet = BLS12381PrivateKeySet;
    type PublicKeySet = BLS12381PublicKeySet;
    type MasterPublicKey = BLS12381PublicKey;
    type PrivateKeyShare = BLS12381PrivateKeyShare;
    type PublicKeyShare = BLS12381PublicKeyShare;
    type SignatureShare = BLS12381SignatureShare;
    type CombinedSignature = BLS12381Signature;
}

impl Crypto<32, 48> for BLS12381Threshold {
    #[cfg(feature = "generate")]
    type KeyGenerator = BLS12381PrivateKeyShare;
    type PrivateKey = BLS12381PrivateKeyShare;
    type PublicKey = BLS12381PublicKeyShare;
    type Signature = BLS12381SignatureShare;
}

#[cfg(any(test, feature = "generate"))]
pub fn generate_keyset<R: CryptoRng + Rng + ?Sized>(
    mut rng: &mut R,
    threshold: usize,
) -> Result<(BLS12381PrivateKeySet, BLS12381PublicKeySet), CryptoError> {
    let poly = Poly::try_random(threshold, &mut rng)
        .map_err(|_e| CryptoError::Other("Failed to create random `PrivateKeySet`"))?;
    let secret_key_set = threshold_crypto::SecretKeySet::from(poly.clone());

    let pub_key_set = secret_key_set.public_keys();

    Ok((
        BLS12381PrivateKeySet(poly),
        BLS12381PublicKeySet(pub_key_set),
    ))
}

#[cfg(feature = "generate")]
impl ophelia::KeyGenerator for BLS12381PrivateKeyShare {
    type Output = BLS12381PrivateKeyShare;

    fn generate<R: CryptoRng + Rng + ?Sized>(_rng: &mut R) -> Self::Output {
        panic!("Should not directly create `PrivateKeyShare`");
    }
}

// TODO: reconsider panic
/// # panic
///
/// Panic when fail to generate key set
#[cfg(feature = "generate")]
impl ophelia::threshold::KeySetGenerator for BLS12381PrivateKeySet {
    type Output = BLS12381PrivateKeySet;

    fn generate<R: CryptoRng + Rng + ?Sized>(mut rng: &mut R, threshold: usize) -> Self::Output {
        let (priv_key_set, _) =
            generate_keyset(&mut rng, threshold).expect("Failed to generate PrivateKeySet");

        priv_key_set
    }
}

//
// PrivateKeySet Impl
//

impl TryFrom<&[u8]> for BLS12381PrivateKeySet {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<BLS12381PrivateKeySet, Self::Error> {
        let poly =
            bincode::deserialize::<Poly>(bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;

        Ok(BLS12381PrivateKeySet(poly))
    }
}

impl PrivateKeySet<72> for BLS12381PrivateKeySet {
    type PublicKeySet = BLS12381PublicKeySet;
    type PrivateKeyShare = BLS12381PrivateKeyShare;

    fn public_key_set(&self) -> Self::PublicKeySet {
        let secret_key_set = threshold_crypto::SecretKeySet::from(self.0.clone());

        BLS12381PublicKeySet(secret_key_set.public_keys())
    }

    // TODO: i must start from 0, move i internal?
    /// Warning: i must start from 0
    fn private_key_share(&self, i: usize) -> Self::PrivateKeyShare {
        let secret_key_set = threshold_crypto::SecretKeySet::from(self.0.clone());
        let share = secret_key_set.secret_key_share(i);

        BLS12381PrivateKeyShare(share)
    }

    // TODO: reconsider panic
    /// # panic
    ///
    /// Panic when failed to serialize secret key set
    fn to_bytes(&self) -> [u8; 72] {
        let ser_poly = bincode::serialize(&self.0).expect("Should serialize serect key set");

        assert_eq!(ser_poly.len(), 72);

        let mut bytes = [0u8; 72];
        bytes.copy_from_slice(ser_poly.as_slice());

        bytes
    }
}

//
// PublicKeySet Impl
//

impl TryFrom<&[u8]> for BLS12381PublicKeySet {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<BLS12381PublicKeySet, Self::Error> {
        let pub_key_set = bincode::deserialize::<threshold_crypto::PublicKeySet>(bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(BLS12381PublicKeySet(pub_key_set))
    }
}

impl PublicKeySet<104> for BLS12381PublicKeySet {
    type MasterPublicKey = BLS12381PublicKey;
    type PublicKeyShare = BLS12381PublicKeyShare;
    type SignatureShare = BLS12381SignatureShare;
    type CombinedSignature = BLS12381Signature;

    fn master_public_key(&self) -> Self::MasterPublicKey {
        let master_key = self.0.public_key();

        BLS12381PublicKey(master_key)
    }

    fn public_key_share(&self, i: usize) -> Self::PublicKeyShare {
        let share = self.0.public_key_share(i);

        BLS12381PublicKeyShare(share)
    }

    fn combine_signatures(
        &self,
        shares: &[Self::SignatureShare],
    ) -> Result<Self::CombinedSignature, CryptoError> {
        let shares = shares
            .iter()
            .enumerate()
            .map(|(i, s)| (i, &s.0))
            .collect::<Vec<_>>();

        let combined = self
            .0
            .combine_signatures(shares)
            .map_err(|_e| CryptoError::Other("Failed to combine signatures"))?;

        Ok(BLS12381Signature(combined))
    }

    fn verify(&self, msg: &HashValue, sig: &Self::CombinedSignature) -> Result<(), CryptoError> {
        let master_pub_key = self.master_public_key();

        sig.verify(msg, &master_pub_key)
    }

    fn to_bytes(&self) -> [u8; 104] {
        let ser_key = bincode::serialize(&self.0).expect("Should serialize public key set");

        assert_eq!(ser_key.len(), 104);

        let mut bytes = [0u8; 104];
        bytes.copy_from_slice(ser_key.as_slice());

        bytes
    }
}

//
// PrivateKey Impl
//

// TODO: SerdeSecret?
impl TryFrom<&[u8]> for BLS12381PrivateKeyShare {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<BLS12381PrivateKeyShare, Self::Error> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidLength);
        }

        let secret_key_share = bincode::deserialize::<threshold_crypto::SecretKeyShare>(bytes)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;

        Ok(BLS12381PrivateKeyShare(secret_key_share))
    }
}

impl PrivateKey<32> for BLS12381PrivateKeyShare {
    type PublicKey = BLS12381PublicKeyShare;
    type Signature = BLS12381SignatureShare;

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        let sig = self.0.sign(msg.as_ref());

        BLS12381SignatureShare(sig)
    }

    fn pub_key(&self) -> Self::PublicKey {
        let pub_key_share = self.0.public_key_share();

        BLS12381PublicKeyShare(pub_key_share)
    }

    fn to_bytes(&self) -> [u8; 32] {
        let ser_secret = {
            let secret = SerdeSecret(&self.0);
            bincode::serialize(&secret).expect("Should serialize secret share key")
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

impl TryFrom<&[u8]> for BLS12381PublicKeyShare {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<BLS12381PublicKeyShare, Self::Error> {
        if bytes.len() != PK_SIZE {
            return Err(CryptoError::InvalidLength);
        }

        let mut key_bytes = [0u8; PK_SIZE];
        key_bytes.copy_from_slice(bytes);

        let pub_key = threshold_crypto::PublicKeyShare::from_bytes(key_bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(BLS12381PublicKeyShare(pub_key))
    }
}

impl PublicKey<48> for BLS12381PublicKeyShare {
    type Signature = BLS12381SignatureShare;

    fn to_bytes(&self) -> [u8; PK_SIZE] {
        self.0.to_bytes()
    }
}

//
// Signature Impl
//

impl TryFrom<&[u8]> for BLS12381SignatureShare {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<BLS12381SignatureShare, Self::Error> {
        if bytes.len() != SIG_SIZE {
            return Err(CryptoError::InvalidLength);
        }

        let mut sig_bytes = [0u8; SIG_SIZE];
        sig_bytes.copy_from_slice(bytes);

        let sig = threshold_crypto::SignatureShare::from_bytes(sig_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;

        Ok(BLS12381SignatureShare(sig))
    }
}

impl Signature for BLS12381SignatureShare {
    type PublicKey = BLS12381PublicKeyShare;

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
    use super::{generate_keyset, BLS12381PrivateKeySet, BLS12381PublicKeySet};
    use super::{BLS12381PrivateKeyShare, BLS12381PublicKeyShare, BLS12381SignatureShare};

    use ophelia::threshold::{PrivateKeySet, PublicKeySet};
    use ophelia::{HashValue, PrivateKey, PublicKey, Signature};

    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use threshold_crypto::poly::Poly;

    use std::convert::TryFrom;

    impl Clone for BLS12381PrivateKeySet {
        fn clone(&self) -> Self {
            Self::try_from(self.to_bytes().as_ref()).expect("Clone")
        }
    }

    impl Arbitrary for BLS12381PrivateKeySet {
        fn arbitrary<G: Gen>(mut g: &mut G) -> BLS12381PrivateKeySet {
            let poly = Poly::try_random(1, &mut g).expect("PrivateKeySet");

            BLS12381PrivateKeySet(poly)
        }
    }

    #[test]
    fn should_generate_workable_keyset_from_crypto_rng() {
        let mut rng = OsRng::new().expect("OsRng");
        let (priv_key_set, pub_key_set) = generate_keyset(&mut rng, 1).expect("Key set");

        println!("len: {}", pub_key_set.to_bytes().len());

        let msg = {
            let mut hasher = Sha256::new();
            hasher.input(b"threshold msg");
            HashValue::try_from(&hasher.result()[..32]).expect("msg")
        };

        let sk_s1 = priv_key_set.private_key_share(0);
        let sk_s2 = priv_key_set.private_key_share(1);

        let pk_s1 = sk_s1.pub_key();
        let pk_s2 = sk_s2.pub_key();

        let sig_s1 = sk_s1.sign_message(&msg);
        let sig_s2 = sk_s2.sign_message(&msg);

        assert!(sig_s1.verify(&msg, &pk_s1).is_ok());
        assert!(sig_s2.verify(&msg, &pk_s2).is_ok());

        let combined_sig = pub_key_set
            .combine_signatures(&[sig_s1, sig_s2])
            .expect("Combine");

        let pk_m = pub_key_set.master_public_key();

        assert!(combined_sig.verify(&msg, &pk_m).is_ok());
        assert!(pub_key_set.verify(&msg, &combined_sig).is_ok());
    }

    #[quickcheck]
    fn prop_private_key_set_bytes_serialization(priv_key_set: BLS12381PrivateKeySet) -> bool {
        BLS12381PrivateKeySet::try_from(priv_key_set.to_bytes().as_ref()) == Ok(priv_key_set)
    }

    #[quickcheck]
    fn prop_public_key_set_bytes_serialization(priv_key_set: BLS12381PrivateKeySet) -> bool {
        let pub_key_set = priv_key_set.public_key_set();

        BLS12381PublicKeySet::try_from(pub_key_set.to_bytes().as_ref()) == Ok(pub_key_set)
    }

    #[quickcheck]
    fn prop_private_key_share_bytes_serialization(priv_key_set: BLS12381PrivateKeySet) -> bool {
        let priv_key_share = priv_key_set.private_key_share(0);

        BLS12381PrivateKeyShare::try_from(priv_key_share.to_bytes().as_ref()) == Ok(priv_key_share)
    }

    #[quickcheck]
    fn prop_public_key_share_bytes_serialization(priv_key_set: BLS12381PrivateKeySet) -> bool {
        let priv_key_share = priv_key_set.private_key_share(0);
        let pub_key_share = priv_key_share.pub_key();

        BLS12381PublicKeyShare::try_from(pub_key_share.to_bytes().as_ref()) == Ok(pub_key_share)
    }

    #[quickcheck]
    fn prop_signature_share_bytes_serialization(
        msg: HashValue,
        priv_key_set: BLS12381PrivateKeySet,
    ) -> bool {
        let priv_key_share = priv_key_set.private_key_share(0);
        let sig_share = priv_key_share.sign_message(&msg);

        BLS12381SignatureShare::try_from(sig_share.to_bytes().as_ref()) == Ok(sig_share)
    }
}

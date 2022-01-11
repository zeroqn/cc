use ophelia::{BlsSignatureVerify, HashValue, PrivateKey, PublicKey, Signature, ToBlsPublicKey};
use ophelia::{Bytes, Error};
use ophelia::{CryptoRng, RngCore};
use ophelia_derive::SecretDebug;

use blst::{min_pk as bls, BLST_ERROR};

use std::convert::TryFrom;

const DST: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RONUL";

#[derive(thiserror::Error, Debug)]
pub enum BlsError {
    #[error("deserialize fail")]
    Deserialize,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("aggregrate pubkey fail")]
    AggregatePublicKey,
    #[error("aggregate signature fail")]
    AggregateSignature,
}

#[derive(SecretDebug, Clone)]
pub struct BlsPrivateKey(bls::SecretKey);

impl TryFrom<&[u8]> for BlsPrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        use BlsError::*;

        let key = bls::SecretKey::from_bytes(bytes).map_err(|_| Deserialize)?;
        Ok(BlsPrivateKey(key))
    }
}

impl PrivateKey for BlsPrivateKey {
    type Signature = BlsSignature;

    const LENGTH: usize = 32;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        BlsPrivateKey(bls::SecretKey::key_gen(&seed, &[]).unwrap())
    }

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        BlsSignature(self.0.sign(msg.as_ref(), DST.as_bytes(), &[]))
    }

    fn to_bytes(&self) -> Bytes {
        Bytes::from(self.0.to_bytes().to_vec())
    }
}

impl ToBlsPublicKey for BlsPrivateKey {
    type PublicKey = BlsPublicKey;
    type CommonReference = String;

    fn pub_key(&self, _cr: &Self::CommonReference) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct BlsPublicKey(bls::PublicKey);

impl BlsPublicKey {
    pub fn aggregate(keys: Vec<BlsPublicKey>) -> Result<Self, BlsError> {
        let keys = keys.iter().map(|k| &k.0).collect::<Vec<_>>();
        let aggregated_pk = bls::AggregatePublicKey::aggregate(&keys, true)
            .map_err(|_| BlsError::AggregatePublicKey)?;

        Ok(BlsPublicKey(bls::PublicKey::from_aggregate(&aggregated_pk)))
    }
}

impl TryFrom<&[u8]> for BlsPublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        use BlsError::*;

        let key = bls::PublicKey::from_bytes(bytes).map_err(|_| Deserialize)?;
        Ok(BlsPublicKey(key))
    }
}

impl PublicKey for BlsPublicKey {
    type Signature = BlsPublicKey;

    const LENGTH: usize = 48;

    fn to_bytes(&self) -> Bytes {
        Bytes::from(self.0.to_bytes().to_vec())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct BlsSignature(bls::Signature);

impl BlsSignature {
    pub fn combine(sigs_pubkeys: Vec<(BlsSignature, BlsPublicKey)>) -> Result<Self, BlsError> {
        let sigs = sigs_pubkeys
            .iter()
            .map(|(sig, _)| &sig.0)
            .collect::<Vec<_>>();
        let aggregated_sig = bls::AggregateSignature::aggregate(&sigs, true)
            .map_err(|_| BlsError::AggregateSignature)?;

        Ok(BlsSignature(bls::Signature::from_aggregate(
            &aggregated_sig,
        )))
    }
}

impl TryFrom<&[u8]> for BlsSignature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        use BlsError::*;

        let sig = bls::Signature::from_bytes(bytes).map_err(|_| Deserialize)?;
        Ok(BlsSignature(sig))
    }
}

impl Signature for BlsSignature {
    fn to_bytes(&self) -> Bytes {
        Bytes::from(self.0.to_bytes().to_vec())
    }
}

impl BlsSignatureVerify for BlsSignature {
    type PublicKey = BlsPublicKey;
    type CommonReference = String;

    #[cfg(not(feature = "fast"))]
    fn verify(
        &self,
        msg: &HashValue,
        pubkey: &Self::PublicKey,
        _cr: &Self::CommonReference,
    ) -> Result<(), Error> {
        if self
            .0
            .verify(true, msg.as_ref(), DST.as_bytes(), &[], &pubkey.0, true)
            == BLST_ERROR::BLST_SUCCESS
        {
            return Ok(());
        }

        Err(BlsError::InvalidSignature.into())
    }

    #[cfg(feature = "fast")]
    fn verify(
        &self,
        msg: &HashValue,
        pubkey: &Self::PublicKey,
        _cr: &Self::CommonReference,
    ) -> Result<(), Error> {
        if self.0.fast_aggregate_verify_pre_aggregated(
            true,
            msg.as_ref(),
            DST.as_bytes(),
            &pubkey.0,
        ) == BLST_ERROR::BLST_SUCCESS
        {
            return Ok(());
        }

        Err(BlsError::InvalidSignature.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{BlsPrivateKey, BlsPublicKey, BlsSignature};

    use ophelia::{
        BlsSignatureVerify, HashValue, PrivateKey, PublicKey, Signature, ToBlsPublicKey,
    };
    use quickcheck::{Arbitrary, Gen};
    use rand::rngs::OsRng;

    use std::convert::TryFrom;

    impl Arbitrary for BlsPrivateKey {
        fn arbitrary(_: &mut Gen) -> BlsPrivateKey {
            BlsPrivateKey::generate(&mut OsRng)
        }
    }

    // Note: test is slow, we only test once.
    #[test]
    fn should_generate_workable_key() {
        let msg = HashValue::from_bytes_unchecked([0u8; 32]);
        let cr = "fly me to the moon".into();

        let priv_key = BlsPrivateKey::generate(&mut OsRng);
        let pub_key = priv_key.pub_key(&cr);

        let sig = priv_key.sign_message(&msg);
        assert!(sig.verify(&msg, &pub_key, &cr).is_ok());
    }

    // Note: test is slow, we only test once.
    #[test]
    fn should_able_serialize_and_deserlize_public_key() {
        let priv_key = BlsPrivateKey::generate(&mut OsRng);
        let cr = "fly me to the moon".into();
        let pub_key = priv_key.pub_key(&cr);

        let same_key = match BlsPublicKey::try_from(pub_key.to_bytes().as_ref()) {
            Ok(pubkey) => pubkey == pub_key,
            Err(_) => false,
        };
        assert!(same_key)
    }

    #[test]
    fn should_able_serialize_and_deserlize_signature() {
        let msg = HashValue::from_bytes_unchecked([0u8; 32]);

        let priv_key = BlsPrivateKey::generate(&mut OsRng);
        let sig = priv_key.sign_message(&msg);

        let same_sig = match BlsSignature::try_from(sig.to_bytes().as_ref()) {
            Ok(s) => s == sig,
            Err(_) => false,
        };
        assert!(same_sig)
    }

    #[test]
    fn should_able_combine_sigs_and_keys() {
        let msg = HashValue::from_bytes_unchecked([0u8; 32]);
        let cr = "fly me to the moon".into();

        let eva_00 = BlsPrivateKey::generate(&mut OsRng);
        let sig_00 = eva_00.sign_message(&msg);
        let plug_00 = eva_00.pub_key(&cr);

        let eva_01 = BlsPrivateKey::generate(&mut OsRng);
        let sig_01 = eva_01.sign_message(&msg);
        let plug_01 = eva_01.pub_key(&cr);

        let eva_02 = BlsPrivateKey::generate(&mut OsRng);
        let sig_02 = eva_02.sign_message(&msg);
        let plug_02 = eva_02.pub_key(&cr);

        let msig = BlsSignature::combine(vec![
            (sig_00, plug_00.clone()),
            (sig_01, plug_01.clone()),
            (sig_02, plug_02.clone()),
        ])
        .unwrap();

        let akey = BlsPublicKey::aggregate(vec![plug_00, plug_01, plug_02]).unwrap();

        assert!(msig.verify(&msg, &akey, &cr).is_ok());
    }
}

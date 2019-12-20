use ophelia::{Bytes, Error, HashValue, PrivateKey, PublicKey, Signature, ToBlsPublicKey};
use ophelia::{CryptoRng, RngCore};
use ophelia_derive::SecretDebug;

use bls_amcl::common::{Params, SigKey, VerKey};
use bls_amcl::multi_sig_slow::{AggregatedVerKey, MultiSignature};
use bls_amcl::simple;

use std::convert::TryFrom;

#[derive(thiserror::Error, Debug)]
pub enum BlsError {
    #[error("deserialize fail")]
    Deserialize,
    #[error("invalid signature")]
    InvalidSignature,
}

pub struct BlsCommonReference(Params);

impl<'a> Into<BlsCommonReference> for &'a str {
    fn into(self) -> BlsCommonReference {
        BlsCommonReference(Params::new(self.as_ref()))
    }
}

#[derive(SecretDebug, PartialEq, Clone)]
pub struct BlsPrivateKey(SigKey);

impl TryFrom<&[u8]> for BlsPrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        use BlsError::*;

        let key = SigKey::from_bytes(bytes).map_err(|_| Deserialize)?;
        Ok(BlsPrivateKey(key))
    }
}

impl PrivateKey for BlsPrivateKey {
    type Signature = BlsSignature;

    const LENGTH: usize = 0;

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        BlsPrivateKey(SigKey::new(rng))
    }

    fn sign_message(&self, msg: &HashValue) -> Self::Signature {
        BlsSignature(simple::Signature::new(msg.as_ref(), &self.0))
    }

    fn to_bytes(&self) -> Bytes {
        Bytes::from(self.0.to_bytes())
    }
}

impl ToBlsPublicKey for BlsPrivateKey {
    type PublicKey = BlsPublicKey;
    type CommonReference = BlsCommonReference;

    fn pub_key(&self, cr: &BlsCommonReference) -> BlsPublicKey {
        BlsPublicKey(VerKey::from_sigkey(&self.0, &cr.0))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct BlsPublicKey(VerKey);

impl BlsPublicKey {
    pub fn aggregate(keys: Vec<&BlsPublicKey>) -> Self {
        let keys = keys.into_iter().map(|k| &k.0).collect::<Vec<_>>();

        BlsPublicKey(AggregatedVerKey::from_verkeys(keys))
    }
}

impl TryFrom<&[u8]> for BlsPublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        use BlsError::*;

        let key = VerKey::from_bytes(bytes).map_err(|_| Deserialize)?;
        Ok(BlsPublicKey(key))
    }
}

impl PublicKey for BlsPublicKey {
    type Signature = BlsPublicKey;

    // FIXME
    const LENGTH: usize = 0;

    fn to_bytes(&self) -> Bytes {
        Bytes::from(self.0.to_bytes())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct BlsSignature(simple::Signature);

impl BlsSignature {
    pub fn bls_verify(
        &self,
        msg: &HashValue,
        pubkey: &BlsPublicKey,
        cr: &BlsCommonReference,
    ) -> Result<(), Error> {
        if !self.0.verify(msg.as_ref(), &pubkey.0, &cr.0) {
            Err(BlsError::InvalidSignature)?
        } else {
            Ok(())
        }
    }

    pub fn combine(sigs_pubkeys: Vec<(BlsSignature, BlsPublicKey)>) -> Self {
        let sigs_pubkeys = sigs_pubkeys
            .into_iter()
            .map(|(sig, pubkey)| (pubkey.0, sig.0))
            .collect::<Vec<_>>();

        BlsSignature(MultiSignature::from_sigs(&sigs_pubkeys))
    }
}

impl TryFrom<&[u8]> for BlsSignature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        use BlsError::*;

        let sig = simple::Signature::from_bytes(bytes).map_err(|_| Deserialize)?;
        Ok(BlsSignature(sig))
    }
}

impl Signature for BlsSignature {
    type PublicKey = BlsPublicKey;

    // FIXME
    /// # Panic
    ///
    /// please use bls_verify() to verify signature
    fn verify(&self, _: &HashValue, _: &Self::PublicKey) -> Result<(), Error> {
        panic!("please use bls_verify()")
    }

    fn to_bytes(&self) -> Bytes {
        Bytes::from(self.0.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{BlsPrivateKey, BlsPublicKey, BlsSignature};

    use ophelia::{HashValue, PrivateKey, PublicKey, Signature, ToBlsPublicKey};
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use rand::rngs::OsRng;

    use std::convert::TryFrom;

    impl Arbitrary for BlsPrivateKey {
        fn arbitrary<G: Gen>(_: &mut G) -> BlsPrivateKey {
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
        assert!(sig.bls_verify(&msg, &pub_key, &cr).is_ok());
    }

    #[quickcheck]
    fn prop_private_key_bytes_serialization(priv_key: BlsPrivateKey) -> bool {
        match BlsPrivateKey::try_from(priv_key.to_bytes().as_ref()) {
            Ok(seckey) => seckey == priv_key,
            Err(_) => false,
        }
    }

    // Note: test is slow, we only test once.
    #[test]
    fn should_able_serialize_and_deserlize_public_key() {
        let priv_key = BlsPrivateKey::generate(&mut OsRng);
        let cr = "fly me to the moon".into();
        let pub_key = priv_key.pub_key(&cr);

        let cmp_ret = match BlsPublicKey::try_from(pub_key.to_bytes().as_ref()) {
            Ok(pubkey) => pubkey == pub_key,
            Err(_) => false,
        };
        assert!(cmp_ret == true)
    }

    #[test]
    fn should_able_serialize_and_deserlize_signature() {
        let msg = HashValue::from_bytes_unchecked([0u8; 32]);

        let priv_key = BlsPrivateKey::generate(&mut OsRng);
        let sig = priv_key.sign_message(&msg);

        let cmp_ret = match BlsSignature::try_from(sig.to_bytes().as_ref()) {
            Ok(s) => s == sig,
            Err(_) => false,
        };
        assert!(cmp_ret == true)
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
        ]);

        let akey = BlsPublicKey::aggregate(vec![&plug_00, &plug_01, &plug_02]);
        assert!(msig.bls_verify(&msg, &akey, &cr).is_ok());
    }
}

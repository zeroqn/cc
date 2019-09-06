use crate::Signature;
use crate::{CryptoError, HashValue};

use bytes::Bytes;
#[cfg(feature = "generate")]
use rand::{CryptoRng, Rng};

use std::convert::TryFrom;

#[cfg(feature = "generate")]
pub trait KeySetGenerator {
    type Output;

    fn generate<R: CryptoRng + Rng + ?Sized>(rng: &mut R, threshold: usize) -> Self::Output;
}

pub trait PrivateKeySet: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type PublicKeySet;
    type PrivateKeyShare;

    fn public_key_set(&self) -> Self::PublicKeySet;

    fn private_key_share(&self, i: usize) -> Self::PrivateKeyShare;

    fn to_bytes(&self) -> Bytes;
}

pub trait PublicKeySet: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type MasterPublicKey;
    type PublicKeyShare;
    type SignatureShare;
    type CombinedSignature;

    fn master_public_key(&self) -> Self::MasterPublicKey;

    fn public_key_share(&self, i: usize) -> Self::PublicKeyShare;

    fn combine_signatures(
        &self,
        shares: &[Self::SignatureShare],
    ) -> Result<Self::CombinedSignature, CryptoError>;

    fn verify(&self, msg: &HashValue, sig: &Self::CombinedSignature) -> Result<(), CryptoError>;

    fn to_bytes(&self) -> Bytes;
}

pub trait ThresholdCrypto {
    #[cfg(feature = "generate")]
    type KeySetGenerator: KeySetGenerator<Output = Self::PrivateKeySet>;
    type PrivateKeySet: PrivateKeySet<
        PublicKeySet = Self::PublicKeySet,
        PrivateKeyShare = Self::PrivateKeyShare,
    >;
    type PublicKeySet: PublicKeySet<
        MasterPublicKey = Self::MasterPublicKey,
        PublicKeyShare = Self::PublicKeyShare,
        SignatureShare = Self::SignatureShare,
        CombinedSignature = Self::CombinedSignature,
    >;
    type MasterPublicKey;
    type PrivateKeyShare;
    type PublicKeyShare;
    type SignatureShare: Signature<PublicKey = Self::PublicKeyShare>;
    type CombinedSignature: for<'a> TryFrom<&'a [u8], Error = CryptoError>;

    #[cfg(feature = "generate")]
    fn generate<R: CryptoRng + Rng + ?Sized>(
        mut rng: &mut R,
        threshold: usize,
    ) -> (Self::PrivateKeySet, Self::PublicKeySet) {
        let priv_key_set = Self::KeySetGenerator::generate(&mut rng, threshold);
        let pub_key_set = priv_key_set.public_key_set();

        (priv_key_set, pub_key_set)
    }

    fn private_key_share(priv_key_set: &Self::PrivateKeySet, i: usize) -> Self::PrivateKeyShare {
        priv_key_set.private_key_share(i)
    }

    fn master_public_key(pub_key_set: &Self::PublicKeySet) -> Self::MasterPublicKey {
        pub_key_set.master_public_key()
    }

    fn public_key_set(priv_key_set: &Self::PrivateKeySet) -> Self::PublicKeySet {
        priv_key_set.public_key_set()
    }

    fn public_key_share(public_key_set: &Self::PublicKeySet, i: usize) -> Self::PublicKeyShare {
        public_key_set.public_key_share(i)
    }

    fn combine_signatures(
        pub_key_set: &[u8],
        sigs: &[&[u8]],
    ) -> Result<Self::CombinedSignature, CryptoError> {
        let pub_key_set = Self::PublicKeySet::try_from(pub_key_set)?;
        let sig_shares = sigs
            .iter()
            .map(|sig| Self::SignatureShare::try_from(*sig))
            .collect::<Result<Vec<_>, CryptoError>>()?;

        pub_key_set.combine_signatures(sig_shares.as_slice())
    }

    fn verify_signature(pub_key_set: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let pub_key_set = Self::PublicKeySet::try_from(pub_key_set)?;
        let msg = HashValue::try_from(msg)?;
        let sig = Self::CombinedSignature::try_from(sig)?;

        pub_key_set.verify(&msg, &sig)
    }
}

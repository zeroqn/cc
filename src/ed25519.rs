// TODO: documents

use crate::error::CryptoError;
use crate::traits::{PrivateKey, PublicKey, Signature};

use curve25519_dalek::scalar::Scalar;

use std::convert::TryFrom;

pub struct Ed25519PrivateKey(ed25519_dalek::SecretKey);

#[derive(Debug, PartialEq)]
pub struct Ed25519PublicKey(ed25519_dalek::PublicKey);

#[derive(Debug, PartialEq)]
pub struct Ed25519Signature(ed25519_dalek::Signature);

pub struct Ed25519Keypair(ed25519_dalek::Keypair);

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

    pub fn priv_key(self) -> Ed25519PrivateKey {
        self.into()
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

    pub fn is_valid(&self) -> Result<(), CryptoError> {
        let bytes = self.as_bytes();

        let mut bits = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        bits.copy_from_slice(&bytes[..ed25519_dalek::PUBLIC_KEY_LENGTH]);

        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or(CryptoError::InvalidPublicKeyError)?;

        if point.is_small_order() {
            Err(CryptoError::SmallSubgroupError)?;
        }

        Ok(())
    }
}

// Check against small subgroup attack
impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Ed25519PublicKey, Self::Error> {
        if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(CryptoError::InvalidLengthError);
        }

        let dalek_pub_key = ed25519_dalek::PublicKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidLengthError)?;

        let pub_key = Ed25519PublicKey(dalek_pub_key);
        pub_key.is_valid()?;

        Ok(pub_key)
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

    pub fn is_valid(&self) -> Result<(), CryptoError> {
        let bytes = self.raw().to_bytes();

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

        Ok(())
    }
}

// Note: check against small subgroup attack
impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Ed25519Signature, Self::Error> {
        if bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
            Err(CryptoError::InvalidLengthError)?;
        }

        let dalek_sig = ed25519_dalek::Signature::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidSignatureError)?;

        let sig = Ed25519Signature(dalek_sig);
        sig.is_valid()?;

        Ok(sig)
    }
}

impl Signature for Ed25519Signature {
    type PublicKey = Ed25519PublicKey;

    fn verify(&self, msg: &[u8], pub_key: &Self::PublicKey) -> Result<(), CryptoError> {
        self.is_valid()?;

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

#[cfg(test)]
mod tests {
    use super::{Ed25519Keypair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

    use crate::error::CryptoError;
    use crate::traits::{PrivateKey, PublicKey, Signature};

    use curve25519_dalek::scalar::Scalar;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use rand::rngs::OsRng;

    use std::convert::TryFrom;
    use std::fmt::Debug;
    use std::ops::{Index, IndexMut};

    // from curve25519_dalek/src/backend/serial/u64
    /// `L` is the order of base point, i.e. 2^252 + 27742317777372353535851937790883648493
    const L: Scalar52 = Scalar52([
        0x0002631a5cf5d3ed,
        0x000dea2f79cd6581,
        0x000000000014def9,
        0x0000000000000000,
        0x0000100000000000,
    ]);

    /// The `Scalar52` struct represents an element in
    /// \\(\mathbb Z / \ell \mathbb Z\\) as 5 \\(52\\)-bit limbs.
    #[derive(Copy, Clone)]
    struct Scalar52(pub [u64; 5]);

    impl Debug for Scalar52 {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            write!(f, "Scalar52: {:?}", &self.0[..])
        }
    }

    impl Index<usize> for Scalar52 {
        type Output = u64;
        fn index(&self, _index: usize) -> &u64 {
            &(self.0[_index])
        }
    }

    impl IndexMut<usize> for Scalar52 {
        fn index_mut(&mut self, _index: usize) -> &mut u64 {
            &mut (self.0[_index])
        }
    }

    impl Scalar52 {
        /// Return the zero scalar
        pub fn zero() -> Scalar52 {
            Scalar52([0, 0, 0, 0, 0])
        }

        /// Unpack a 32 byte / 256 bit scalar into 5 52-bit limbs.
        pub fn from_bytes(bytes: &[u8; 32]) -> Scalar52 {
            let mut words = [0u64; 4];
            for i in 0..4 {
                for j in 0..8 {
                    words[i] |= (bytes[(i * 8) + j] as u64) << (j * 8);
                }
            }

            let mask = (1u64 << 52) - 1;
            let top_mask = (1u64 << 48) - 1;
            let mut s = Scalar52::zero();

            s[0] = words[0] & mask;
            s[1] = ((words[0] >> 52) | (words[1] << 12)) & mask;
            s[2] = ((words[1] >> 40) | (words[2] << 24)) & mask;
            s[3] = ((words[2] >> 28) | (words[3] << 36)) & mask;
            s[4] = (words[3] >> 16) & top_mask;

            s
        }

        /// Pack the limbs of this `Scalar52` into 32 bytes
        pub fn to_bytes(&self) -> [u8; 32] {
            let mut s = [0u8; 32];

            s[0] = (self.0[0] >> 0) as u8;
            s[1] = (self.0[0] >> 8) as u8;
            s[2] = (self.0[0] >> 16) as u8;
            s[3] = (self.0[0] >> 24) as u8;
            s[4] = (self.0[0] >> 32) as u8;
            s[5] = (self.0[0] >> 40) as u8;
            s[6] = ((self.0[0] >> 48) | (self.0[1] << 4)) as u8;
            s[7] = (self.0[1] >> 4) as u8;
            s[8] = (self.0[1] >> 12) as u8;
            s[9] = (self.0[1] >> 20) as u8;
            s[10] = (self.0[1] >> 28) as u8;
            s[11] = (self.0[1] >> 36) as u8;
            s[12] = (self.0[1] >> 44) as u8;
            s[13] = (self.0[2] >> 0) as u8;
            s[14] = (self.0[2] >> 8) as u8;
            s[15] = (self.0[2] >> 16) as u8;
            s[16] = (self.0[2] >> 24) as u8;
            s[17] = (self.0[2] >> 32) as u8;
            s[18] = (self.0[2] >> 40) as u8;
            s[19] = ((self.0[2] >> 48) | (self.0[3] << 4)) as u8;
            s[20] = (self.0[3] >> 4) as u8;
            s[21] = (self.0[3] >> 12) as u8;
            s[22] = (self.0[3] >> 20) as u8;
            s[23] = (self.0[3] >> 28) as u8;
            s[24] = (self.0[3] >> 36) as u8;
            s[25] = (self.0[3] >> 44) as u8;
            s[26] = (self.0[4] >> 0) as u8;
            s[27] = (self.0[4] >> 8) as u8;
            s[28] = (self.0[4] >> 16) as u8;
            s[29] = (self.0[4] >> 24) as u8;
            s[30] = (self.0[4] >> 32) as u8;
            s[31] = (self.0[4] >> 40) as u8;

            s
        }

        /// Compute `a + b`
        pub fn add(a: &Scalar52, b: &Scalar52) -> Scalar52 {
            let mut sum = Scalar52::zero();
            let mask = (1u64 << 52) - 1;

            // a + b
            let mut carry: u64 = 0;
            for i in 0..5 {
                carry = a[i] + b[i] + (carry >> 52);
                sum[i] = carry & mask;
            }

            sum
        }
    }

    // to_bytes() from CompressedEdwardsY
    const EIGHT_TORSION: [[u8; 32]; 8] = [
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 128,
        ],
        [
            38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223,
            172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5,
        ],
        [
            236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ],
        [
            38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223,
            172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250,
        ],
    ];

    #[derive(Clone, Debug)]
    struct Octet32([u8; 32]);

    impl AsRef<[u8]> for Octet32 {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Arbitrary for Octet32 {
        fn arbitrary<G: Gen>(g: &mut G) -> Octet32 {
            let mut octet32 = [0u8; 32];

            for i in 0..32 {
                octet32[i] = u8::arbitrary(g);
            }

            Octet32(octet32)
        }
    }

    impl Ed25519Signature {
        fn from_bytes_unchecked(bytes: &[u8]) -> Result<Ed25519Signature, CryptoError> {
            let sig = ed25519_dalek::Signature::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidSignatureError)?;

            Ok(Ed25519Signature(sig))
        }
    }

    #[test]
    fn should_generate_workable_keypair_from_crypto_rng() {
        let mut csprng = OsRng::new().unwrap();
        let keypair = Ed25519Keypair::generate(&mut csprng);

        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let msg: &[u8] = b"the last night";
        let sig = priv_key.sign_message(msg);

        assert!(pub_key.verify_signature(msg, &sig).is_ok());
        assert!(sig.verify(msg, &pub_key).is_ok());
    }

    #[test]
    fn should_result_small_subgroup_error_on_torsion_group() {
        for point_bytes in &EIGHT_TORSION {
            // It's ok in dalek
            assert!(ed25519_dalek::PublicKey::from_bytes(point_bytes).is_ok());

            // Should not pass in our implementation
            assert_eq!(
                Ed25519PublicKey::try_from(point_bytes as &[u8]),
                Err(CryptoError::SmallSubgroupError)
            );
        }
    }

    #[quickcheck]
    fn prop_malleable_signature_should_not_pass(msg: Octet32, priv_key: Octet32) {
        let private_key = Ed25519PrivateKey::try_from(priv_key.as_ref()).unwrap();
        let pub_key = private_key.pub_key();
        let sig = private_key.sign_message(msg.as_ref());

        assert!(sig.verify(msg.as_ref(), &pub_key).is_ok());

        let mut s_bits: [u8; 32] = [0; 32];
        s_bits.copy_from_slice(&sig.to_bytes()[32..]);

        // Verify canoncial bytes
        assert!(Scalar::from_canonical_bytes(s_bits).is_some());

        // Signature is malleable, modify scalar, add base point to crate one
        let scalar52 = {
            let s = Scalar52::from_bytes(&s_bits);
            Scalar52::add(&s, &L)
        };

        let modified_sig_bytes: [u8; 64] = {
            let mut sig_bytes = sig.raw().to_bytes();
            sig_bytes[32..].copy_from_slice(&scalar52.to_bytes());
            sig_bytes
        };

        // Modified signature is able to pass dalek check
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&modified_sig_bytes);
        let dalek_pub_key = pub_key.raw();

        assert!(dalek_sig.is_ok());
        assert!(dalek_pub_key
            .verify(msg.as_ref(), &dalek_sig.unwrap())
            .is_ok());

        // Modified signature should not pass in our implementation
        assert_eq!(
            Ed25519Signature::try_from(&modified_sig_bytes as &[u8]),
            Err(CryptoError::InvalidSignatureError)
        );

        let modified_sig: Ed25519Signature =
            Ed25519Signature::from_bytes_unchecked(&modified_sig_bytes as &[u8]).unwrap();
        assert!(modified_sig.verify(msg.as_ref(), &pub_key).is_err());
    }

    #[quickcheck]
    fn prop_private_key_bytes_serialization(priv_key: Octet32) -> bool {
        let private_key = Ed25519PrivateKey::try_from(priv_key.as_ref()).unwrap();

        ed25519_dalek::SecretKey::from_bytes(private_key.as_bytes()).is_ok()
    }

    #[quickcheck]
    fn prop_public_key_bytes_serialization(priv_key: Octet32) -> bool {
        let private_key = Ed25519PrivateKey::try_from(priv_key.as_ref()).unwrap();
        let pub_key = private_key.pub_key();

        ed25519_dalek::PublicKey::from_bytes(pub_key.as_bytes()).is_ok()
    }

    #[quickcheck]
    fn prop_signature_bytes_serialization(msg: Octet32, priv_key: Octet32) -> bool {
        let private_key = Ed25519PrivateKey::try_from(priv_key.as_ref()).unwrap();
        let sig = private_key.sign_message(msg.as_ref());

        ed25519_dalek::Signature::from_bytes(&sig.to_bytes()).is_ok()
    }

    #[quickcheck]
    fn prop_message_sign_and_verify(msg: Octet32, priv_key: Octet32) -> bool {
        let private_key = Ed25519PrivateKey::try_from(priv_key.as_ref()).unwrap();
        let pub_key = private_key.pub_key();
        let sig = private_key.sign_message(msg.as_ref());

        assert!(sig.verify(msg.as_ref(), &pub_key).is_ok());
        pub_key.raw().verify(msg.as_ref(), sig.raw()).is_ok()
    }
}

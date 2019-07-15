use crate::error::CryptoError;

use std::convert::TryFrom;

pub trait PrivateKey: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type PublicKey;
    type Signature;

    fn sign_message(&self, msg: &[u8]) -> Self::Signature;

    fn pub_key(&self) -> Self::PublicKey;

    fn as_bytes(&self) -> &[u8];
}

pub trait PublicKey: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type Signature;

    fn verify_signature(&self, msg: &[u8], sig: Self::Signature) -> Result<(), CryptoError>;

    fn as_bytes(&self) -> &[u8];
}

pub trait Signature: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type PublicKey;

    fn verify(&self, msg: &[u8], pub_key: &Self::PublicKey) -> Result<(), CryptoError>;

    fn to_bytes(&self) -> Vec<u8>;
}

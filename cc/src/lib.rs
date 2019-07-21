#![feature(const_generics)]

pub mod hash;
pub use hash::Hash;

use std::convert::TryFrom;

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidLength,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    Other(&'static str),
}

pub trait PrivateKey<const LENGTH: usize>: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type PublicKey;
    type Signature;

    fn sign_message(&self, msg: &Hash) -> Self::Signature;

    fn pub_key(&self) -> Self::PublicKey;

    fn to_bytes(&self) -> [u8; LENGTH];
}

pub trait PublicKey<const LENGTH: usize>: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type Signature;

    fn verify_signature(&self, msg: &Hash, sig: &Self::Signature) -> Result<(), CryptoError>;

    fn to_bytes(&self) -> [u8; LENGTH];
}

pub trait Signature<const LENGTH: usize>: for<'a> TryFrom<&'a [u8], Error = CryptoError> {
    type PublicKey;

    fn verify(&self, msg: &Hash, pub_key: &Self::PublicKey) -> Result<(), CryptoError>;

    fn to_bytes(&self) -> [u8; LENGTH];
}

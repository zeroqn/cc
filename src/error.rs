#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidLength,
    SmallSubgroup,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    Other(&'static str),
}

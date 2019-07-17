#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidLengthError,
    SmallSubgroupError,
    InvalidSignatureError,
    InvalidPublicKeyError,
    InvalidPrivateKeyError,
}

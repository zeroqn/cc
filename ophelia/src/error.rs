use std::error::Error;

use derive_more::Display;

#[derive(Debug, Display)]
pub enum CryptoKind {
    #[display(fmt = "signature")]
    Signature,

    #[display(fmt = "private key")]
    PrivateKey,

    #[display(fmt = "public key")]
    PublicKey,

    #[display(fmt = "hash value")]
    HashValue,

    #[display(fmt = "public key set")]
    PublicKeySet,

    #[display(fmt = "private key set")]
    PrivateKeySet,

    #[display(fmt = "public key share")]
    PublicKeyShare,

    #[display(fmt = "private key share")]
    PrivateKeyShare,
}

#[derive(Debug, Display)]
pub enum CryptoError {
    #[display(fmt = "wrong length: expect {}, got {}", expect, got)]
    WrongLength { expect: usize, got: usize },

    #[display(fmt = "invalid {}: {:?}", kind, cause)]
    InvalidValue {
        kind: CryptoKind,
        cause: Option<Box<dyn Error + Send>>,
    },

    #[display(fmt = "unexpected {}", _0)]
    Unexpected(Box<dyn Error + Send>),

    #[display(fmt = "other: {}", _0)]
    Other(&'static str),
}

impl CryptoError {
    pub fn with_cause(self, cause: Box<dyn Error + Send>) -> Self {
        match self {
            Self::InvalidValue { kind, .. } => Self::InvalidValue {
                kind,
                cause: Some(cause),
            },
            _ => self,
        }
    }
}

impl Error for CryptoError {}

impl From<CryptoKind> for CryptoError {
    fn from(kind: CryptoKind) -> CryptoError {
        CryptoError::InvalidValue { kind, cause: None }
    }
}

impl From<ophelia_hasher::WrongLengthError> for CryptoError {
    fn from(err: ophelia_hasher::WrongLengthError) -> CryptoError {
        CryptoError::InvalidValue {
            kind: CryptoKind::HashValue,
            cause: Some(Box::new(err)),
        }
    }
}

use ophelia::CryptoError;

pub fn ensure_length(expect: usize, bytes: &[u8]) -> Result<(), CryptoError> {
    let got = bytes.len();

    if got != expect {
        Err(CryptoError::WrongLength { expect, got })
    } else {
        Ok(())
    }
}

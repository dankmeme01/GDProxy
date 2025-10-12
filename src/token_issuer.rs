use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64e};
use thiserror::Error;

#[derive(Clone)]
pub struct HmacSigner {
    secret_key: [u8; 32],
}

impl HmacSigner {
    pub fn new(secret_key: &str) -> Result<Self, &'static str> {
        let mut authtoken_secret_key = [0u8; 32];
        hex::decode_to_slice(secret_key, &mut authtoken_secret_key)
            .map_err(|_| "invalid secret key format, expected a 256-bit hex string")?;

        Ok(Self {
            secret_key: authtoken_secret_key,
        })
    }

    #[inline]
    pub fn validate(&self, content: &[u8], signature: [u8; 32]) -> bool {
        blake3::keyed_hash(&self.secret_key, content) == blake3::Hash::from_bytes(signature)
    }

    #[inline]
    pub fn sign(&self, content: &[u8]) -> [u8; 32] {
        blake3::keyed_hash(&self.secret_key, content)
            .as_bytes()
            .to_owned()
    }
}

#[derive(Clone)]
pub struct TokenIssuer {
    signer: HmacSigner,
}

#[derive(Clone)]
pub struct TokenData {
    pub id: u64,
}

#[derive(Debug, Error)]
pub enum TokenValidationError {
    #[error("Invalid token format")]
    InvalidFormat,
    #[error("Could not decode base64 in token: {0}")]
    InvalidBase64(#[from] base64::DecodeSliceError),
    #[error("Invalid binary token structure")]
    InvalidBinary,
    #[error("Unsupported token version: {0}")]
    UnsupportedVersion(u8),
    #[error("Username too long")]
    UsernameTooLong,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Account ID mismatch")]
    AccountMismatch,
    #[error("Token revoked")]
    Revoked,
}

impl TokenIssuer {
    pub fn new(secret_key: &str) -> Result<Self, &'static str> {
        Ok(Self {
            signer: HmacSigner::new(secret_key)?,
        })
    }

    pub fn validate(&self, token: &str) -> Result<TokenData, TokenValidationError> {
        let (data, sig) = token
            .split_once('.')
            .ok_or(TokenValidationError::InvalidFormat)?;

        let mut data_buf = [0u8; 8];
        let data_len = b64e.decode_slice(data, &mut data_buf)?;
        let data = &data_buf[..data_len];

        // validate signature
        let mut sig_buf = [0u8; 32];
        if b64e.decode_slice(sig, &mut sig_buf)? != 32 {
            return Err(TokenValidationError::InvalidSignature);
        }

        if !self.signer.validate(data, sig_buf) {
            return Err(TokenValidationError::InvalidSignature);
        }

        // decode the data
        let id = u64::from_be_bytes(data_buf);

        Ok(TokenData { id })
    }

    pub fn generate(&self, id: u64) -> String {
        let buf = id.to_be_bytes();

        // sign the token
        let mut sig_buf = [0u8; 43]; // 32 / 3 * 4 + (32 % 3) + 1 for some reason??
        let sig_len = b64e
            .encode_slice(self.signer.sign(&buf), &mut sig_buf)
            .expect("b64 encoded signature must be exactly 42 bytes long");

        assert_eq!(
            sig_len, 43,
            "b64 encoded signature must be exactly 43 bytes long"
        );

        let mut data_buf = [0u8; 16];
        let data_len = b64e
            .encode_slice(buf, &mut data_buf)
            .expect("b64 encoded data must fit in 512 bytes");

        format!(
            "{}.{}",
            str::from_utf8(&data_buf[..data_len]).expect("data must be valid UTF-8"),
            str::from_utf8(&sig_buf).expect("signature must be valid UTF-8"),
        )
    }
}

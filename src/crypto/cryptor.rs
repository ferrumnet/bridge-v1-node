use crate::{BError, BResult};

#[derive(Clone,Debug)]
pub struct EncryptedData {
    pub key: String,
    pub data: String,
}

impl EncryptedData {
    pub fn from_str(s: &String) -> BResult<EncryptedData> {
        let slice = s.as_str();
        let len_s = &slice[0..16];
        let len = i64::from_str_radix(len_s, 16)
            .map_err(|_| BError::new("Invalid format: Error parsing len"))? as usize;
        // ValidationUtils.isTrue(Number.isFinite(len), 'Invalid data format');
        let key = &slice[16..16+len];
        let data = &slice[16+len..];
        return Ok(EncryptedData{
            key: String::from(key),
            data: String::from(data),
        });
    }

    pub fn to_str(&self) -> String {
        let len = format!("{:0>16x}", self.key.len());
        assert_eq!(len.len(), 16, "Bad formatting for len, or key too large");
        format!("{}{}{}", len, self.key, self.data)
    }
}

pub trait DirectCryptor {
    fn decrypt_to_hex(&self, d: &String, key: &String) -> BResult<String>;
    fn encrypt_hex(&self, raw_data_hex: &String, key: &String) -> BResult<String>;
}

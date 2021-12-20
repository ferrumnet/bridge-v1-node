use crate::BResult;
use crate::crypto::cryptor::{DirectCryptor, EncryptedData};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead, Payload};
use crate::crypto::crypto_utils::{b2h, h2b, keccak256_hash, rand_hex};



pub struct LocalCryptor {
}

impl LocalCryptor {
    pub fn new() -> Self {
        LocalCryptor {}
    }
    #[allow(dead_code)]
    pub fn key_from_pw(owned_pw: String) -> String {
        let pw = &owned_pw;
        assert!(pw.len() >= 20, "PW too short at least 20 characters");
        b2h(&keccak256_hash(&pw.as_bytes()))
    }
    #[allow(dead_code)]
    pub fn raw_str_to_key(txt: &str) -> String {
        let b = format!("PW__{}__PW", txt);
        b2h(keccak256_hash(b.as_bytes()).as_slice())
    }
    pub fn raw_string_to_key(txt: &String) -> String {
        let b = format!("PW__{}__PW", txt);
        b2h(keccak256_hash(b.as_bytes()).as_slice())
    }
}

/**
 Note: everything is hex encoded
**/
impl DirectCryptor for LocalCryptor {
    fn decrypt_to_hex(&self, d: &String, key_hex: &String) -> BResult<String> {
        let key_b = h2b(key_hex);
        let key = Key::from_slice(key_b.as_slice());
        let cipher = Aes256Gcm::new(key);
        let d_key = EncryptedData::from_str(d)?;
        let d_key_key = h2b(&d_key.key);
        let nonce = Nonce::from_slice(d_key_key.as_slice());
        let d_key_data_b = h2b(&d_key.data);
        let payload = Payload::from(d_key_data_b.as_slice());
        let ciphertext = cipher.decrypt(nonce, payload)
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
        Ok(b2h(&ciphertext))
    }

    fn encrypt_hex(&self, raw_data_hex: &String, key_hex: &String) -> BResult<String> {
        let key_b = h2b(key_hex);
        let key = Key::from_slice(key_b.as_slice());
        let cipher = Aes256Gcm::new(key);
        let nonce_s = rand_hex(12);
        let nonce_b = h2b(&nonce_s);
        let nonce = Nonce::from_slice(nonce_b.as_slice());
        let raw_data_b = h2b(raw_data_hex);
        let payload = Payload::from(raw_data_b.as_slice());
        let ciphertext = cipher.encrypt(nonce, payload)
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
        Ok((EncryptedData {
            key: nonce_s.clone(),
            data: b2h(&ciphertext),
        }).to_str())
    }
}
mod test {
    #[allow(unused_imports)]
    use crate::crypto::crypto_utils::{b2h, h2b};
    #[allow(unused_imports)]
    use crate::crypto::cryptor::DirectCryptor;
    #[allow(unused_imports)]
    use crate::crypto::local_cryptor::LocalCryptor;

    # [test]
    fn test_enc_dec() {
        let pw = "My very secure password";
        let msg = "Some text to encrypt";
        let c = LocalCryptor::new();
        println!("PW WILL BE {}", LocalCryptor::raw_str_to_key(&pw));
        let pw_s = String::from("My very secure password22");
        println!("and PW WILL BE {}", LocalCryptor::raw_string_to_key(&pw_s));

        let encrypted = c.encrypt_hex(&b2h(msg.as_bytes()),
                      &LocalCryptor::key_from_pw(String::from(pw)))
            .unwrap_or(String::new());

        let decrypted = c.decrypt_to_hex(
            &encrypted,
            &LocalCryptor::key_from_pw(String::from(pw)))
            .unwrap_or(String::new());
        println!("RAW {}", b2h(msg.as_bytes()));
        println!("DEC {} -> {}", encrypted, &decrypted);
        let dec_txt = String::from_utf8(h2b(&decrypted)).unwrap_or(String::new());
        println!("DEC TXT {}", dec_txt);
        assert_eq!(msg, dec_txt, "Bad bad crypto")
    }
}

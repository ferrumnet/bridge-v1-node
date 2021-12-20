use crate::BResult;
use crate::crypto::crypto_utils::{rand_hex32};
use crate::crypto::cryptor::{DirectCryptor, EncryptedData};

pub trait EnvelopeCryptor {
    fn decrypt_to_hex(&self, d: &EncryptedData, kek: &String) -> BResult<String>;
    fn encrypt_hex(&self, raw_data_hex: &String, kek: &String) -> BResult<EncryptedData>;
}

pub struct EnvelopeCryptorImpl<KC: DirectCryptor, DC: DirectCryptor> {
    key_cryptor: Box<KC>,
    data_cryptor: Box<DC>,
}

impl<KC: DirectCryptor, DC: DirectCryptor> EnvelopeCryptorImpl<KC, DC> {
    pub fn new(key_cryptor: KC, data_cryptor: DC) -> Self {
        EnvelopeCryptorImpl {
            key_cryptor: Box::new(key_cryptor),
            data_cryptor: Box::new(data_cryptor),
        }
    }
}

/**
Note: everything is hex encoded

Envelope cryptor is useful if we use remote or even out of process
encryption service. To avoid sending the data outside, we first, encrypt a key using
the remote cryptor. Then we use the encrypted key to encrypt data locally.
This way the remote cryptor will only know about our keys. So if it gets compromised,
data will not be leacked and we will have the chance to rotate the encryption.

Algo:
key is encrypted
 **/
impl<KC: DirectCryptor, DC: DirectCryptor> EnvelopeCryptor for EnvelopeCryptorImpl<KC, DC> {
    fn decrypt_to_hex(&self, d: &EncryptedData, kek: &String) -> BResult<String> {
        let key = self.key_cryptor.decrypt_to_hex(&d.key, kek)?;
        self.data_cryptor.decrypt_to_hex(&d.data, &key)
    }

    fn encrypt_hex(&self, data_hex: &String, kek: &String) -> BResult<EncryptedData> {
        let key = rand_hex32();
        let enc_key = self.key_cryptor.encrypt_hex(&key, kek)?;
        let enc_data = self.data_cryptor.encrypt_hex(data_hex, &key)?;
        Ok(
            EncryptedData {
                key: enc_key,
                data: enc_data,
            }
        )
    }
}
mod test {
    use crate::crypto::crypto_utils::{b2h, h2b};
    use crate::crypto::envelope_cryptor::{EnvelopeCryptor, EnvelopeCryptorImpl};
    use crate::crypto::local_cryptor::LocalCryptor;

    # [test]
    fn test_enc_dec() {
        let pw = "My very secure password";
        let msg = "Some text to encrypt";
        let k_crypt = LocalCryptor::new();
        let d_crypt = LocalCryptor::new();
        let c = EnvelopeCryptorImpl::new(
            k_crypt,
            d_crypt, );
        let kek = LocalCryptor::key_from_pw(String::from(pw));

        let encrypted = c.encrypt_hex(&b2h(msg.as_bytes()), &kek)
            .ok().expect("Ooo");

        let decrypted = c.decrypt_to_hex(
            &encrypted,
            &kek)
            .ok().expect("Ooops");
        println!("ENC {} - {}", encrypted.key, encrypted.data);
        let dec_txt = String::from_utf8(h2b(&decrypted)).unwrap_or(String::new());
        println!("DEC TXT {}", dec_txt);
        assert_eq!(msg, dec_txt, "Bad bad crypto")
    }
}

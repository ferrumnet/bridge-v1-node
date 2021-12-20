use std::env;
use crate::BResult;
use crate::crypto::cryptor::EncryptedData;
use crate::crypto::envelope_cryptor::EnvelopeCryptor;
use crate::crypto::local_cryptor::LocalCryptor;
use crate::two_fa::two_fa_client::{TwoFaClient};

const PRIVATE_KEY_CLEAR_TEXT: &str = "PRIVATE_KEY_CLEAR_TEXT";

pub trait KeyProvider {
    fn get_sk(&self) -> String;
}

pub struct EnvKeyProvider {
    sk: String,
}

impl EnvKeyProvider {
    pub fn new() -> Self {
        EnvKeyProvider {
            sk: env::var(PRIVATE_KEY_CLEAR_TEXT).expect("PRIVATE_KEY_CLEAR_TEXT required"),
        }
    }
}

impl KeyProvider for EnvKeyProvider {
    fn get_sk(&self) -> String {
        self.sk.clone()
    }
}

pub struct SecureKeyProvider<TFC: TwoFaClient, EC: EnvelopeCryptor> {
    secret: String,
    two_fa_client: Box<TFC>,
    cryptor: Box<EC>,
}

pub struct LiveConfig {
    pub pw: String,
    pub two_fa: String,
}

impl<TFC: TwoFaClient, EC: EnvelopeCryptor> SecureKeyProvider<TFC, EC> {
    pub fn new(
        two_fa_client: TFC,
        cryptor: EC,
    ) -> Self {
        SecureKeyProvider {
            two_fa_client: Box::new(two_fa_client),
            cryptor: Box::new(cryptor),
            secret: String::new(),
        }
    }
    pub async fn init(&mut self, enc_key: &String, two_fa_id: &String, lc: LiveConfig, ) -> BResult<()> {
        let enc = EncryptedData::from_str(&enc_key)?;
        let unwrap1 = self.two_fa_client.decrypt(two_fa_id, &lc.two_fa, &enc).await?;
        let sk = EncryptedData::from_str(&unwrap1)?;

        self.secret = self.cryptor.decrypt_to_hex(
            &sk, &LocalCryptor::raw_string_to_key(&lc.pw))?;
        Ok(())
    }
}

impl <TFC: TwoFaClient, EC: EnvelopeCryptor> KeyProvider for SecureKeyProvider<TFC, EC> {
    fn get_sk(&self) -> String {
        self.secret.clone() // TODO: Update such that secret is never passed
    }
}
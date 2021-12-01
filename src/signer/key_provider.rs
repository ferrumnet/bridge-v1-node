use std::env;

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
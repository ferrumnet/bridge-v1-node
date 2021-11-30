
pub trait KeyProvider {
    fn get_sk(&self) -> String;
}

pub struct EnvKeyProvider {
    sk: String,
}

impl EnvKeyProvider {
    pub fn new() -> Self {
        EnvKeyProvider {
            sk: String::from("HTTP"),
        }
    }
}

impl KeyProvider for EnvKeyProvider {
    fn get_sk(&self) -> String {
        String::from("YO")
    }
}
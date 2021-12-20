use crate::{BError, BResult};
use serde::{Deserialize, Serialize};
use serde_json::{json};
use crate::crypto::cryptor::EncryptedData;
use crate::crypto::hmac::calculate_hmac_auth;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use crate::crypto::envelope_cryptor::EnvelopeCryptor;

#[derive(Serialize, Deserialize)]
struct NewTwoFaResponse {
    two_fa_id: String,
    two_fa: String,
}

#[derive(Serialize, Deserialize)]
pub struct TwoFaWrappedData {
    secret: String,
}

fn req_west_err_map(e: reqwest::Error) -> BError {
    BError::new(
        &format!("Error requesting '{}': {}",
        e.url().map(|u| u.as_str()).unwrap_or(""),
        e.to_string(),
        ))
}

async fn json_rpc<T: DeserializeOwned>(
    url: &String,
    body: &String,
    hmac_public_key: &String,
    hmac_secret_key: &String,
) -> BResult<T> {
    let client = reqwest::Client::new();
    let hmac_header = calculate_hmac_auth(url, body, hmac_public_key, hmac_secret_key);
    let res = client.post(url)
         .body(body.clone())
         .header("X-Authorization", hmac_header)
         .send()
        .await
        .map_err(req_west_err_map)?;
    let j_res: T = res.json()
        .await
        .map_err(req_west_err_map)?;
    Ok(j_res)
}

#[async_trait(?Send)]
pub trait TwoFaClient {
    async fn get_two_fa_wrapped_data(
        &self,
        two_fa_id: &String,
        two_fa: &String,
        data_key_id: &String,
    ) -> BResult<TwoFaWrappedData>;
    async fn decrypt(
        &self,
        two_fa_id: &String,
        two_fa: &String,
        data: &EncryptedData,
    ) -> BResult<String>;
}

pub struct TwoFaClientImpl<EC> {
    cryptor: Box<EC>,
    url: String,
    hmac_public_key: String,
    hmac_private_key: String,
}

impl <EC: EnvelopeCryptor> TwoFaClientImpl<EC> {
    pub fn new(cryptor: EC,
               url: &String, hmac_public_key: &String, hmac_private_key: &String) -> Self {
        TwoFaClientImpl {
            cryptor: Box::new(cryptor),
            hmac_private_key: hmac_private_key.clone(),
            hmac_public_key: hmac_public_key.clone(),
            url: url.clone(),
        }
    }
}

#[async_trait(?Send)]
impl <EC: EnvelopeCryptor> TwoFaClient for TwoFaClientImpl<EC> {
    async fn get_two_fa_wrapped_data(&self,
        two_fa_id: &String,
        two_fa: &String,
        data_key_id: &String,
    ) -> BResult<TwoFaWrappedData> {
        let req = json!({
            "method": "getTwoFaWrappedData",
            "data": {
                "keyId": two_fa_id, "twoFa": two_fa, "dataKeyId": data_key_id
            },
            "params": [],
        });
        Ok(json_rpc(
            &self.url,
            &req.to_string(),
            &self.hmac_public_key,
            &self.hmac_private_key)
            .await?)
    }

    async fn decrypt(
        &self,
        two_fa_id: &String,
        two_fa: &String,
        data: &EncryptedData,
    ) -> BResult<String> {
        let unwrap_data_key = EncryptedData::from_str(&data.data)?;
        let data_key_id = &unwrap_data_key.key;
        let data_data = &unwrap_data_key.data;
        if data_data.len() == 0 {
            return Err(BError::new("Incalid encrypted data format: cannot extract key from data"));
        }
        let wrapper_key = self.get_two_fa_wrapped_data(
            two_fa_id, two_fa, data_key_id).await?;
        self.cryptor.decrypt_to_hex(
            &EncryptedData {
                key: data.key.clone(),
                data: data_data.clone()
            }, &wrapper_key.secret)
    }
}

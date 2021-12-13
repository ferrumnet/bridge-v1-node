use serde::Deserialize;
use serde::__private::Formatter;
use serde_json;
use std::fmt;

#[derive(Clone, Debug)]
pub struct WithdrawItemSignature {
    pub creation_time: i64,
    pub creator: String,
    pub signature: String,
}
impl fmt::Display for WithdrawItemSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "creation_time: {}, creator: {}, signature: {}",
               self.creation_time, self.creator, self.signature)
    }
}

pub struct PayBySig {
    pub source_chain_id: i32,
    pub swap_tx_id: String,
    pub contract_name: String,
    pub contract_version: String,
    pub contract_address: String,
    pub hash: String,
    pub signatures: Vec<WithdrawItemSignature>,
}

pub struct WithdrawItem {
    pub v: i32,
    pub version: String,
    pub receive_network: String,
    pub receive_transaction_id: String,
    pub send_network: String,
    pub pay_by_sig: PayBySig,
    pub signatures: i32,
}

pub struct SignedSwap {
    pub creation_time: i64,
    pub network: String,
    pub transaction_id: String,
    pub msg_hash: String,
    pub signer: String,
    pub signature: String,
}

impl fmt::Display for SignedSwap {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} - {}:{} msg_hash:{}, signer: {}, signature: {}",
            &self.creation_time,
            &self.network,
            &self.transaction_id,
            &self.msg_hash,
            &self.signer,
            &self.signature
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerConfig {
    pub address: String,
    pub validators: Vec<String>,
    pub min_threshold: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbConfig {
    pub connection_string: String,
    pub database: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub signer: SignerConfig,
    pub db: DbConfig,
}

impl AppConfig {
    pub fn from_str(s: &String) -> Self {
        let c: AppConfig = serde_json::from_str(s).expect(&format!("Error parsing: '{}'", &s));
        c
    }
}

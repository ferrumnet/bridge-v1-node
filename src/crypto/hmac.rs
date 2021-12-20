use sha2::Sha256;
use hmac::{Hmac, Mac};
use super::crypto_utils::{b2h, h2b};
use crate::types::utils::now;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/*
 Port of the equivalent js code
 return { key: 'X-Authorization', value: `hmac/${this.publicKey}/${this.timestamp}/${this.hash()}`, }

 	private hash() {
		ValidationUtils.isTrue(!!this.secret, 'secret is required for hmac');
		ValidationUtils.isTrue(!!this.postData, 'postData is required for hmac');
		ValidationUtils.isTrue(!!this.timestamp, 'timestamp is required for hmac');
		return hmac(this.secret!, (this.url || '') + '|' + this.timestamp + '|' + this.postData);
	}

	export function hmac(secret: HexString, dataUtf8: string) {
        const secretWa = encHex.parse(secret);
        const dataWa = encUtf8.parse(dataUtf8);
        const res = HmacSHA256(dataWa, secretWa);
        return res.toString(encHex);
	}

 */

fn hmac(hex_secret: &String, data_utf8: &String) -> String {
    let secret = h2b(hex_secret);
    let data = data_utf8.as_bytes();
    let mut mac = HmacSha256::new_from_slice(secret.as_slice())
        .expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    b2h(code_bytes.as_slice())
}

pub fn auth_hash(
    url: &String,
    body: &String,
    timestamp: &String,
    secret_key: &String,
) -> String {
    hmac(secret_key,
         &format!("{}|{}|{}", url, timestamp, body))
}

pub fn calculate_hmac_auth(
    url: &String,
    body: &String,
    public_key: &String,
    secret_key: &String,
) -> String {
    let timestamp = now().to_string();
    format!("hmac/{}/{}/{}",
        public_key,
        timestamp,
        auth_hash(url, body, &timestamp, secret_key)
    )
}
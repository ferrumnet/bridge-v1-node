mod cli;
mod crypto;
mod database;
mod signer;
mod types;
mod validator;
mod two_fa;
use crate::crypto::crypto_utils::CryptoUtils;
use crate::database::mongo::DatabaseClient;
use crate::signer::key_provider::{EnvKeyProvider, LiveConfig, SecureKeyProvider};
use crate::types::errors::{BError, BResult};
use crate::types::types::AppConfig;
use crate::validator::swap_processor::{Processor, SwapProcessor};
use crate::validator::validator::{MultiSigValidator};
use cli::cli::cli;
use signer::service::SignerServiceImpl;
use std::{fs, io};
use crate::crypto::envelope_cryptor::EnvelopeCryptorImpl;
use crate::crypto::local_cryptor::LocalCryptor;
use crate::two_fa::two_fa_client::TwoFaClientImpl;

// MultiSigSigner. This signer just aggregates signatures for a number of other
// signers. Once enough signatures for a message is provided, we just sign it
// without knowing what the msg represents at all.

async fn setup(c: &AppConfig, live_config: LiveConfig, insecure: bool) -> BResult<Box<dyn Processor>> {
    let cr_f = || CryptoUtils::new();
    let signer = || SignerServiceImpl::new(Box::new(cr_f()));
    let db = DatabaseClient::new(&c.db)
        .await
        .map_err(|_| BError::new("Error initializing db client"))?;
    match insecure {
        true => {
            let kp = EnvKeyProvider::new();
            let v = MultiSigValidator::new(&c.signer, signer(), kp);
            let p = SwapProcessor::new( v, db);
            Ok(Box::new(p))
        },
        false => {
            let double_cryptor = || EnvelopeCryptorImpl::new(
                LocalCryptor::new(), LocalCryptor::new());
            let two_fa_client = TwoFaClientImpl::new(
                double_cryptor(),
                &c.two_fa.url,
                &c.two_fa.hmac_public_key,
                &c.two_fa.hmac_secret_key,);
            let mut skp = SecureKeyProvider::new(
                two_fa_client,
                double_cryptor(), );
            skp.init(&c.enc_key, &c.two_fa.two_fa_id, live_config).await?;
            let v = MultiSigValidator::new(&c.signer, signer(), skp);
            let p = SwapProcessor::new(v, db);
            Ok(Box::new(p))
        },
    }
}

pub fn get_input(prompt: &str) -> String {
    println!();
    print!("{}",prompt);
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_goes_into_input_above) => {},
        Err(_no_updates_is_fine) => {},
    }
    input.trim().to_string()
}

#[tokio::main]
async fn main() {
    let opt = cli();
    let confs = match fs::read_to_string(&opt.config) {
        Ok(c) => AppConfig::from_str(&c),
        Err(e) => {
            println!(
                "Error reading config file {}: {}",
                &opt.config.as_path().to_str().unwrap_or(""),
                e
            );
            return;
        }
    };
    let live_config = match opt.insecure {
        true => LiveConfig {
            two_fa: String::new(),
            pw: String::new()
        },
        false => LiveConfig {
            pw: get_input("Enter Key Password:"),
            two_fa: get_input("Enter Google Authenticator Token:"),
        }
    };
    let psr = setup(&confs, live_config, opt.insecure).await;
    let ps = match psr {
        Ok(p) => p,
        Err(e) => {
            println!("Error setting up the environment: {}", &e.msg);
            return;
        }
    };
    match ps.process_for_network(&opt.network).await {
        Ok(r) => r,
        Err(e) => {
            println!(
                "Error processing for the network: {} - {}",
                &opt.network, e.msg
            );
            return;
        }
    }
}

mod test {
    #[allow(unused_imports)]
    use crate::crypto::crypto_utils::{b2h, h2b, private_to_address, CryptoUtils};
    #[allow(unused_imports)]
    use crate::signer::service::{SignerService, SignerServiceImpl};

    #[test]
    fn zero_x_works() {
        let msg1 = String::from("0x123412341234");
        let msg2 = String::from("123412341234");
        let msg3 = String::from("0X123412341234");
        let h1 = h2b(&msg1);
        let h2 = h2b(&msg2);
        let h3 = h2b(&msg3);
        println!(
            "decoded: '{}' vs '{}' and '{}'",
            b2h(&h1),
            b2h(&h2),
            b2h(&h3)
        );
        assert_eq!(&h1, &h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn test_sign_then_verify() {
        let msg: String =
            String::from("1a15b1ea0d007ed0e4262248d3406e310474b14bb6434266a5f941eaf86081ce");
        let sk: String =
            String::from("915c8bf73c84c0482beef48bb4bf782892d38d57d3c9af32de6af27a54d12c5a");
        let address: String = b2h(&private_to_address(&h2b(&sk)));
        println!("Using address: {}", &address);

        let cr_f = || CryptoUtils::new();
        let signer = SignerServiceImpl::new(Box::new(cr_f()));
        let signed = signer.sign(&msg, &sk);

        println!("Signed message: {}", &signed);
        let verif_addr = signer.recover(&msg, &signed);
        println!("Verified address is: {}", &verif_addr);
    }
}

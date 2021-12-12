use crate::crypto::crypto_utils::{b2h, h2b, CryptoUtils};

pub trait SignerService {
    fn sign(&self, msg: &String, sk: &String) -> String;
    fn recover(&self, msg: &String, sig: &String) -> String;
}

pub struct SignerServiceImpl {
    cr: Box<CryptoUtils>,
}

impl SignerServiceImpl {
    pub fn new(cr: Box<CryptoUtils>) -> Self {
        return SignerServiceImpl { cr };
    }
}

impl SignerService for SignerServiceImpl {
    fn sign(&self, msg: &String, sk: &String) -> String {
        let h = h2b(msg);
        let sig = self.cr.sign(h.as_slice(), h2b(sk).as_slice());
        b2h(sig.as_slice())
    }

    fn recover(&self, msg: &String, sig: &String) -> String {
        let h = h2b(msg);
        let sig_v = h2b(sig);
        let address = self.cr.recover(&h, &sig_v);
        b2h(&address)
    }
}

use crate::crypto::crypto_utils::{b2h, h2b, CryptoUtils};

pub trait SignerService {
    fn sign(&self, msg: &String, sk: &String) -> String;
    fn recover(&self, msg: &String, sig: &String) -> String;
}

pub struct SignerServiceImpl {
    cr: Box<CryptoUtils>,
}

fn v_to_standard(sig: &String) -> String {
    let mut trimmed = sig.chars();
    trimmed.by_ref().nth(sig.len() - 3); // Move to the last two char position
    let suffix = trimmed.as_str();
    if suffix.eq("1b") {
        let mut rv = sig.clone();
        rv.pop(); rv.pop();
        rv.push('0'); rv.push('0');
        rv
    } else if suffix.eq("1c") {
        let mut rv = sig.clone();
        rv.pop(); rv.pop();
        rv.push('0'); rv.push('1');
        rv
    } else {
        sig.to_owned()
    }
}

fn v_to_smart_contract(sig: &String) -> String {
    let mut trimmed = sig.chars();
    trimmed.by_ref().nth(sig.len() - 3); // Move to the last two char position
    let suffix = trimmed.as_str();
    if suffix.eq("00") {
        let mut rv = sig.clone();
        rv.pop(); rv.pop();
        rv.push('1'); rv.push('b');
        rv
    } else if suffix.eq("01") {
        let mut rv = sig.clone();
        rv.pop(); rv.pop();
        rv.push('1'); rv.push('c');
        rv
    } else {
        sig.to_owned()
    }
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
        v_to_smart_contract(&b2h(sig.as_slice()))
    }

    fn recover(&self, msg: &String, sig: &String) -> String {
        let h = h2b(msg);
        let sig_v = h2b(&v_to_standard(sig));
        let address = self.cr.recover(&h, &sig_v);
        format!("0x{}", b2h(&address))
    }
}

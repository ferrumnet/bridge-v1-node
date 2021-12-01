use std::time::SystemTime;

pub fn now() -> i64 {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap().as_millis();
    millis as i64
}


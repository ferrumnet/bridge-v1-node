pub struct BError {
    pub msg: String,
}

impl BError {
    pub fn new(msg: &str) -> Self {
        BError {
            msg: String::from(msg),
        }
    }
}

pub type BResult<T> = Result<T, BError>;

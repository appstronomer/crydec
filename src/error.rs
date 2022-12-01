#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Aead(aead::Error),
    Arg(String),
    Hash(argon2::Error),
    Spec(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "io: {}", err),
            Error::Aead(err) => write!(f, "cipher algorithm: {}", err),
            Error::Arg(err) => write!(f, "argument: {}", err),
            Error::Hash(err) => write!(f, "hash argon2: {}", err),
            Error::Spec(err) => write!(f, "spec: {}", err),
        }   
    }
}

impl Error {
    pub fn make_io(err: std::io::Error) -> Self { Self::Io(err) }
    pub fn make_aead(err: aead::Error) -> Self { Self::Aead(err) }
    pub fn make_arg(err: impl ToString) -> Self { Self::Arg(err.to_string()) }
    pub fn make_hash(err: argon2::Error) -> Self { Self::Hash(err) }
    pub fn make_spec(err: impl ToString) -> Self { Self::Spec(err.to_string()) }
}

impl std::error::Error for Error {}

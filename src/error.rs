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
            Error::Io(err) => write!(f, "io error: {}", err),
            Error::Aead(err) => write!(f, "cipher algorithm error: {}", err),
            Error::Arg(err) => write!(f, "argument error: {}", err),
            Error::Hash(err) => write!(f, "hash argon2 error: {}", err),
            Error::Spec(err) => write!(f, "spec error: {}", err),
        }   
    }
}

impl std::error::Error for Error {}

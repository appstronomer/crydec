use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::error::Error;

#[derive(Parser, Debug)]
#[command(about, version, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt data from stdin or file (--fin) to stdout or file (--fout)
    Encrypt(Encrypt),
    /// Decrypt data from stdin or file (--fin) to stdout or file (--fout)
    Decrypt(Decrypt),
}


#[derive(Args, Debug)]
pub struct Encrypt {
    #[clap(flatten)]
    pub io: Io,
    /// password as cli argument
    #[arg(long)]
    pub pwd: Option<String>,
    #[clap(flatten)]
    pub spec: Spec,
}


#[derive(Args, Debug)]
pub struct Decrypt {
    #[clap(flatten)]
    pub io: Io,
    /// password as cli argument
    #[arg(long)]
    pub pwd: Option<String>,
}

#[derive(Args, Debug)]
pub struct Io {
    /// use file as input instead of stdin
    #[arg(long)]
    pub fin: Option<PathBuf>,
    /// use file as output instead of stdout
    #[arg(long)]
    pub fout: Option<PathBuf>,
    /// use file as storage for salt, nonce, cypher type, hash type, etc.
    #[arg(long)]
    pub fspec: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct Spec {
    /// salt as cli argument, used as utf-8 string bytes
    #[arg(long)]
    pub salt: Option<String>,
    /// salt as tty input, used as utf-8 string bytes
    #[arg(long)]
    pub salt_tty: bool,
    /// nonce as cli argument, used as utf-8 string bytes
    #[arg(long)]
    pub nonce: Option<String>,
    /// nonce as tty input, used as utf-8 string bytes
    #[arg(long)]
    pub nonce_tty: bool, 
    #[arg(long, value_enum, default_value_t=Cipher::XChacha20Poly1305)]
    pub cipher: Cipher,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Cipher {
    XChacha20Poly1305,
    Chacha20Poly1305,
    Aes256Gcm,
    Aes128Gcm,
}
impl Cipher {
    /// Returns cipher type by type_id
    pub fn from_type_id(type_id: u8) -> Result<Self, Error> {
        let res = match type_id {
            0 => Self::XChacha20Poly1305,
            1 => Self::Chacha20Poly1305,
            2 => Self::Aes256Gcm,
            3 => Self::Aes128Gcm,
            _ => return Err(Error::Spec("unable to define cipher type".to_string())),
        };
        Ok(res)
    }

    /// Returns (type_id, key_size, nonce_size) 
    pub fn get_spec(&self) -> (u8, u32, usize) {
        match self {
            Cipher::XChacha20Poly1305 => (0, 32, 24),
            Cipher::Chacha20Poly1305 => (1, 32, 12),
            Cipher::Aes256Gcm => (2, 32, 12),
            Cipher::Aes128Gcm => (3, 16, 12),
        }
    }
}
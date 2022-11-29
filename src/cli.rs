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
    pub io: CfgIo,
    #[arg(long, value_enum, default_value_t=Cipher::XChacha20Poly1305)]
    pub cipher: Cipher,
    #[clap(flatten)]
    pub hash: CfgHash,
    #[clap(flatten)]
    pub rand: CfgRand,
    /// (insecure) password as cli argument
    #[arg(long)]
    pub pwd_cli: Option<String>,
}


#[derive(Args, Debug)]
pub struct Decrypt {
    #[clap(flatten)]
    pub io: CfgIo,
    /// (insecure) password as cli argument
    #[arg(long)]
    pub pwd_cli: Option<String>,
}


#[derive(Args, Debug)]
pub struct CfgIo {
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
pub struct CfgHash {
    #[arg(long, value_enum, default_value_t=ArgonVariant::Argon2id)]
    pub hash_var: ArgonVariant,
    #[arg(long, value_enum, default_value_t=ArgonVersion::Ver13)]
    pub hash_ver: ArgonVersion,
    /// argon2 degree of parallelism
    #[arg(long, default_value_t=4)]
    pub lanes: u32,
    /// argon2 memory cost in kibibytes
    #[arg(long, default_value_t=2 * 1024 * 1024)]
    pub memory: u32,
    /// argon2 number of rounds to use
    #[arg(long, default_value_t=1)]
    pub time: u32,
}


#[derive(Args, Debug)]
pub struct CfgRand {
    /// (insecure) salt as cli argument, used as utf-8 string bytes
    #[arg(long)]
    pub salt_cli: Option<String>,
    /// salt as tty input, used as utf-8 string bytes
    #[arg(long)]
    pub salt: bool,
    /// (insecure) nonce as cli argument, used as utf-8 string bytes
    #[arg(long)]
    pub nonce_cli: Option<String>,
    /// nonce as tty input, used as utf-8 string bytes
    #[arg(long)]
    pub nonce: bool, 
}


#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum ArgonVariant {
    Argon2i,
    Argon2d,
    Argon2id,
}

impl ArgonVariant {
    pub fn from_type_id(type_id: u8) -> Result<Self, Error> {
        let res = match type_id {
            0 => Self::Argon2i,
            1 => Self::Argon2d,
            2 => Self::Argon2id,
            _ => return Err(Error::Spec("unable to define hash variant".to_string())),
        };
        Ok(res)
    }

    pub fn get_type_id(&self) -> u8 {
        match self {
            Self::Argon2i => 0,
            Self::Argon2d => 1,
            Self::Argon2id => 2,
        }
    }
}


#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum ArgonVersion {
    Ver10,
    Ver13,
}

impl ArgonVersion {
    pub fn from_type_id(type_id: u8) -> Result<Self, Error> {
        let res = match type_id {
            0 => Self::Ver10,
            1 => Self::Ver13,
            _ => return Err(Error::Spec("unable to define hash version".to_string())),
        };
        Ok(res)
    }

    pub fn get_type_id(&self) -> u8 {
        match self {
            Self::Ver10 => 0,
            Self::Ver13 => 1,
        }
    }
}


#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Cipher {
    XChacha20Poly1305,
    XChacha12Poly1305,
    XChacha8Poly1305,
    Chacha20Poly1305,
    Chacha12Poly1305,
    Chacha8Poly1305,
    Aes256Gcm,
    Aes128Gcm,
}

impl Cipher {
    /// Returns cipher type by type_id
    pub fn from_type_id(type_id: u8) -> Result<Self, Error> {
        let res = match type_id {
            0 => Self::XChacha20Poly1305,
            1 => Self::XChacha12Poly1305,
            2 => Self::XChacha8Poly1305,
            3 => Self::Chacha20Poly1305,
            4 => Self::Chacha12Poly1305,
            5 => Self::Chacha8Poly1305,
            6 => Self::Aes256Gcm,
            7 => Self::Aes128Gcm,
            _ => return Err(Error::Spec("unable to define cipher type".to_string())),
        };
        Ok(res)
    }

    /// Returns (type_id, key_size, nonce_size) 
    pub fn get_spec(&self) -> (u8, u32, usize) {
        match self {
            Self::XChacha20Poly1305 => (0, 32, 24),
            Self::XChacha12Poly1305 => (1, 32, 24),
            Self::XChacha8Poly1305 => (2, 32, 24),
            Self::Chacha20Poly1305 => (3, 32, 12),
            Self::Chacha12Poly1305 => (4, 32, 12),
            Self::Chacha8Poly1305 => (5, 32, 12),
            Self::Aes256Gcm => (6, 32, 12),
            Self::Aes128Gcm => (7, 16, 12),
        }
    }
}
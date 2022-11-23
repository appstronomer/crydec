use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    #[clap(flatten)]
    pub common: Common,
}


#[derive(Args, Debug)]
pub struct Decrypt {
    #[clap(flatten)]
    pub io: Io,
    #[clap(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct Io {
    /// use file as input instead of stdin
    #[arg(long)]
    pub fin: Option<PathBuf>,
    /// use file as output instead of stdout
    #[arg(long)]
    pub fout: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct Common {
    /// password as cli argument
    #[arg(long)]
    pub pwd: Option<String>,
    /// salt as cli argument, used as utf-8 string bytes, not storred to ciphertext
    #[arg(long)]
    pub salt: Option<String>,
    /// salt as tty input, used as utf-8 string bytes, not storred to ciphertext
    #[arg(long)]
    pub salt_tty: bool,
    /// nonce as cli argument, used as utf-8 string bytes, not storred to ciphertext
    #[arg(long)]
    pub nonce: Option<String>,
    /// nonce as tty input, used as utf-8 string bytes, not storred to ciphertext
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

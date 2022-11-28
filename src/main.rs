mod cipher;
mod io;
mod error;
mod cli;
mod command;
mod hash;

use std::io::Write;

use clap::Parser;

use cli::{Cli, Commands};


fn main() {
    let cli = Cli::parse();
    let res = match cli.command {
        Commands::Encrypt(cfg) => command::encrypt(cfg.cipher, cfg.io, cfg.pwd_cli, cfg.hash, cfg.rand),
        Commands::Decrypt(cfg) => command::decrypt(cfg.io, cfg.pwd_cli),
    };
    if let Err(err) = res {
        let _ = writeln!(&mut std::io::stderr(), "ERROR: {}", err);
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}

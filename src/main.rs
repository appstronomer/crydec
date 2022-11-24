mod cipher;
mod io;
mod error;
mod cli;
mod command;
mod hash;

use clap::Parser;
use error::Error;

use cli::{Cli, Commands};


fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt(params) => command::encrypt(params.io, params.pwd, params.spec),
        Commands::Decrypt(params) => command::decrypt(params.io, params.pwd),
    }
}

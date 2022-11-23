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
        Commands::Encrypt(params) => {
            let (input, output) = io::make_inout(params.io.fin, params.io.fout)?;
            command::encrypt(params.common, input, output)?;
        },
        Commands::Decrypt(params) => {
            let (input, output) = io::make_inout(params.io.fin, params.io.fout)?;
            command::decrypt(params.common, input, output)?;
        }
    }
    Ok(())
}

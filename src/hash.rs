use argon2::{Config, Variant, Version, ThreadMode};
use zeroize::Zeroizing;

use crate::{
    error::Error,
    cli::{CfgHash},
};


pub fn make_key(cfg: &CfgHash, password: &str, salt: &[u8], key_size: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
    let version = match cfg.hash_ver {
        crate::cli::ArgonVersion::Ver10 => Version::Version10,
        crate::cli::ArgonVersion::Ver13 => Version::Version13,
    };
    let variant = match cfg.hash_var {
        crate::cli::ArgonVariant::Argon2id => Variant::Argon2id,
        crate::cli::ArgonVariant::Argon2i => Variant::Argon2i,
        crate::cli::ArgonVariant::Argon2d => Variant::Argon2d,
    };
    let config = Config {
        version,
        variant,
        hash_length: key_size,
        lanes: cfg.lanes,
        mem_cost: cfg.memory,
        time_cost: cfg.time,
        thread_mode: ThreadMode::Parallel,
        ..Default::default()
    };
    let hash = argon2::hash_raw(password.as_bytes(), salt, &config).map_err(Error::make_hash)?;
    Ok(Zeroizing::new(hash))
}

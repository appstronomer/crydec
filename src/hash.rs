use argon2::{Config};
use zeroize::Zeroizing;

use crate::error::Error;

pub fn make_key(password: &str, salt: &[u8], key_size: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
    let config = Config {
        variant: argon2::Variant::Argon2id,
        hash_length: key_size,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
    let hash = argon2::hash_raw(password.as_bytes(), salt, &config).map_err(|err|Error::Hash(err))?;
    Ok(Zeroizing::new(hash))
}

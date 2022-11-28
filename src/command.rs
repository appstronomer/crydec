use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

use crate::{
    hash::make_key,
    cipher,
    cli::{CfgRand, CfgIo, Cipher as CipherType, CfgHash, ArgonVariant, ArgonVersion, Cipher},
    io::{Input, Output, extract_pwd, extract_salt, extract_nonce, make_inout},
    error::Error,
};


pub fn encrypt(cipher: Cipher, cfg_io: CfgIo, cfg_pwd: Option<String>, cfg_hash: CfgHash, cfg_rand: CfgRand) -> Result<(), Error> {
    // IO preparing: input stream, output stream, spec stream
    let (mut input, mut output) = make_inout(cfg_io.fin, cfg_io.fout)?;
    let mut spec_file: Output;
    let spec = if let Some(path) = cfg_io.fspec {
        spec_file = Output::from_fpath(path)?;
        &mut spec_file
    } else {
        &mut output
    };

    // Salt preparing
    let mut salt = Zeroizing::new([0u8; 32]);
    if let None = extract_salt(&mut salt, cfg_rand.salt_cli, cfg_rand.salt)? {
        OsRng.fill_bytes( salt.as_mut());
    }
    
    let (cipher_id, key_size, mut nonce_size) = cipher.get_spec();
    nonce_size -= 5; // AEAD requires 5 bytes of nonce to operate

    // Password preparing
    let password = extract_pwd(cfg_pwd)?;

    // Key preparing
    let key = make_key(&cfg_hash, &password, salt.as_ref(), key_size)?;

    spec.write_u8(cfg_hash.hash_var.get_type_id())?;
    spec.write_u8(cfg_hash.hash_ver.get_type_id())?;
    spec.write_u32(cfg_hash.lanes)?;
    spec.write_u32(cfg_hash.memory)?;
    spec.write_u32(cfg_hash.time)?;
    spec.write(salt.as_ref())?;

    // Nonce preparing
    let mut nonce_arr = Zeroizing::new([0u8; 19]);
    let nonce = if let Some(nonce_slice) = extract_nonce(&mut nonce_arr, nonce_size, cfg_rand.nonce_cli, cfg_rand.nonce)? {
        nonce_slice
    } else {
        let nonce_slice = &mut nonce_arr[..nonce_size];
        OsRng.fill_bytes(nonce_slice);
        nonce_slice
    };

    spec.write_u8(cipher_id)?;
    spec.write(nonce)?;

    cipher::encrypt(cipher, &key[..], nonce, &mut input, &mut output)?;

    Ok(())
    
}


pub fn decrypt(cfg_io: CfgIo, cfg_pwd: Option<String>) -> Result<(), Error> {
    // IO preparing: input stream, output stream, spec stream
    let (mut input, mut output) = make_inout(cfg_io.fin, cfg_io.fout)?;
    let mut spec_file: Input;
    let spec = if let Some(path) = cfg_io.fspec {
        spec_file = Input::from_fpath(path)?;
        &mut spec_file
    } else {
        &mut input
    };

    let hash_variant = ArgonVariant::from_type_id( spec.read_u8()? )?;
    let hash_version = ArgonVersion::from_type_id( spec.read_u8()? )?;
    let hash_lanes = spec.read_u32()?;
    let hash_memory = spec.read_u32()?;
    let hash_time = spec.read_u32()?;

    let cfg_hash = CfgHash {
        hash_var: hash_variant,
        hash_ver: hash_version,
        lanes: hash_lanes,
        memory: hash_memory,
        time: hash_time,
    };

    // Salt preparing
    let mut salt = Zeroizing::new([0u8; 32]);
    spec.read_exact(salt.as_mut())?;

    let cipher_type = CipherType::from_type_id( spec.read_u8()? )?;
    let (_, key_size, mut nonce_size) = cipher_type.get_spec();
    nonce_size -= 5; // AEAD requires 5 bytes of nonce to operate

    // Nonce preparing
    let mut nonce_arr = Zeroizing::new([0u8; 19]);
    let nonce = {
        let nonce_slice = &mut nonce_arr[..nonce_size];
        spec.read_exact(nonce_slice)?;
        nonce_slice
    };

    // Password preparing
    let password = extract_pwd(cfg_pwd)?;

    // Key preparing
    let key = make_key(&cfg_hash, &password, salt.as_ref(), key_size)?;

    cipher::decrypt(cipher_type, &key[..], nonce, &mut input, &mut output)?;

    Ok(())
}

use std::fs::File;

use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

use crate::{
    hash::make_key,
    cipher,
    cli::{CfgRand, CfgIo, Cipher as CipherType, CfgHash, ArgonVariant, ArgonVersion, Cipher},
    io::{Input, Output, make_inout, make_control},
    error::Error,
};


pub fn encrypt(cipher: Cipher, cfg_io: CfgIo, cfg_pwd: Option<String>, cfg_hash: CfgHash, cfg_rand: CfgRand) -> Result<(), Error> {
    // IO preparing: input stream, output stream, spec stream
    let (mut input, mut output) = make_inout(cfg_io.fin, cfg_io.fout)?;
    let mut spec_stream: Output;
    let spec = if let Some(path) = cfg_io.fspec {
        spec_stream = Output::new( Box::new( File::create(path).map_err(Error::make_io)? ) );
        &mut spec_stream
    } else {
        &mut output
    };

    // Control to extract some arguments
    let ctrl = make_control();

    // Have to wait for first data before any TTY input to implement multiple encryption using unix pipes
    let mut buf = [0u8; cipher::BUFFER_LEN_ENC];
    let nread = input.read(&mut buf)?;

    // Password preparing
    let password = ctrl.prompt("password", cfg_pwd)?;

    // Salt preparing
    let mut salt = Zeroizing::new([0u8; 32]);
    if let None = ctrl.extract("salt", &mut salt[..], cfg_rand.salt_cli, cfg_rand.salt)? {
        OsRng.fill_bytes( salt.as_mut());
    }
    
    let (cipher_id, key_size, mut nonce_size) = cipher.get_spec();
    nonce_size -= 5; // AEAD requires 5 bytes of nonce to operate

    // Nonce preparing
    let mut nonce_arr = Zeroizing::new([0u8; 19]);
    let nonce = &mut nonce_arr[..nonce_size];
    if let None = ctrl.extract("nonce", nonce, cfg_rand.nonce_cli, cfg_rand.nonce)? {
        OsRng.fill_bytes(nonce);
    }

    // Key preparing
    let key = make_key(&cfg_hash, &password, salt.as_ref(), key_size)?;

    spec.write_u8(cfg_hash.hash_var.get_type_id())?;
    spec.write_u8(cfg_hash.hash_ver.get_type_id())?;
    spec.write_u32(cfg_hash.lanes)?;
    spec.write_u32(cfg_hash.memory)?;
    spec.write_u32(cfg_hash.time)?;
    spec.write(salt.as_ref())?;

    spec.write_u8(cipher_id)?;
    spec.write(nonce)?;

    cipher::encrypt(cipher, &key[..], nonce, &mut input, &mut output, buf, nread)?;

    Ok(())
    
}


pub fn decrypt(cfg_io: CfgIo, cfg_pwd: Option<String>) -> Result<(), Error> {
    // IO preparing: input stream, output stream, spec stream
    let (mut input, mut output) = make_inout(cfg_io.fin, cfg_io.fout)?;
    let mut spec_stream: Input;
    let spec = if let Some(path) = cfg_io.fspec {
        spec_stream = Input::new( Box::new( File::open(path).map_err(Error::make_io)? ) );
        &mut spec_stream
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

    // Have to wait for first data before any TTY input to implement multiple encryption using unix pipes
    let mut buf = [0u8; cipher::BUFFER_LEN_DEC];
    let nread = input.read(&mut buf)?;

    // Control to extract password
    let ctrl = make_control();

    // Password preparing
    let password = ctrl.prompt("password", cfg_pwd)?;

    // Key preparing
    let key = make_key(&cfg_hash, &password, salt.as_ref(), key_size)?;

    cipher::decrypt(cipher_type, &key[..], nonce, &mut input, &mut output, buf, nread)?;

    Ok(())
}

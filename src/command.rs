use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

use crate::{
    hash::make_key,
    cipher,
    cli::Common as CommonParams,
    io::{Input, Output, extract_pwd, extract_salt, extract_nonce},
    error::Error,
};


pub fn encrypt(common: CommonParams, mut input: Input, mut output: Output) -> Result<(), Error> {
    let (key_size, mut nonce_size) = cipher::get_spec(&common.cipher);
    // TODO: checked sub?
    nonce_size -= 5; // AEAD requires 5 bytes of nonce to operate

    // Salt preparing
    let mut salt = Zeroizing::new([0u8; 32]);
    if let None = extract_salt(&mut salt, common.salt, common.salt_tty)? {
        OsRng.fill_bytes( salt.as_mut());
        output.write(salt.as_ref())?;
    }

    // Nonce preparing
    let mut nonce_arr = Zeroizing::new([0u8; 19]);
    let nonce = if let Some(nonce_slice) = extract_nonce(&mut nonce_arr, nonce_size, common.nonce, common.salt_tty)? {
        nonce_slice
    } else {
        let nonce_slice = &mut nonce_arr[..nonce_size];
        OsRng.fill_bytes(nonce_slice);
        output.write(nonce_slice)?;
        nonce_slice
    };

    // Password preparing
    let password = extract_pwd(common.pwd)?;

    // Key preparing
    let key = make_key(&password, salt.as_ref(), key_size)?;

    cipher::encrypt(common.cipher, &key[..], nonce, &mut input, &mut output)?;

    Ok(())
    
}


pub fn decrypt(common: CommonParams, mut input: Input, mut output: Output) -> Result<(), Error> {
    let (key_size, mut nonce_size) = cipher::get_spec(&common.cipher);
    // TODO: checked sub?
    nonce_size -= 5; // AEAD requires 5 bytes of nonce to operate

    // Salt preparing
    let mut salt = Zeroizing::new([0u8; 32]);
    if let None = extract_salt(&mut salt, common.salt, common.salt_tty)? {
        let count = input.read(salt.as_mut())?;
        if count != salt.len() {
            return Err(Error::Spec("unable to read salt".to_string()));
        }
    }

    // Nonce preparing
    let mut nonce_arr = Zeroizing::new([0u8; 19]);
    let nonce = if let Some(nonce_slice) = extract_nonce(&mut nonce_arr, nonce_size, common.nonce, common.salt_tty)? {
        nonce_slice
    } else {
        let nonce_slice = &mut nonce_arr[..nonce_size];
        let count = input.read(nonce_slice)?;
        if count != nonce_slice.len() {
            return Err(Error::Spec("unable to read nonce".to_string()));
        }
        nonce_slice
    };

    // Password preparing
    let password = extract_pwd(common.pwd)?;

    // Key preparing
    let key = make_key(&password, salt.as_ref(), key_size)?;

    cipher::decrypt(common.cipher, &key[..], nonce, &mut input, &mut output)?;

    Ok(())
}
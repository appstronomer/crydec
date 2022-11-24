use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

use crate::{
    hash::make_key,
    cipher,
    cli::{Spec as ParamsSpec, Io as ParamsIo, Cipher as CipherType},
    io::{Input, Output, extract_pwd, extract_salt, extract_nonce, make_inout},
    error::Error,
};


pub fn encrypt(params_io: ParamsIo, params_pwd: Option<String>, params_spec: ParamsSpec) -> Result<(), Error> {
    // IO preparing: input stream, output stream, spec stream
    let (mut input, mut output) = make_inout(params_io.fin, params_io.fout)?;
    let mut spec_file: Output;
    let spec = if let Some(path) = params_io.fspec {
        spec_file = Output::from_fpath(path)?;
        &mut spec_file
    } else {
        &mut output
    };

    let (cipher_id, key_size, mut nonce_size) = params_spec.cipher.get_spec();
    nonce_size -= 5; // AEAD requires 5 bytes of nonce to operate
    spec.write(&[cipher_id])?;

    // Salt preparing
    let mut salt = Zeroizing::new([0u8; 32]);
    if let None = extract_salt(&mut salt, params_spec.salt, params_spec.salt_tty)? {
        OsRng.fill_bytes( salt.as_mut());
    }
    spec.write(salt.as_ref())?;

    // Nonce preparing
    let mut nonce_arr = Zeroizing::new([0u8; 19]);
    let nonce = if let Some(nonce_slice) = extract_nonce(&mut nonce_arr, nonce_size, params_spec.nonce, params_spec.salt_tty)? {
        nonce_slice
    } else {
        let nonce_slice = &mut nonce_arr[..nonce_size];
        OsRng.fill_bytes(nonce_slice);
        nonce_slice
    };
    spec.write(nonce)?;

    // Password preparing
    let password = extract_pwd(params_pwd)?;

    // Key preparing
    let key = make_key(&password, salt.as_ref(), key_size)?;

    cipher::encrypt(params_spec.cipher, &key[..], nonce, &mut input, &mut output)?;

    Ok(())
    
}


pub fn decrypt(params_io: ParamsIo, params_pwd: Option<String>) -> Result<(), Error> {
    // IO preparing: input stream, output stream, spec stream
    let (mut input, mut output) = make_inout(params_io.fin, params_io.fout)?;
    let mut spec_file: Input;
    let spec = if let Some(path) = params_io.fspec {
        spec_file = Input::from_fpath(path)?;
        &mut spec_file
    } else {
        &mut input
    };

    // CipherType, key_size AND nonce_size retrieving 
    let cipher_type: CipherType;
    let (_, key_size, mut nonce_size) = {
        let mut cipher_id_arr = [0u8; 1];
        let count = spec.read(&mut cipher_id_arr)?;
        if count != 1 {
            return Err(Error::Spec("unable to read cipher type".to_string()));
        }
        cipher_type = CipherType::from_type_id(cipher_id_arr[0])?;
        cipher_type.get_spec()
    };
    nonce_size -= 5; // AEAD requires 5 bytes of nonce to operate

    // Salt preparing
    let mut salt = Zeroizing::new([0u8; 32]);
    let count = spec.read(salt.as_mut())?;
    if count != salt.len() {
        return Err(Error::Spec("unable to read salt".to_string()));
    }

    // Nonce preparing
    let mut nonce_arr = Zeroizing::new([0u8; 19]);
    let nonce = {
        let nonce_slice = &mut nonce_arr[..nonce_size];
        let count = spec.read(nonce_slice)?;
        if count != nonce_slice.len() {
            return Err(Error::Spec("unable to read nonce".to_string()));
        }
        nonce_slice
    };

    // Password preparing
    let password = extract_pwd(params_pwd)?;

    // Key preparing
    let key = make_key(&password, salt.as_ref(), key_size)?;

    cipher::decrypt(cipher_type, &key[..], nonce, &mut input, &mut output)?;

    Ok(())
}

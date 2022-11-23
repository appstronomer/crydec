use std::ops::Sub;

use aead::{
    KeyInit, AeadInPlace, AeadCore,
    stream::{EncryptorBE32, DecryptorBE32}, 
    generic_array::{typenum::U5, ArrayLength},
};
use aes_gcm::{Aes256Gcm, Aes128Gcm};
use chacha20poly1305::{XChaCha20Poly1305, ChaCha20Poly1305};

pub use crate::{
    cli::Cipher as CipherType,
    error::Error,
    io::{Input, Output},
};


const BUFFER_LEN_ENC: usize = 500;
const BUFFER_LEN_DEC: usize =  BUFFER_LEN_ENC + 16;


/// Returns key size and nonce cize for any supported cipher type
pub fn get_spec(cipher: &CipherType) -> (u32, usize) {
    match cipher {
        CipherType::XChacha20Poly1305 => (32, 24),
        CipherType::Chacha20Poly1305 => (32, 12),
        CipherType::Aes256Gcm => (32, 12),
        CipherType::Aes128Gcm => (16, 12),
    }
}


pub fn encrypt(cipher_type: CipherType, key: &[u8], nonce: &[u8], src: &mut Input, dst: &mut Output) -> Result<(), Error> {
    // TODO: catch panic!
    match cipher_type {
        CipherType::XChacha20Poly1305 => {
            let aead = XChaCha20Poly1305::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst)?;
        },
        CipherType::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst)?;
        },
        CipherType::Aes256Gcm => {
            let aead = Aes256Gcm::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst)?;
        },
        CipherType::Aes128Gcm => {
            let aead = Aes128Gcm::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst)?;
        },
    }
    Ok(())
}

pub fn decrypt(cipher_type: CipherType, key: &[u8], nonce: &[u8], src: &mut Input, dst: &mut Output) -> Result<(), Error> {
    // TODO: catch panic!
    match cipher_type {
        CipherType::XChacha20Poly1305 => {
            let aead = XChaCha20Poly1305::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst)?;
        },
        CipherType::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst)?;
        },
        CipherType::Aes256Gcm => {
            let aead = Aes256Gcm::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst)?;
        },
        CipherType::Aes128Gcm => {
            let aead = Aes128Gcm::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst)?;
        },
    }
    Ok(())
}


fn transfer_encryption<T>(mut encryptor: EncryptorBE32<T>, src: &mut Input, dst: &mut Output) -> Result<(), Error> 
    where
        T: AeadInPlace,
        T::NonceSize: Sub<U5>,
        <<T as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>
{
    let mut buffer = [0u8; BUFFER_LEN_ENC];
    loop {
        let read_count = src.read(&mut buffer)?;
        if read_count == BUFFER_LEN_ENC {
            let ciphertext= encryptor.encrypt_next(buffer.as_slice()).map_err(|e| Error::Aead(e))?;
            dst.write(&ciphertext)?;
        } else {
            let ciphertext = encryptor.encrypt_last(&buffer[..read_count]).map_err(|e| Error::Aead(e))?;
            dst.write(&ciphertext)?;
            break;
        }
    }
    Ok(())
}

fn transfer_decryption<T>(mut decryptor: DecryptorBE32<T>, src: &mut Input, dst: &mut Output) -> Result<(), Error>
    where
        T: aead::AeadInPlace,
        T::NonceSize: std::ops::Sub<U5>,
        <<T as aead::AeadCore>::NonceSize as std::ops::Sub<U5>>::Output: ArrayLength<u8>
{
    let mut buffer = [0u8; BUFFER_LEN_DEC];
    loop {
        let read_count = src.read(&mut buffer)?;
        if read_count == BUFFER_LEN_DEC {
            let plaintext = decryptor.decrypt_next(buffer.as_slice()).map_err(|e| Error::Aead(e))?;
                dst.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = decryptor.decrypt_last(&buffer[..read_count]).map_err(|e| Error::Aead(e))?;
            dst.write(&plaintext)?;
            break;
        }
    }
    Ok(())
}

use std::ops::Sub;

use aead::{
    KeyInit, AeadInPlace, AeadCore,
    stream::{EncryptorBE32, DecryptorBE32}, 
    generic_array::{typenum::U5, ArrayLength},
};
use aes_gcm::{Aes256Gcm, Aes128Gcm};
use chacha20poly1305::{XChaCha20Poly1305, XChaCha12Poly1305, XChaCha8Poly1305, ChaCha20Poly1305, ChaCha12Poly1305, ChaCha8Poly1305};

pub use crate::{
    cli::Cipher as CipherType,
    error::Error,
    io::{Input, Output},
};


pub const BUFFER_LEN_ENC: usize = 500;
pub const BUFFER_LEN_DEC: usize =  BUFFER_LEN_ENC + 16;


pub fn encrypt(cipher: CipherType, key: &[u8], nonce: &[u8], src: &mut Input, dst: &mut Output, buf: [u8; BUFFER_LEN_ENC], nread: usize) -> Result<(), Error> {
    // TODO: catch panic!
    match cipher {
        CipherType::XChacha20Poly1305 => {
            let aead = XChaCha20Poly1305::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::XChacha12Poly1305 => {
            let aead = XChaCha12Poly1305::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::XChacha8Poly1305 => {
            let aead = XChaCha8Poly1305::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Chacha12Poly1305 => {
            let aead = ChaCha12Poly1305::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Chacha8Poly1305 => {
            let aead = ChaCha8Poly1305::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Aes256Gcm => {
            let aead = Aes256Gcm::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Aes128Gcm => {
            let aead = Aes128Gcm::new(key.into());
            let encryptor = EncryptorBE32::from_aead(aead, nonce.into());
            transfer_encryption(encryptor, src, dst, buf, nread)?;
        },
    }
    Ok(())
}

pub fn decrypt(cipher: CipherType, key: &[u8], nonce: &[u8], src: &mut Input, dst: &mut Output, buf: [u8; BUFFER_LEN_DEC], nread: usize) -> Result<(), Error> {
    // TODO: catch panic!
    match cipher {
        CipherType::XChacha20Poly1305 => {
            let aead = XChaCha20Poly1305::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::XChacha12Poly1305 => {
            let aead = XChaCha12Poly1305::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::XChacha8Poly1305 => {
            let aead = XChaCha8Poly1305::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Chacha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Chacha12Poly1305 => {
            let aead = ChaCha12Poly1305::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Chacha8Poly1305 => {
            let aead = ChaCha8Poly1305::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Aes256Gcm => {
            let aead = Aes256Gcm::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst, buf, nread)?;
        },
        CipherType::Aes128Gcm => {
            let aead = Aes128Gcm::new(key.into());
            let encryptor = DecryptorBE32::from_aead(aead, nonce.into());
            transfer_decryption(encryptor, src, dst, buf, nread)?;
        },
    }
    Ok(())
}


fn transfer_encryption<T>(mut encryptor: EncryptorBE32<T>, src: &mut Input, dst: &mut Output, mut buf: [u8; BUFFER_LEN_ENC], nread: usize) -> Result<(), Error> 
    where
        T: AeadInPlace,
        T::NonceSize: Sub<U5>,
        <<T as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>
{
    let mut read_count = nread;
    loop {
        if read_count == BUFFER_LEN_ENC {
            let ciphertext= encryptor.encrypt_next(buf.as_slice()).map_err(Error::make_aead)?;
            dst.write(&ciphertext)?;
        } else {
            let ciphertext = encryptor.encrypt_last(&buf[..read_count]).map_err(Error::make_aead)?;
            dst.write(&ciphertext)?;
            break;
        }
        read_count = src.read(&mut buf)?;
    }
    Ok(())
}

fn transfer_decryption<T>(mut decryptor: DecryptorBE32<T>, src: &mut Input, dst: &mut Output, mut buf: [u8; BUFFER_LEN_DEC], nread: usize) -> Result<(), Error>
    where
        T: aead::AeadInPlace,
        T::NonceSize: std::ops::Sub<U5>,
        <<T as aead::AeadCore>::NonceSize as std::ops::Sub<U5>>::Output: ArrayLength<u8>
{
    let mut read_count = nread;
    loop {
        if read_count == BUFFER_LEN_DEC {
            let plaintext = decryptor.decrypt_next(buf.as_slice()).map_err(Error::make_aead)?;
                dst.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = decryptor.decrypt_last(&buf[..read_count]).map_err(Error::make_aead)?;
            dst.write(&plaintext)?;
            break;
        }
        read_count = src.read(&mut buf)?;
    }
    Ok(())
}

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




#[cfg(test)]
mod tests {
    use std::{
        rc::Rc,
        cell::RefCell,
        io::{Read, Write, Result},
    };
    use rand::{RngCore, rngs::OsRng};
    use strum::IntoEnumIterator;
    use crate::{
        cli::Cipher,
        io::{Input, Output},
    };
    use super::{BUFFER_LEN_ENC, BUFFER_LEN_DEC, encrypt, decrypt};


    #[test]
    fn encrypt_decrypt() {
        let size_data = BUFFER_LEN_ENC * 3 + 1;
        for cipher in Cipher::iter() {
            let (_, key_size, mut nonce_size) = cipher.get_spec();
            nonce_size -= 5;

            // Key
            let mut key: Vec<u8> = vec![0u8; key_size.try_into().unwrap()];
            OsRng.fill_bytes(&mut key);

            // Salt
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(salt.as_mut());

            // Nonce
            let mut nonce_arr = [0u8; 19];
            let nonce = &mut nonce_arr[..nonce_size];
            OsRng.fill_bytes(nonce);

            // Data
            let mut data_expected = vec![0u8; size_data];
            OsRng.fill_bytes(&mut data_expected);
            let data_enc = Rc::new(RefCell::new( Vec::with_capacity(size_data) ));

            // Process enc
            let input_reader = MockRead::new(data_expected.clone());
            let enc_writer = MockWrite::new(data_enc.clone());

            {
                let mut input = Input::new(Box::new( input_reader ));
                let mut output = Output::new(Box::new( enc_writer ));
                let mut buf = [0u8; BUFFER_LEN_ENC];
                let nread = input.read(&mut buf).unwrap();
                encrypt(cipher, &key[..], nonce, &mut input, &mut output, buf, nread).unwrap();
            }
            
            // Check encrypted
            let data_enc: Vec<u8> = Rc::try_unwrap(data_enc).unwrap().into_inner();
            assert_ne!(data_expected, data_enc, "encripted cipher: {:?}", cipher);
            
            // Process dec
            let input_reader = MockRead::new(data_enc);
            let data_dec = Rc::new(RefCell::new( Vec::with_capacity(size_data) ));
            let dec_writer = MockWrite::new(data_dec.clone());

            {
                let mut input = Input::new(Box::new( input_reader ));
                let mut output = Output::new(Box::new( dec_writer ));
                let mut buf = [0u8; BUFFER_LEN_DEC];
                let nread = input.read(&mut buf).unwrap();
                decrypt(cipher, &key[..], nonce, &mut input, &mut output, buf, nread).unwrap();
            }

            // Check decrypted
            let data_fact: Vec<u8> = Rc::try_unwrap(data_dec).unwrap().into_inner();
            assert_eq!(data_expected, data_fact, "decripted cipher: {:?}", cipher);
        }
    }


    struct MockRead<T: AsRef<[u8]>> {
        inner: T,
        idx_start: usize,
    }

    impl <T: AsRef<[u8]>> MockRead<T> {
        fn new(inner: T) -> Self {
            Self { inner, idx_start: 0 }
        }
    }

    impl <T: AsRef<[u8]>> Read for MockRead<T> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let len_inner = self.inner.as_ref().len().checked_sub(self.idx_start).unwrap();
            let n = if buf.len() < len_inner { buf.len() } else { len_inner };
            let idx_stop = self.idx_start.checked_add(n).unwrap();
            buf[..n].copy_from_slice(&self.inner.as_ref()[self.idx_start..idx_stop]);
            self.idx_start = idx_stop;
            Ok(n)
        }
    }


    struct MockWrite {
        inner: Rc<RefCell<Vec<u8>>>,
    }

    impl MockWrite {
        fn new(inner: Rc<RefCell<Vec<u8>>>) -> Self {
            Self { inner }
        }
    }

    impl Write for MockWrite {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let mut inner = self.inner.borrow_mut();
            for byte in buf {
                inner.push(*byte);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }
} 

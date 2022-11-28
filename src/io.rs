use std::{
    fs::File,
    io::{Read, Write, stdin, stdout, ErrorKind as IoErrorKind, Error as IoError},
    path::PathBuf,
};

use zeroize::Zeroizing;

use crate::error::Error;


pub fn make_inout(path_in: Option<PathBuf>, path_out: Option<PathBuf>) -> Result<(Input, Output), Error> {
    let input = if let Some(path) = path_in {
        Input::from_fpath(path)?
    } else {
        Input::from_stdin()
    };

    let output = if let Some(path) = path_out {
        Output::from_fpath(path)?
    } else {
        Output::from_stdout()
    };

    Ok((input, output))
}


pub fn extract_pwd(pwd_arg: Option<String>) -> Result<Zeroizing<String>, Error> {
    if let Some(pwd) = pwd_arg {
        Ok(Zeroizing::new(pwd))
    } else {
        let pwd = rpassword::prompt_password("password: ").map_err(|err|Error::Io(err))?;
        Ok(Zeroizing::new(pwd))
    }
}

pub fn extract_salt<'a>(salt_arr: &mut [u8; 32], salt_arg: Option<String>, salt_tty: bool) -> Result<Option<()>, Error> {
    if let Some(salt_arg) = extract_arg(salt_arg, salt_tty, "salt: ")? {
        let bytes = salt_arg.as_bytes();
        if bytes.len() < 32 {
            return Err(Error::Arg("salt shoud be at least 32 bytes".to_string()));
        }
        let _ = &salt_arr.copy_from_slice(&bytes[..32]);
        Ok(Some(()))
    } else {
        Ok(None)
    }
}

pub fn extract_nonce<'a>(nonce_arr: &'a mut [u8; 19], nonce_size: usize, nonce_arg: Option<String>, nonce_tty: bool) -> Result<Option<&'a [u8]>, Error> {
    if let Some(nonce_arg) = extract_arg(nonce_arg, nonce_tty, "nonce: ")? {
        let bytes = nonce_arg.as_bytes();
        if bytes.len() < nonce_size {
            return Err(Error::Arg(format!("nonce shoud be at least {} bytes", nonce_size)));
        }
        let nonce_slice = &mut nonce_arr[..nonce_size];
        let _ = &nonce_slice.copy_from_slice(&bytes[..nonce_size]);
        Ok(Some(nonce_slice))
    } else {
        Ok(None)
    }
}


fn extract_arg(arg: Option<String>, is_tty: bool, prompt: &str) -> Result<Option<Zeroizing<String>>, Error> {
    if let Some(arg) = arg {
        Ok(Some(Zeroizing::new(arg)))
    } else if is_tty {
        let password = rpassword::prompt_password(prompt).map_err(|err|Error::Io(err))?;
        Ok(Some(Zeroizing::new(password)))
    } else {
        Ok(None)
    }
}


pub struct Input {
    reader: Box<dyn Read>,
}
impl Input {
    pub fn from_stdin() -> Self {
        Self { reader: Box::new(stdin()) }
    }

    pub fn from_fpath(path: PathBuf) -> Result<Self, Error> {
        let file = File::open(path).map_err(|err| Error::Io(err))?;
        Ok(Self { 
            reader: Box::new(file), 
        })
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.reader.read_exact(buf).map_err(|err| Error::Io(err))
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut nread = 0usize;
        while nread < buf.len() {
            match self.reader.read(&mut buf[nread..]) {
                Ok(0) => break,
                Ok(n) => nread += n,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        Ok(nread)
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let mut arr = [0u8; 1];
        let num = self.read(&mut arr)?;
        if num != 1 {
            Err(Error::Io(IoError::new(IoErrorKind::UnexpectedEof, "unable to read u8")))
        } else {
            Ok(u8::from_be_bytes(arr))
        }

    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        let mut arr = [0u8; 4];
        let num = self.read(&mut arr)?;
        if num != 4 {
            Err(Error::Io(IoError::new(IoErrorKind::UnexpectedEof, "unable to read u32")))
        } else {
            Ok(u32::from_be_bytes(arr))
        }

    }
}


pub struct Output {
    writer: Box<dyn Write>,
}
impl Output {
    pub fn from_stdout() -> Self {
        Self { writer: Box::new(stdout()) }
    }

    pub fn from_fpath(path: PathBuf) -> Result<Self, Error> {
        let file = File::create(path).map_err(|err| Error::Io(err))?;
        Ok(Self { 
            writer: Box::new(file), 
        })
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.writer.write_all(buf).map_err(|err| Error::Io(err))
    }

    pub fn write_u8(&mut self, val: u8) -> Result<(), Error> {
        self.write(&val.to_be_bytes())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<(), Error> {
        self.write(&val.to_be_bytes())
    }
}

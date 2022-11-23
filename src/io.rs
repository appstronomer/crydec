use std::{
    fs::File,
    io::{Read, Write, stdin, stdout},
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

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self.reader.read(buf) {
            Ok(n) => Ok(n),
            Err(err) => Err(Error::Io(err))
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

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        match self.writer.write(buf) {
            Ok(n) => Ok(n),
            Err(err) => Err(Error::Io(err)),
        }
    }
}

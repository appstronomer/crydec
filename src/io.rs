use std::{
    fs::File,
    io::{Read, Write, stdin, stdout, ErrorKind as IoErrorKind, Error as IoError, Result as IoResult},
    path::PathBuf,
};

use zeroize::Zeroizing;

use crate::error::Error;


pub fn make_inout(path_in: Option<PathBuf>, path_out: Option<PathBuf>) -> Result<(Input, Output), Error> {
    let input = if let Some(path) = path_in {
        Input::new( Box::new( File::open(path).map_err(Error::make_io)? ) )
    } else {
        Input::new( Box::new(stdin()) )
    };

    let output = if let Some(path) = path_out {
        Output::new( Box::new( File::create(path).map_err(Error::make_io)? ) )
    } else {
        Output::new( Box::new(stdout()) )
    };

    Ok((input, output))
}

pub fn make_control() -> Control {
    Control::new(|req| rpassword::prompt_password(req))
}


pub struct Control {
    func: fn(&str) -> IoResult<String>,
}

impl Control {
    fn new(func: fn(&str) -> IoResult<String>) -> Self {
        Self { func }
    }

    pub fn prompt(&self, name: &str, arg: Option<String>) -> Result<Zeroizing<String>, Error> {
        if let Some(val) = arg {
            Ok(Zeroizing::new(val))
        } else {
            let request = format!("{}: ", name);
            let val = (self.func)(&request).map_err(Error::make_io)?;
            Ok(Zeroizing::new(val))
        }
    }

    pub fn extract(&self, name: &str, slice: &mut [u8], arg: Option<String>, is_tty: bool) -> Result<Option<()>, Error> {
        let text_opt = if let Some(arg) = arg {
            Some(Zeroizing::new(arg))
        } else if is_tty {
            let request = format!("{}: ", name);
            let password = (self.func)(&request).map_err(Error::make_io)?;
            Some(Zeroizing::new(password))
        } else {
            None
        };
        if let Some(text) = text_opt {
            let size = slice.len();
            let bytes = text.as_bytes();
            if bytes.len() < size {
                return Err(Error::make_arg(format!("{} shoud be at least {} bytes", name, size)));
            }
            let _ = &slice.copy_from_slice(&bytes[..size]);
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }
}


pub struct Input {
    reader: Box<dyn Read>,
}
impl Input {
    pub fn new(reader: Box<dyn Read>) -> Self {
        Self { reader }
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.reader.read_exact(buf).map_err(Error::make_io)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut nread = 0usize;
        while nread < buf.len() {
            match self.reader.read(&mut buf[nread..]) {
                Ok(0) => break,
                Ok(n) => nread += n,
                Err(ref e) if e.kind() == IoErrorKind::Interrupted => {}
                Err(e) => return Err(Error::make_io(e)),
            }
        }
        Ok(nread)
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let mut arr = [0u8; 1];
        let num = self.read(&mut arr)?;
        if num != 1 {
            Err(Error::make_io(IoError::new(IoErrorKind::UnexpectedEof, "unable to read u8")))
        } else {
            Ok(u8::from_be_bytes(arr))
        }

    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        let mut arr = [0u8; 4];
        let num = self.read(&mut arr)?;
        if num != 4 {
            Err(Error::make_io(IoError::new(IoErrorKind::UnexpectedEof, "unable to read u32")))
        } else {
            Ok(u32::from_be_bytes(arr))
        }

    }
}


pub struct Output {
    writer: Box<dyn Write>,
}
impl Output {
    pub fn new(writer: Box<dyn Write>) -> Self {
        Self { writer }
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.writer.write_all(buf).map_err(Error::make_io)
    }

    pub fn write_u8(&mut self, val: u8) -> Result<(), Error> {
        self.write(&val.to_be_bytes())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<(), Error> {
        self.write(&val.to_be_bytes())
    }
}




#[cfg(test)]
mod tests {
    use std::io::{Read, Result, Error, ErrorKind};
    use super::Input;


    #[test]
    fn input_read_aliquant() {
        const SIZE_DATA: usize = 41;
        const SIZE_SAMPLE: usize = SIZE_DATA + 1;
        const SIZE_BUFFER: usize = 15;
        let (left, right) = input_read_base(5, SIZE_DATA, SIZE_SAMPLE, SIZE_BUFFER);
        assert_eq!(left, right);
    }


    #[test]
    fn input_read_aliquot() {
        const SIZE_DATA: usize = 40;
        const SIZE_SAMPLE: usize = SIZE_DATA;
        const SIZE_BUFFER: usize = 10;
        let (left, right) = input_read_base(5, SIZE_DATA, SIZE_SAMPLE, SIZE_BUFFER);
        assert_eq!(left, right);
    }

    
    #[test]
    fn input_read_u32() {
        const VALUE: u32 = 2177283148;
        let bytes = VALUE.clone().to_be_bytes();
        let mock_read = MockRead::new(bytes, 5);
        let mut input = Input::new( Box::new(mock_read) );
        assert_eq!(VALUE, input.read_u32().unwrap());
    }

    
    #[test]
    fn input_read_u8() {
        const VALUE: u8 = 184;
        let bytes = VALUE.clone().to_be_bytes();
        let mock_read = MockRead::new(bytes, 5);
        let mut input = Input::new( Box::new(mock_read) );
        assert_eq!(VALUE, input.read_u8().unwrap());
    }

    
    #[test]
    fn input_read_exact() {
        const VALUE: &str = "Han shot first";
        let mock = String::from(VALUE).into_bytes();
        let expect = VALUE.as_bytes();
        let mut fact = vec![0u8; expect.len()];
        let mock_read = MockRead::new(mock, 5);
        let mut input = Input::new( Box::new(mock_read) );
        input.read_exact(&mut fact).unwrap();
        assert_eq!(expect, fact);
    }


    struct MockRead<T: AsRef<[u8]>> {
        inner: T,
        idx_start: usize,
        step: usize,
        is_err: bool,
    }

    impl <T: AsRef<[u8]>> MockRead<T> {
        fn new(inner: T, step: usize) -> Self {
            Self { inner, step, idx_start: 0, is_err: false }
        }
    }

    impl <T: AsRef<[u8]>> Read for MockRead<T> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if self.idx_start % (self.step.checked_mul(2).unwrap()) == 0 {
                if self.is_err {
                    self.is_err = false;
                } else {
                    self.is_err = true;
                    return Err(Error::new(ErrorKind::Interrupted, "test interruption"))
                }
            }
            let n = [
                    self.step, 
                    buf.len(), 
                    self.inner.as_ref().len().checked_sub(self.idx_start).unwrap()
                ].iter().min().unwrap().to_owned();
            let idx_stop = self.idx_start.checked_add(n).unwrap();
            buf[..n].copy_from_slice(&self.inner.as_ref()[self.idx_start..idx_stop]);
            self.idx_start = idx_stop;
            Ok(n)
        }
    }


    fn input_read_base(size_step: usize, size_data: usize, size_sample: usize, size_buffer: usize) -> (Vec<u8>, Vec<u8>) {
        // Data set
        let mut vec_data = vec![0u8; size_data];
        let mut vec_expected = vec![0u8; size_sample];
        for i in 0..size_data {
            let val = u8::try_from(i).unwrap();
            vec_data[i] = val;
            vec_expected[i] = val;
        }

        // Mock reader and input
        let mock_read = MockRead::new(vec_data, size_step);
        let mut input = Input::new( Box::new(mock_read) );
        
        // Process data
        let mut vec_fact = vec![0u8; size_sample];
        let mut vec_buff = vec![0u8; size_buffer];
        
        let mut idx_start = 0;
        loop {
            let nread = input.read(&mut vec_buff).unwrap();
            if nread == size_buffer {
                let idx_stop = idx_start + size_buffer;
                (&mut vec_fact[idx_start..idx_stop]).copy_from_slice(&vec_buff);
                idx_start = idx_stop;
            } else {
                let idx_stop = idx_start + nread;
                (&mut vec_fact[idx_start..idx_stop]).copy_from_slice(&vec_buff[..nread]);
                break;
            }
        }
        (vec_expected, vec_fact)
    }

}

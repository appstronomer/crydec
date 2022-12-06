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
    use std::{
        rc::Rc,
        cell::RefCell,
        borrow::Borrow,
        io::{Read, Write, Result, Error, ErrorKind},
    };
    use zeroize::Zeroizing;
    use crate::error::Error as CrateError;
    use super::{Input, Output, Control};


    #[test]
    fn input_read_aliquant() {
        let size_data: usize = 41;
        let size_sample: usize = size_data + 1;
        let size_buffer: usize = 15;
        let (left, right) = input_read_base(5, size_data, size_sample, size_buffer);
        assert_eq!(left, right);
    }


    #[test]
    fn input_read_aliquot() {
        let size_data: usize = 40;
        let size_sample: usize = size_data;
        let size_buffer: usize = 10;
        let (left, right) = input_read_base(5, size_data, size_sample, size_buffer);
        assert_eq!(left, right);
    }

    
    #[test]
    fn input_read_u32() {
        const VALUE: u32 = 2217864614;
        let bytes = VALUE.clone().to_be_bytes();
        let mock_read = MockRead::new(bytes, 5);
        let mut input = Input::new( Box::new(mock_read) );
        assert_eq!(VALUE, input.read_u32().unwrap());
    }

    
    #[test]
    fn input_read_u8() {
        const VALUE: u8 = 188;
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


    #[test]
    fn output_write_aliquant() {
        let size_data: usize = 41;
        let size_sample: usize = size_data + 1;
        let (left, right_rc) = output_write_base(5, size_data, size_sample);
        let right_refcell: &RefCell<Vec<u8>> = right_rc.borrow();
        let rigth_borrow = right_refcell.borrow();
        let right_ref: &Vec<u8> = rigth_borrow.as_ref();
        assert_eq!(&left, right_ref);
    }


    #[test]
    fn output_write_aliquot() {
        let size_data: usize = 40;
        let size_sample: usize = size_data;
        let (left, right_rc) = output_write_base(5, size_data, size_sample);
        let right_refcell: &RefCell<Vec<u8>> = right_rc.borrow();
        let rigth_borrow = right_refcell.borrow();
        let right_ref: &Vec<u8> = rigth_borrow.as_ref();
        assert_eq!(&left, right_ref);
    }

    
    #[test]
    fn output_write_u32() {
        const VALUE: u32 = 2217864614;
        let right_rc = Rc::new(RefCell::new( [0u8; 4] ));
        {
            let mock_write = MockWrite::new(right_rc.clone(), 5);
            let mut output = Output::new( Box::new(mock_write) );
            output.write_u32(VALUE).unwrap();
        }
        let right_refcell: &RefCell<[u8; 4]> = right_rc.borrow();
        let rigth_borrow = right_refcell.borrow();
        let right_ref = rigth_borrow.as_ref();
        assert_eq!(&VALUE.to_be_bytes(), right_ref);
    }

    
    #[test]
    fn output_write_u8() {
        const VALUE: u8 = 188;
        let right_rc = Rc::new(RefCell::new( [0u8; 1] ));
        {
            let mock_write = MockWrite::new(right_rc.clone(), 5);
            let mut output = Output::new( Box::new(mock_write) );
            output.write_u8(VALUE).unwrap();
        }
        let right_refcell: &RefCell<[u8; 1]> = right_rc.borrow();
        let rigth_borrow = right_refcell.borrow();
        let right_ref = rigth_borrow.as_ref();
        assert_eq!(&VALUE.to_be_bytes(), right_ref);
    }


    #[test]
    fn control_prompt_arg() {
        let name: &str = "prompt-arg";
        const REQ_LEFT: &str = "prompt-arg: ";
        let arg: Option<String> = Some("imput via argument".to_string());
        let resp_left = Zeroizing::new("imput via argument".to_string());

        let control = Control::new(|req| {
            assert_eq!(REQ_LEFT, req);
            Ok("imput via TTY".to_string())   
        });
        let resp_right = control.prompt(name, arg).unwrap();
        assert_eq!(resp_left, resp_right);
    }


    #[test]
    fn control_prompt_noarg() {
        let name: &str = "prompt-noarg";
        const REQ_LEFT: &str = "prompt-noarg: ";
        let arg: Option<String> = None;
        let resp_left = Zeroizing::new("imput via TTY".to_string());

        let control = Control::new(|req| {
            assert_eq!(REQ_LEFT, req);
            Ok("imput via TTY".to_string())   
        });
        let resp_right = control.prompt(name, arg).unwrap();
        assert_eq!(resp_left, resp_right);
    }


    #[test]
    fn control_extract_arg() {
        let name: &str = "extract-arg";
        const REQ_LEFT: &str = "extract-arg: ";
        let arg = Some("imput a argument".to_string());

        let data = "imput a argument";
        let data_left = data.as_bytes();
        let mut data_right = [0u8; 16];

        let control = Control::new(|req| {
            assert_eq!(REQ_LEFT, req);
            Ok("imput via TTY".to_string())   
        });

        let res = control.extract(name, &mut data_right[..], arg, true).unwrap();
        assert_eq!(Some(()),res);
        assert_eq!(data_left, data_right);
    }


    #[test]
    fn control_extract_noarg() {
        let name: &str = "extract-arg";
        const REQ_LEFT: &str = "extract-arg: ";
        let arg = None;

        let data = "imput via TTY...";
        let data_left = data.as_bytes();
        let mut data_right = [0u8; 16];

        let control = Control::new(|req| {
            assert_eq!(REQ_LEFT, req);
            Ok("imput via TTY...".to_string())   
        });

        let res = control.extract(name, &mut data_right[..], arg, true).unwrap();
        assert_eq!(Some(()), res);
        assert_eq!(data_left, data_right);
    }


    #[test]
    fn control_extract_none() {
        let control = Control::new(|_| Ok("imput via TTY...".to_string()) );
        let mut data = [0u8; 16];
        let right = control.extract("extract-arg", &mut data[..], None, false).unwrap();
        assert_eq!(None, right);
        assert_eq!([0u8; 16], data);
    }


    #[test]
    fn control_extract_err() {
        let name = "err-arg";
        let mut data = [0u8; 17];
        let msg_left = format!("{} shoud be at least {} bytes", name, data.len());

        let arg = Some("imput a argument".to_string());
        let control = Control::new(|_| Ok("imput via TTY...".to_string()) );
        
        let res = control.extract(name, &mut data[..], arg, false);
        if let Err(CrateError::Arg(msg_right)) = res {
            assert_eq!(msg_left, msg_right);
        } else {
            panic!("test should return an error message: {}", msg_left);
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


    fn output_write_base(size_step: usize, size_data: usize, size_sample: usize) -> (Vec<u8>, Rc<RefCell<Vec<u8>>>) {
        // Data set
        let mut vec_data = vec![0u8; size_data];
        let mut vec_expected = vec![0u8; size_sample];
        for i in 0..size_data {
            let val = u8::try_from(i).unwrap();
            vec_data[i] = val;
            vec_expected[i] = val;
        }

        // Mock reader and output
        let vec_fact = Rc::new(RefCell::new( vec![0u8; size_sample] ));
        let mock_write = MockWrite::new(vec_fact.clone(), size_step);
        let mut output = Output::new( Box::new(mock_write) );
        
        // Process data
        output.write(&vec_data).unwrap();
        drop(output);

        (vec_expected, vec_fact)
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

    struct MockWrite<T: AsMut<[u8]>> {
        inner: Rc<RefCell<T>>,
        idx_start: usize,
        step: usize,
        is_err: bool,
    }

    impl <T: AsMut<[u8]>> MockWrite<T> {
        fn new(inner: Rc<RefCell<T>>, step: usize) -> Self {
            Self { inner, step, idx_start: 0, is_err: false }
        }
    }

    impl <T: AsMut<[u8]>> Write for MockWrite<T> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            if self.idx_start % (self.step.checked_mul(2).unwrap()) == 0 {
                if self.is_err {
                    self.is_err = false;
                } else {
                    self.is_err = true;
                    return Err(Error::new(ErrorKind::Interrupted, "test interruption"))
                }
            }
            let mut inner = self.inner.borrow_mut();
            let n = [
                    self.step, 
                    buf.len(), 
                    inner.as_mut().len().checked_sub(self.idx_start).unwrap()
                ].iter().min().unwrap().to_owned();
            let idx_stop = self.idx_start.checked_add(n).unwrap();
            inner.as_mut()[self.idx_start..idx_stop].copy_from_slice(&buf[..n]);
            self.idx_start = idx_stop;
            Ok(n)
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

}
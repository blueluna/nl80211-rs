
use std::num;
use std::str;
use std::string;
use std::io;
use std::ffi;

error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }
    foreign_links {
        ParseInt(num::ParseIntError);
        ParseFloat(num::ParseFloatError);
        Utf8(str::Utf8Error);
        FromUtf8(string::FromUtf8Error);
        Io(io::Error);
        FromBytesWithNul(ffi::FromBytesWithNulError);
        Nul(ffi::NulError);
    }
}

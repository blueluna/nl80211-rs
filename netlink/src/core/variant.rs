use std::mem;
use std::str;
use std::io::{Read, Write, Error, ErrorKind};
use std::ffi::{CString, CStr};
use core::hardware_address::HardwareAddress;
use ::errors::Result;

use byteorder::{ByteOrder, NativeEndian, ReadBytesExt, WriteBytesExt};

pub trait NativeRead: Sized {
    fn read<R: Read>(reader: &mut R) -> Result<Self>;
}

pub trait NativeWrite: Sized {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()>;
}

pub trait NativeParse: Sized {
    fn parse(buffer: &[u8]) -> Result<Self>;
}

pub trait MultiValue: Sized {
    fn read<R: Read>(reader: &mut R, size: usize) -> Result<Self>;
    fn write<W: Write>(&self, writer: &mut W) -> Result<()>;
    fn size(&self) -> usize;
}

impl NativeRead for u8 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_u8()?)
    }
}
impl NativeWrite for u8 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(*self)?;
        Ok(())
    }
}
impl NativeParse for u8 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<u8>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(buffer[0])
    }
}

impl NativeRead for u16 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_u16::<NativeEndian>()?)
    }
}
impl NativeWrite for u16 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<NativeEndian>(*self)?;
        Ok(())
    }
}
impl NativeParse for u16 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(NativeEndian::read_u16(buffer))
    }
}

impl NativeRead for u32 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_u32::<NativeEndian>()?)
    }
}
impl NativeWrite for u32 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<NativeEndian>(*self)?;
        Ok(())
    }
}
impl NativeParse for u32 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(NativeEndian::read_u32(buffer))
    }
}

impl NativeRead for u64 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_u64::<NativeEndian>()?)
    }
}
impl NativeWrite for u64 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u64::<NativeEndian>(*self)?;
        Ok(())
    }
}
impl NativeParse for u64 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(NativeEndian::read_u64(buffer))
    }
}

impl NativeRead for i8 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_i8()?)
    }
}
impl NativeWrite for i8 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_i8(*self)?;
        Ok(())
    }
}
impl NativeParse for i8 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(buffer[0] as i8)
    }
}

impl NativeRead for i16 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_i16::<NativeEndian>()?)
    }
}
impl NativeWrite for i16 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_i16::<NativeEndian>(*self)?;
        Ok(())
    }
}
impl NativeParse for i16 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(NativeEndian::read_i16(buffer))
    }
}

impl NativeRead for i32 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_i32::<NativeEndian>()?)
    }
}
impl NativeWrite for i32 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_i32::<NativeEndian>(*self)?;
        Ok(())
    }
}
impl NativeParse for i32 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(NativeEndian::read_i32(buffer))
    }
}

impl NativeRead for i64 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_i64::<NativeEndian>()?)
    }
}
impl NativeWrite for i64 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_i64::<NativeEndian>(*self)?;
        Ok(())
    }
}
impl NativeParse for i64 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(NativeEndian::read_i64(buffer))
    }
}

impl NativeRead for f32 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_f32::<NativeEndian>()?)
    }
}
impl NativeWrite for f32 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_f32::<NativeEndian>(*self)?;
        Ok(())
    }
}
impl NativeParse for f32 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(NativeEndian::read_f32(buffer))
    }
}

impl NativeRead for f64 {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(reader.read_f64::<NativeEndian>()?)
    }
}
impl NativeWrite for f64 {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_f64::<NativeEndian>(*self)?;
        Ok(())
    }
}
impl NativeParse for f64 {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(NativeEndian::read_f64(buffer))
    }
}

impl NativeRead for HardwareAddress {
    fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut data = vec![0u8; 6];
        reader.read_exact(&mut data)?;
        Ok(HardwareAddress::from(data.as_slice()))
    }
}
impl NativeWrite for HardwareAddress {
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write(&self.bytes())?;
        Ok(())
    }
}
impl NativeParse for HardwareAddress {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < mem::size_of::<Self>() {
            return Err(Error::new(ErrorKind::InvalidData, "").into());
        }
        Ok(HardwareAddress::from(&buffer[0..6]))
    }
}

impl MultiValue for String {
    fn read<R: Read>(reader: &mut R, size: usize) -> Result<Self> {
        let mut data = vec![0u8; size];
        reader.read_exact(&mut data)?;
        match CStr::from_bytes_with_nul(&data) {
            Ok(bytes) => {
                let s = bytes.to_str()?;
                Ok(String::from(s))
            },
            Err(_) => {
                let s = str::from_utf8(&data)?;
                Ok(String::from(s))
            }
        }
    }
    
    fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        let c_string = CString::new((*self).clone())?;
        let bytes = c_string.into_bytes_with_nul();
        writer.write(&bytes)?;
        Ok(())
    }

    fn size(&self) -> usize {
        self.len() + 1
    }
}


#[cfg(test)]
mod tests {
    use std::io;
    use super::*;
    use std::fmt;
    use std::cmp;

    fn read_write_test<T: NativeRead + NativeWrite + NativeParse + fmt::Debug + cmp::PartialEq>(bytes: &[u8], value: T) {
        let value_size = mem::size_of::<T>();
        assert_eq!(bytes.len(), mem::size_of::<T>());
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(T::read(&mut reader).unwrap(), value);
        let mut writer = io::Cursor::new(vec![0u8; value_size]);
        value.write(&mut writer).unwrap();
        assert_eq!(writer.into_inner(), Vec::from(bytes));
        assert_eq!(T::parse(bytes).unwrap(), value);
    }

    #[test]
    fn read_write_u8() {
        read_write_test(&[0x5a], 0x5au8);
    }

    #[test]
    fn read_write_i8() {
        read_write_test(&[0xa5], -91i8);
    }

    #[test]
    fn read_write_u16() {
        read_write_test(&[0x22, 0xaa], 0xaa22u16.to_le());
    }

    #[test]
    fn read_write_u32() {
        read_write_test(&[0x44, 0x33, 0x22, 0x11], 0x11223344u32.to_le());
    }

    #[test]
    fn read_write_u64() {
        read_write_test(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            0x1122334455667788u64.to_le());
    }

    #[test]
    fn read_write_i16() {
        read_write_test(&[0x55, 0xaa], (-21931i16).to_le());
    }

    #[test]
    fn read_write_i32() {
        read_write_test(&[0x11, 0x22, 0x33, 0xa4], (-1540152815i32).to_le());
    }

    #[test]
    fn read_write_i64() {
        read_write_test(&[0x11, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x88],
            (-8637284766759618799i64).to_le());
    }

    #[test]
    fn read_write_hardware_address() {
        let bytes = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let hwa = HardwareAddress::from(bytes.as_slice());
        read_write_test(bytes.as_slice(), hwa);
    }

    #[test]
    fn read_string() {
        let bytes = vec![0xf0, 0x9f, 0x9b, 0xa0];
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(String::read(&mut reader, 4).unwrap(), String::from("🛠"));

        let bytes = vec![0xf0, 0x9f, 0x9b, 0xa0, 0x00];
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(String::read(&mut reader, 5).unwrap(), String::from("🛠"));

        let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00];
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(String::read(&mut reader, 6).unwrap(),
            String::from("Hello"));
        
        let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f];
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(String::read(&mut reader, 5).unwrap(),
            String::from("Hello"));

        // Could this be an issue?
        let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f,
            0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(String::read(&mut reader, 10).unwrap(),
            String::from("Hello\0\0\0\0\0"));
    }

    #[test]
    fn write_string() {
        let string = String::from("🛠");
        let mut writer = io::Cursor::new(vec![0u8; 4]);
        string.write(&mut writer).unwrap();
        assert_eq!(writer.into_inner(), vec![0xf0, 0x9f, 0x9b, 0xa0, 0x00]);

        let string = String::from("Hello");
        let mut writer = io::Cursor::new(vec![0u8; 5]);
        string.write(&mut writer).unwrap();
        assert_eq!(writer.into_inner(), vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00]);
    }
}

#[cfg(all(test, target_endian = "little"))]
mod tests_le {
    // Little endian specific tests
    use std::io;
    use super::*;

    #[test]
    fn read_f32() {
        let bytes = vec![82, 15, 73, 192];
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(f32::read(&mut reader).unwrap(), -3.14156);
    }

    #[test]
    fn read_f64() {
        let bytes = vec![105, 87, 20, 139, 10, 191, 5, 192];
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(f64::read(&mut reader).unwrap(), -2.718281828459045);
    }

    #[test]
    fn write_f32() {
        let mut writer = io::Cursor::new(vec![0u8; 4]);
        (-3.14156f32).write(&mut writer).unwrap();
        assert_eq!(writer.into_inner(), vec![82, 15, 73, 192]);
    }

    #[test]
    fn write_f64() {
        let mut writer = io::Cursor::new(vec![0u8; 8]);
        (-2.718281828459045f64).write(&mut writer).unwrap();
        assert_eq!(writer.into_inner(), vec![105, 87, 20, 139, 10, 191, 5, 192]);
    }
}

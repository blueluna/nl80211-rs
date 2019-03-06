use std::io;
use std::mem;

use byteorder::{ByteOrder, LittleEndian};

use netlink_rust::{HardwareAddress, Result};

/// Trait for unpacking values from byte stream
pub trait LittleUnpack: Sized {
    fn unpack(buffer: &[u8]) -> Result<Self> {
        Self::unpack_with_size(buffer).and_then(|r| Ok(r.1))
    }
    fn unpack_with_size(buffer: &[u8]) -> Result<(usize, Self)> {
        let size = mem::size_of::<Self>();
        if buffer.len() < size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "").into());
        }
        Ok((mem::size_of::<Self>(), Self::unpack_unchecked(buffer)))
    }
    fn unpack_unchecked(buffer: &[u8]) -> Self;
}

impl LittleUnpack for u8 {
    fn unpack_unchecked(data: &[u8]) -> Self {
        data[0]
    }
}

impl LittleUnpack for u16 {
    fn unpack_unchecked(data: &[u8]) -> Self {
        LittleEndian::read_u16(data)
    }
}

impl LittleUnpack for u32 {
    fn unpack_unchecked(data: &[u8]) -> Self {
        LittleEndian::read_u32(data)
    }
}

impl LittleUnpack for u64 {
    fn unpack_unchecked(data: &[u8]) -> Self {
        LittleEndian::read_u64(data)
    }
}

impl LittleUnpack for i8 {
    fn unpack_unchecked(data: &[u8]) -> Self {
        data[0] as i8
    }
}

impl LittleUnpack for i16 {
    fn unpack_unchecked(data: &[u8]) -> Self {
        LittleEndian::read_i16(data)
    }
}

impl LittleUnpack for i32 {
    fn unpack_unchecked(data: &[u8]) -> Self {
        LittleEndian::read_i32(data)
    }
}

impl LittleUnpack for i64 {
    fn unpack_unchecked(data: &[u8]) -> Self {
        LittleEndian::read_i64(data)
    }
}
impl LittleUnpack for HardwareAddress {
    fn unpack_unchecked(buffer: &[u8]) -> Self {
        HardwareAddress::from(&buffer[0..6])
    }
}

pub fn unpack_vec<T: LittleUnpack>(data: &[u8], size: usize) -> Result<(usize, Vec<T>)> {
    let mut items = vec![];
    let mut pos = 0;
    for _ in 0..size {
        let (offset, item) = T::unpack_with_size(&data[pos..])?;
        items.push(item);
        pos += offset;
    }
    let octets = mem::size_of::<T>() * size;
    Ok((octets, items))
}

/// Find the last non-zero byte
#[allow(dead_code)]
fn c_string_length(c_string: &[u8]) -> usize {
    match c_string.iter().rposition(|&b| b != 0) {
        Some(s) => s + 1,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_u8() {
        let data = [0xff, 1, 2, 3];
        let v = u8::unpack(&data).unwrap();
        assert_eq!(v, 255u8);
        let (s, v) = u8::unpack_with_size(&data[1..]).unwrap();
        assert_eq!(s, 1usize);
        assert_eq!(v, 1u8);
    }

    #[test]
    fn unpack_u16() {
        let v = u16::unpack(&[0xff, 1, 2, 3]).unwrap();
        assert_eq!(v, 0x01ffu16);
    }

    #[test]
    fn unpack_u32() {
        let v = u32::unpack(&[0, 1, 2, 3, 0xff, 0xee, 0xdd, 0xcc]).unwrap();
        assert_eq!(v, 0x03020100u32);
    }

    #[test]
    fn unpack_u64() {
        let v = u64::unpack(&[
            0, 1, 2, 3, 0xff, 0xee, 0xdd, 0xcc, 0x55, 0xaa, 0, 1, 2, 3, 4, 5,
        ])
        .unwrap();
        assert_eq!(v, 0xccddeeff03020100u64);
    }

    #[test]
    fn unpack_vector() {
        let (s, v) = unpack_vec::<u16>(
            &[
                0, 1, 2, 3, 0xff, 0xee, 0xdd, 0xcc, 0x55, 0xaa, 0, 1, 2, 3, 4, 5,
            ],
            4,
        )
        .unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v[0], 0x0100u16);
        assert_eq!(s, 8);
    }
}

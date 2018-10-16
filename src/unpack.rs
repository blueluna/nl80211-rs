use std::mem;
use std::str;
use netlink_rust::{Error};
use byteorder::{ByteOrder, NativeEndian};

/// Trait for unpacking values from byte stream
pub trait Unpack: Sized {
    fn unpack(data: &[u8]) -> (Self, &[u8]);
}

impl Unpack for u8 {
    fn unpack(data: &[u8]) -> (Self, &[u8])
    {
        return (data[0], &data[1..]);
    }
}

impl Unpack for u16 {
    fn unpack(data: &[u8]) -> (Self, &[u8])
    {
        return (NativeEndian::read_u16(data), &data[2..]);
    }
}

impl Unpack for u32 {
    fn unpack(data: &[u8]) -> (Self, &[u8])
    {
        return (NativeEndian::read_u32(data), &data[4..]);
    }
}

impl Unpack for u64 {
    fn unpack(data: &[u8]) -> (Self, &[u8])
    {
        return (NativeEndian::read_u64(data), &data[8..]);
    }
}

impl Unpack for i8 {
    fn unpack(data: &[u8]) -> (Self, &[u8])
    {
        return (data[0] as i8, &data[1..]);
    }
}

impl Unpack for i16 {
    fn unpack(data: &[u8]) -> (Self, &[u8])
    {
        return (NativeEndian::read_i16(data), &data[2..]);
    }
}

impl Unpack for i32 {
    fn unpack(data: &[u8]) -> (Self, &[u8])
    {
        return (NativeEndian::read_i32(data), &data[4..]);
    }
}

impl Unpack for i64 {
    fn unpack(data: &[u8]) -> (Self, &[u8])
    {
        return (NativeEndian::read_i64(data), &data[8..]);
    }
}

pub fn unpack_vec<T: Unpack>(data: &[u8], size: usize)
    -> Result<(Vec<T>, &[u8]), Error>
{
    let mut items = vec![];
    let r = (0, data);
    for _ in 0..size {
        let r = T::unpack(r.1);
        items.push(r.0);
    }
    let octets = mem::size_of::<T>() * size;
    Ok((items, &data[octets..]))
}

/// Find the last non-zero byte
#[allow(dead_code)]
fn c_string_length(c_string: &[u8]) -> usize
{
    match c_string.iter().rposition(|&b| b != 0) {
        Some(s) => s + 1,
        None => 0,
    }
}

/// Unpack zero byte terminated string from byte buffer of provided size
#[allow(dead_code)]
pub fn unpack_c_string(data: &[u8], size: usize)
    -> Result<(String, &[u8]), Error>
{
    let string_length = c_string_length(&data[..size]);
    let s = str::from_utf8(&data[..string_length])?;
    Ok((String::from(s), &data[size..]))
}

/// Unpack sized string from byte buffer of provided size
#[allow(dead_code)]
pub fn unpack_string(data: &[u8], size: usize, buffer_size: usize)
    -> Result<(String, &[u8]), Error>
{
    let s = str::from_utf8(&data[..size])?;
    Ok((String::from(s), &data[buffer_size..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_u8() {
        let (v, s) = u8::unpack(&[0xff, 1, 2, 3]);
        assert_eq!(v, 255u8);
        let (v, s) = u8::unpack(s);
        assert_eq!(v, 1u8);
        let (v, s) = u8::unpack(s);
        assert_eq!(v, 2u8);
        let (v, _) = u8::unpack(s);
        assert_eq!(v, 3u8);
    }
    
    #[test]
    fn unpack_u16() {
        let (v, s) = u16::unpack(&[0xff, 1, 2, 3]);
        assert_eq!(v, 0x01ffu16);
        let (v, _) = u16::unpack(s);
        assert_eq!(v, 0x0302u16);
    }
    
    #[test]
    fn unpack_u32() {
        let (v, s) = u32::unpack(&[0, 1, 2, 3, 0xff, 0xee, 0xdd, 0xcc]);
        assert_eq!(v, 0x03020100u32);
        let (v, _) = u32::unpack(s);
        assert_eq!(v, 0xccddeeffu32);
    }
    
    #[test]
    fn unpack_u64() {
        let (v, s) = u64::unpack(&[
            0, 1, 2, 3, 0xff, 0xee, 0xdd, 0xcc,
            0x55, 0xaa, 0, 1, 2, 3, 4, 5
            ]);
        assert_eq!(v, 0xccddeeff03020100u64);
        let (v, _) = u64::unpack(s);
        assert_eq!(v, 0x050403020100aa55u64);
    }
    
    #[test]
    fn unpack_vector() {
        let (v, s) = unpack_vec::<u16>(&[
            0, 1, 2, 3, 0xff, 0xee, 0xdd, 0xcc,
            0x55, 0xaa, 0, 1, 2, 3, 4, 5
            ], 4).unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v[0], 0x0100u16);
        assert_eq!(s[0], 0x55);
    }

    #[test]
    fn unpack_c_strings() {
        let (s, _) = unpack_c_string(&"ABCD\0".as_bytes(), 5).unwrap();
        assert_eq!(s, "ABCD");

        let (s, _) = unpack_c_string(&"ABC\0\0\0".as_bytes(), 6).unwrap();
        assert_eq!(s, "ABC");

        let (s, _) = unpack_c_string(&"\0\0\0".as_bytes(), 3).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn unpack_strings() {
        let (s, _) = unpack_string(&"ABC\0\0".as_bytes(), 3, 5).unwrap();
        assert_eq!(s, "ABC");

        let (s, _) = unpack_string(&"\0\0\0".as_bytes(), 0, 3).unwrap();
        assert_eq!(s, "");

        let (s, _) = unpack_string(&"\0\0\0".as_bytes(), 1, 3).unwrap();
        assert_eq!(s, "\0");
    }
}

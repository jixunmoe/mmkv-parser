use crate::Error;
use std::collections::HashMap;
use byteorder::{ByteOrder, LE};

/// Parse u64 from a given byte-slice.
/// Return `(buffer_rest, result)`.
pub fn read_u64(buffer: &[u8]) -> Result<(&[u8], u64), Error> {
    let mut result = 0;
    let mut shift = 0;

    for (i, &byte) in buffer.iter().enumerate() {
        result |= (u64::from(byte) & 0x7f) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            return Ok((&buffer[i + 1..], result));
        }
    }

    Err(Error::UnexpectedEof)
}

pub fn read_container(buffer: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (buffer, len) = read_u64(buffer)?;
    let (result, buffer) = buffer.split_at(len as usize);
    Ok((buffer, result))
}

pub fn read_string(buffer: &[u8]) -> Result<String, Error> {
    let (_, result) = read_container(buffer)?;
    Ok(String::from_utf8_lossy(result).into())
}

pub enum ParseControl {
    Continue,
    Stop,
}

/// Callback style parser.
#[allow(clippy::needless_lifetimes)]
pub fn parse_callback<'a, F>(buffer: &'a [u8], mut callback: F) -> Result<(), Error>
where
    F: FnMut(&'a [u8], &'a [u8]) -> ParseControl,
{
    // Skip the first 4 bytes - that's the size of the payload.
    let mmkv_len = LE::read_u32(&buffer) as usize;

    if buffer.len() < mmkv_len + 4 {
        Err(Error::BufferTooSmall(mmkv_len + 4))?;
    }

    // Skip the first integer - no idea what this is, probably not used anyway...
    let (next, _) = read_u64(&buffer[4..4 + mmkv_len])?;
    let mut buffer = next;

    while !buffer.is_empty() {
        let (next, key) = read_container(buffer)?;
        let (next, value) = read_container(next)?;
        buffer = next;

        match callback(key, value) {
            ParseControl::Continue => continue,
            ParseControl::Stop => break,
        }
    }

    Ok(())
}

/// Parse a non-encrypted mmkv file to key-value pairs.
pub fn parse(buffer: &[u8]) -> Result<HashMap<&[u8], &[u8]>, Error> {
    let mut result = HashMap::new();
    parse_callback(buffer, |k, v| {
        result.insert(k, v);
        ParseControl::Continue
    })?;
    Ok(result)
}

/// Parse a non-encrypted mmkv file to `HashMap<String, String>`.
/// If the store may contain non-string values, use `parse` instead.
pub fn parse_string_key_value_pairs(buffer: &[u8]) -> Result<HashMap<String, String>, Error> {
    let mut result = HashMap::new();
    let mut parse_err = Ok(());
    parse_callback(buffer, |k, v| match read_string(v) {
        Ok(value) => {
            let k = String::from_utf8_lossy(k);
            result.insert(k.into(), value);
            ParseControl::Continue
        }
        Err(err) => {
            parse_err = Err(err);
            ParseControl::Stop
        }
    })
    .and(parse_err)?;
    Ok(result)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_read_u64() {
        let buffer = [0xff, 0x81, 0x01, 0x00];
        let value = read_u64(&buffer);
        assert_eq!(value, Ok((&buffer[3..], 16639)));

        let buffer = [0x81, 0xAA];
        let value = read_u64(&buffer);
        assert_eq!(value, Err(Error::UnexpectedEof));

        let buffer = [0x80, 0x00, 0xff];
        let value = read_u64(&buffer);
        assert_eq!(value, Ok((&buffer[2..], 0)));
    }

    #[test]
    fn test_read_container() {
        let buffer = [0x03, b'A', b'B', b'C', 0];
        let value = read_container(&buffer);
        assert_eq!(value, Ok((&buffer[4..], &b"ABC"[..])));

        let buffer = [0x00, b'A', b'B', b'C', 0];
        let value = read_container(&buffer);
        assert_eq!(value, Ok((&buffer[1..], &b""[..])));
    }

    #[test]
    fn test_parse() {
        let buffer = [
            19, 0, 0, 0, // size of payload
            0xff,0xff,0xff,0x07,
            0x03, b'A', b'B', b'C', 0, //
            0x03, b'D', b'E', b'F', //
            0x05, 0x04, b'1', b'2', b'3', b'4',
        ];
        let value = parse(&buffer);
        let mut map = HashMap::new();
        map.insert(&b"ABC"[..], &b""[..]);
        map.insert(&b"DEF"[..], &b"\x041234"[..]);
        assert_eq!(value, Ok(map));
    }

    #[test]
    fn test_parse_buffer_len() {
        let buffer = [
            20, 0, 0, 0, // size of payload
        ];
        let value = parse(&buffer);
        assert_eq!(value, Err(Error::BufferTooSmall(24)));
    }

    #[test]
    fn test_parse_empty() {
        let buffer = [
            1, 0, 0, 0, // size of payload
            0, // padding
            0xff, // should be ignored
        ];
        let value = parse(&buffer);
        assert_eq!(value, Ok(HashMap::new()));
    }
}

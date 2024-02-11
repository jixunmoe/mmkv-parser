use crate::Error;
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use byteorder::{ByteOrder, LE};

pub type Decipher = cfb_mode::Decryptor<aes::Aes128>;

pub struct MmkvCrcHeader {
    /// CRC32 checksum of the enciphered file content, to the `hdr.real_size` bytes.
    pub crc32: u32,

    /// AES-128-CFB IV
    pub iv: [u8; 16],

    /// The actual mmkv store file size (without the 4-byte header).
    pub real_size: usize,
}

impl MmkvCrcHeader {
    /// Parse mmkv crc file from bytes.
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Error> {
        let bytes = bytes.as_ref();
        if bytes.len() < 32 {
            return Err(Error::UnexpectedEof);
        }

        let crc32 = LE::read_u32(&bytes[0..4]);
        let iv = bytes[0x0C..0x1C].try_into().unwrap();
        let real_size = LE::read_u32(&bytes[0x1C..0x20]) as usize;

        Ok(Self {
            crc32,
            iv,
            real_size,
        })
    }
}

/// Decrypt a given mmkv file using the header
pub fn decrypt(
    crc_header: &MmkvCrcHeader,
    key: &[u8],
    mmkv_file_body: &mut [u8],
) -> Result<usize, Error> {
    let real_size = crc_header.real_size;
    if mmkv_file_body.len() < real_size + 4 {
        Err(Error::BufferTooSmall(real_size))?;
    }

    // First 4 bytes is also the mmkv body size.
    let expected_size = LE::read_u32(&mmkv_file_body) as usize;
    if expected_size != real_size {
        Err(Error::FileSizeMismatch)?;
    }

    let mut file_slice = &mut mmkv_file_body[4..real_size + 4];
    if crc32fast::hash(file_slice) != crc_header.crc32 {
        Err(Error::ChecksumMismatch)?;
    }

    let decipher = Decipher::new(key.into(), &crc_header.iv.into());
    decipher.decrypt(&mut file_slice);

    Ok(real_size)
}

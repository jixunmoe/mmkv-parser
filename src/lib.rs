pub mod mmkv;

#[cfg(feature = "cipher")]
pub mod cipher;

// Expose some commonly used ones...
pub use mmkv::parse as parse_mmkv;
pub use mmkv::parse_string_key_value_pairs as parse_mmkv_key_value_pairs;

use thiserror::Error as ThisError;

#[derive(Debug, ThisError, Eq, PartialEq)]
pub enum Error {
    #[error("Unexpected End-of-File while parsing")]
    UnexpectedEof,

    #[error("buffer too small, at least {0} bytes required")]
    BufferTooSmall(usize),

    #[error("File size mismatch (crc vs mmkv)")]
    FileSizeMismatch,

    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

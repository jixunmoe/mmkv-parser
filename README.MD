# mmkv-parser

A read-only mmkv parser for [MMKV containers](https://github.com/Tencent/MMKV) with support for encrypted mmkv store.

This crate provides methods to parse the mmkv file to a `HashMap`, which its values can then be parsed into
unsigned integer (`read_u64`), variable-length byte slice (`read_container`), or UTF-8 String (`read_string`).

> [!WARNING]
> The encryption implementation is different from the rust [`mmkv`](https://crates.io/crates/mmkv) crate.
> Notably, the `mmkv` crate uses `aes-128-eax`, while the Tencent C++ MMKV implementation uses `aes-128-cfb`.

## Encrypted mmkv store

There'll be an extra `filename.mmkv.crc` header file, which contains `crc` and `IV` fields.
You'll also need to provide the key (not within those 2 files) to decrypt the mmkv store.
See `src/bin/mmkv.rs` for details.

## License

One of the following:

- MIT License
- Apache 2.0

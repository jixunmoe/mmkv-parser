# mmkv-parser

A read-only mmkv parser (encryption supported) for [MMKV containers](https://github.com/Tencent/MMKV).

> [!WARNING]
> The encryption implementation is different from the rust [`mmkv`](https://crates.io/crates/mmkv) crate.
> Notably, the `mmkv` crate uses `aes-128-eax`, while the Tencent C++ MMKV implementation uses `aes-128-cfb`.

## License

One of the following:

- MIT License
- Apache 2.0

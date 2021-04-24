# yara-sys

[![Crates.io](https://img.shields.io/crates/v/yara-sys.svg)](https://crates.io/crates/yara-sys)
[![Documentation](https://docs.rs/yara-sys/badge.svg)](https://docs.rs/yara-sys)

Native bindings for the [Yara library from VirusTotal](https://github.com/VirusTotal/yara).
Only works with Yara v4.

More documentation can be found on [the Yara's documentation](https://yara.readthedocs.io/en/stable/index.html).

## Features

By default, this crate uses bindgen to generate bindings on-the-fly, but you can
also use the following features to use pre-built bindings file for different
version of Yara. Just make sure the version you specify is the same that the
version on your system!

- `bindgen`: this is the default feature, to use generated bindings.
- `bundled-4_0`: use pre-generated bindings for Yara 4.0.2 **on Linux**.

You can specify the location of Yara:

- The path of the Yara library by setting the `YARA_LIBRARY_PATH` environment
  variable.
- The path of the Yara headers by setting the `YARA_INCLUDE_DIR` environment
  variable, if you use the `bindgen` feature.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

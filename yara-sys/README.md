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

- `bindgen`: **recommended**: this is the default feature, to use generated bindings.
- `bundled-4_1_2`: use pre-generated bindings for Yara 4.1.2. Useful if you do not
  want to install LLVM to run bindgen. However, you'll have to make sure you use
  a version of Yara with the same major and minor version number.
- `vendored`: automatically compile and link libyara v4.1.2.

You can specify the location of Yara:

- The path of the Yara library by setting the `YARA_LIBRARY_PATH` environment
  variable.
- The path of the Yara headers by setting the `YARA_INCLUDE_DIR` environment
  variable, if you use the `bindgen` feature.

You can specify compile options for libyara v4.1.2 if choice `vendored` (`0` - disable, `1` - enable):
- YARA_ENABLE_PROFILING - enable rules profiling support (default: **Disable**)
- YARA_ENABLE_NDEBUG - enable NDEBUG (default: **Enable**)
- YARA_ENABLE_HASH - enable [hash](https://yara.readthedocs.io/en/stable/modules/hash.html) module (default: **Enable**)
- YARA_ENABLE_MAGIC - enable [magic](https://yara.readthedocs.io/en/stable/modules/magic.html) module (depends on libmagic) (default: **Disable**)
- YARA_ENABLE_CUCKOO - enable [cuckoo](https://yara.readthedocs.io/en/stable/modules/cuckoo.html) module (depends on [Jansson](https://digip.org/jansson/) for parsing JSON) (default: **Disable**)
- YARA_ENABLE_DOTNET - enable [dotnet](https://yara.readthedocs.io/en/stable/modules/dotnet.html) module (default: **Enable**)
- YARA_ENABLE_DEX - enable dex module (default: **Enable**)
- YARA_ENABLE_DEX_DEBUG - enable dex module debugging (default: **Disable**)
- YARA_ENABLE_MACHO - enable macho module (default: **Enable**)
- YARA_CRYPTO_LIB - which crypto lib to use for the hash and pe modules. Header files must be available during compilation, and the lib must be installed on the target platform. Recognized values: `OpenSSL`, `Wincrypt`, `CommonCrypto` or `disable`. (default: will choose based on target os)
- YARA_DEBUG_VERBOSITY - Set debug level information on runtime (default: **0**)
- OPENSSL_LIB_DIR - path to OpenSSL library directory

Each of these variables can also be supplied with certain prefixes and suffixes,
in the following prioritized order:

1. `<var>_<target>` - for example, `YARA_ENABLE_MACHO_x86_64-unknown-linux-gnu`
2. `<var>_<target_with_underscores>` - for example, `YARA_ENABLE_MACHO_x86_64_unknown_linux_gnu`
3. `<var>` - a plain `YARA_ENABLE_MACHO`, as above.

If none of these variables exist, yara-sys uses built-in defaults

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

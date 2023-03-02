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
- `vendored`: automatically compile and link libyara v4.2.3.
- `bundled-4_2_3`: use pre-generated bindings for Yara 4.2.3. Useful if you do not
  want to install LLVM to run bindgen. However, you'll have to make sure you use
  a version of Yara with the same major and minor version number. List of supported targets:
  - x86_64-apple-darwin
  - x86_64-pc-windows-gnu
  - x86_64-pc-windows-msvc
  - x86_64-unknown-linux-gnu
  - x86_64-unknown-linux-musl

## Link on already compiled libyara

This is the default, when the `vendored` option is disabled.
You can specify the following environment variables:

- `YARA_LIBRARY_PATH` specifies the directoy containing the Yara library binary.
- `YARA_INCLUDE_DIR` specifies the directory containing the Yara include files,
  if you use the `bindgen` feature.
- `LIBYARA_STATIC` can be set to `1` to link statically against Yara (a .a or
  .lib file must be present).

## Compile options for libyara v4.2.3

When using the `vendored` feature, Yara will be automatically built and linked
statically with yara-sys.
You can set the following features change how Yara is built:

### Features:
- `module-cuckoo`: enable [cuckoo](https://yara.readthedocs.io/en/stable/modules/cuckoo.html) module (depends on [Jansson](https://digip.org/jansson/) for parsing JSON).
- `module-magic`: enable [magic](https://yara.readthedocs.io/en/stable/modules/magic.html) module (depends on libmagic).
- `module-macho`: enable macho module.
- `module-dex`: enable dex module.
- `module-debug-dex`: enable dex module debugging.
- `module-dotnet`: enable [dotnet](https://yara.readthedocs.io/en/stable/modules/dotnet.html) module.
- `module-hash`: enable [hash](https://yara.readthedocs.io/en/stable/modules/hash.html) module.
- `profiling`: enable rules profiling support.
- `ndebug`: enable `NDEBUG`.
- `openssl-static`: enable static link to OpenSSL rather then dynamically link.

### ENV variables 
- `YARA_CRYPTO_LIB` - which crypto lib to use for the hash and pe modules. Header files must be available during compilation, and the lib must be installed on the target platform. Recognized values: `OpenSSL`, `Wincrypt`, `CommonCrypto` or `disable`. (default: will choose based on target os)
- `YARA_DEBUG_VERBOSITY` - Set debug level information on runtime (default: **0**)
- `YARA_OPENSSL_DIR` - If specified, the directory of an OpenSSL installation. The directory should contain `lib` and `include` subdirectories containing the libraries and headers respectively.
- `YARA_OPENSSL_LIB_DIR` and `YARA_OPENSSL_INCLUDE_DIR` - If specified, the directories containing the OpenSSL libraries and headers respectively. This can be used if the OpenSSL installation is split in a nonstandard directory layout.

Each of these variables can also be supplied with certain prefixes and suffixes,
in the following prioritized order:

1. `<var>_<target>` - for example, `YARA_CRYPTO_LIB_x86_64-unknown-linux-gnu`
2. `<var>_<target_with_underscores>` - for example, `YARA_CRYPTO_LIB_x86_64_unknown_linux_gnu`
3. `<var>` - a plain `YARA_CRYPTO_LIB`, as above.

If none of these variables exist, yara-sys uses built-in defaults

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

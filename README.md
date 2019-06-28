# yara-rust

[![Build Status](https://travis-ci.org/Hugal31/yara-rust.svg?branch=master)](https://travis-ci.org/Hugal31/yara-rust)
[![Crates.io](https://img.shields.io/crates/v/yara.svg)](https://crates.io/crates/yara)
[![Documentation](https://docs.rs/yara/badge.svg)](https://docs.rs/yara)

Bindings for VirusTotal's [Yara library](https://github.com/VirusTotal/yara) via [yara-sys](https://crates.io/crates/yara-sys).

Tested with Yara 3.10.

Yara documentation can be found [here](https://yara.readthedocs.io/en/v3.10.0/index.html).

## Example

The implementation is inspired from [yara-python](https://github.com/VirusTotal/yara-python).

```rust
let mut yara = Yara::create().unwrap();
let mut compiler = yara.new_compiler().unwrap();
compiler.add_rules_str("rule contains_rust {
  strings:
    $rust = \"rust\" nocase
  condition:
    $rust
}").expect("Should have parsed rule");
let mut rules = compiler.compile_rules().expect("Should have compiled rules");
let results = rules.scan_mem("I love Rust!".as_bytes(), 5).expect("Should have scanned");
assert!(results.iter().find(|r| r.identifier == "contains_rust").is_some());
```

## Features

* Support Yara 3.10.
* Compile rules from strings or files.
* Save and load compiled rules.
* Scan byte arrays (`&[u8]`) or files.

## Requirements

Works with Linux, OpenBSD, and macOS. In order to build, the following packages must be installed:
* jansson
* libmagic
* openssl
* yara
* zlib

### TODO

- [ ] Address warning on exclusive access for drop, as identified by [recent compiler changes](https://github.com/rust-lang/rust/issues/31567).
- [ ] Support other versions of yara.
- [ ] Remove some `unwrap` on string conversions (currently this crate assume the rules, meta and namespace identifier are valid Rust's `str`).
- [ ] Look at the source code of Yara (or in documentation if specified) to assess thread safety.
- [ ] Look at the source code of Yara (or in documentation if specified) to see if we can remove some `mut` in some functions (as `Yara::new_compiler` and `Yara::load_rules`).

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

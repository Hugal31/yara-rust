# yara-rust

[![Build Status](https://travis-ci.org/Hugal31/yara-rust.svg?branch=master)](https://travis-ci.org/Hugal31/yara-rust)

Bindings for the [Yara library from VirusTotal](https://github.com/VirusTotal/yara).
Only works with Yara 3.7 for now.

More documentation can be found on [the Yara's documentation](https://yara.readthedocs.io/en/v3.7.0/index.html).

## How to use it

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

By default, this crate use a pre-built bindings file for Yara 3.7,
but you can use the feature `bindgen` to use on-the-fly generated bindings.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

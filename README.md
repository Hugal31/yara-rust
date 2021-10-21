# yara-rust

[![Build Status](https://travis-ci.com/Hugal31/yara-rust.svg?branch=master)](https://travis-ci.org/Hugal31/yara-rust)
[![Tests Status](https://github.com/Hugal31/yara-rust/actions/workflows/tests.yml/badge.svg)](https://github.com/Hugal31/yara-rust/actions/workflows/tests.yml)
[![Crates.io](https://img.shields.io/crates/v/yara.svg)](https://crates.io/crates/yara)
[![Documentation](https://docs.rs/yara/badge.svg)](https://docs.rs/yara)

Bindings for the [Yara library from VirusTotal](https://github.com/VirusTotal/yara).

More documentation can be found on [the Yara's documentation](https://yara.readthedocs.io/en/stable/index.html).

## Example

The implementation is inspired from [yara-python](https://github.com/VirusTotal/yara-python).

```rust
const RULES: &str = r#"
    rule contains_rust {
      strings:
        $rust = "rust" nocase
      condition:
        $rust
    }
"#;

fn main() {
    let compiler = Compiler::new().unwrap();
    compiler.add_rules_str(RULES)
        .expect("Should have parsed rule");
    let rules = compiler.compile_rules()
        .expect("Should have compiled rules");
    let results = rules.scan_mem("I love Rust!".as_bytes(), 5)
        .expect("Should have scanned");
    assert!(results.iter().any(|r| r.identifier == "contains_rust"));
}
```

## Features

* Support from Yara v4.1.
* Compile rules from strings or files.
* Save and load compiled rules.
* Scan byte arrays (`&[u8]`) or files.

## Feature flags and Yara linking.

Look at the [yara-sys](yara-sys) crate documentation for a list of feature flags
and how to link to your Yara crate.

### TODO

- [ ] Remove some `unwrap` on string conversions (currently this crate assume the rules, meta and namespace identifier are valid Rust's `str`).
- [ ] Accept `AsRef<Path>` instead of `&str` on multiple functions.
- [x] Implement the scanner API.
- [x] Add process scanning.
- [ ] Report the warnings to the user.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Please follow the [conventional commit][Conventional commit] rules when
committing to this repository.

If you add any new feature, add the corresponding unit/doc tests.

[Conventional commit]: https://www.conventionalcommits.org/en/v1.0.0/

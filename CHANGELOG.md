# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [0.11.0](https://github.com/Hugal31/yara-rust/compare/v0.10.0...v0.11.0) (2021-10-28)


### Features

* Add support for the include directive ([26273f0](https://github.com/Hugal31/yara-rust/commit/26273f0f03e182b0e00ec2173f304f156738689d))


### Bug Fixes

* add missing CallbackMsg type ([ea2a28c](https://github.com/Hugal31/yara-rust/commit/ea2a28c3548c3c917408338543d0e04a0917f047))
* add scan flags ([af34e15](https://github.com/Hugal31/yara-rust/commit/af34e15c317c511addb68988d8971b3354de9010))
* avoid warnings in generated bindings on x64 windows msvc ([43d0be1](https://github.com/Hugal31/yara-rust/commit/43d0be1cdd8bafaffa26cfb0c247da573fe1a818))
* improve API safety ([7dd00b1](https://github.com/Hugal31/yara-rust/commit/7dd00b1bf66b14f01a367b3ae1fab444f210287f))
* remove Box closure ([50a9a4e](https://github.com/Hugal31/yara-rust/commit/50a9a4ea5d553878fdc69fbf11dcb0a9eb584973))
* remove `non_upper_case_globals` warning with windows x86 target ([d1176b7](https://github.com/Hugal31/yara-rust/commit/d1176b76c59dcbf730188d764ca474278c4b6630))
* remove unused flag ([15f2472](https://github.com/Hugal31/yara-rust/commit/15f2472ecad8aba28a0455ead4472b4a263831d2))

## [0.10.0](https://github.com/Hugal31/yara-rust/compare/v0.9.1...v0.10.0) (2021-09-19)


### ⚠ BREAKING CHANGES

* Compiler.add_rules_* functions now takes `Compiler`
by value and return it if the rule is succesfully added.
* Minimum Rust version is now 1.55.

### Features

* **yara-sys:** vendored feature uses v4.1.2 ([18b7ae4](https://github.com/Hugal31/yara-rust/commit/18b7ae48656c1ffaf6b8ea8db295d43b86294812))
* add support for `yr_scanner_scan_mem_blocks` ([e1aa11e](https://github.com/Hugal31/yara-rust/commit/e1aa11e75338c64fe63ef4bbeafaccce62f1dca2))

### Bug Fixes

* prevent UB when failing to compile a rule ([99f756a](https://github.com/Hugal31/yara-rust/commit/99f756a15dd9a11dde76923dcee0ee4bbdf6073b)), closes [#47](https://github.com/Hugal31/yara-rust/issues/47)

## [0.9.1](https://github.com/Hugal31/yara-rust/compare/v0.9.0...v0.9.1) (2021-09-13)


### Bug Fixes

* correctly enable the DOTNET module ([338935e](https://github.com/Hugal31/yara-rust/commit/338935e01ad9c046854b547feb6861dc77d017e0))

## [0.9.0](https://github.com/Hugal31/yara-rust/compare/v0.8.0...v0.9.0) (2021-08-02)

### Features

* build with ssl ([eff2ddf](https://github.com/Hugal31/yara-rust/commit/eff2ddfdcbd8e1bdb5e23b057a1c551e69cea2c7)), closes [#37](https://github.com/Hugal31/yara-rust/pull/37)
* allow to use already opened files to add rules and scan ([acf7c19](https://github.com/Hugal31/yara-rust/commit/acf7c19d30e1408abd05c289dbe02f1132988b5e)), closes [#39](https://github.com/Hugal31/yara-rust/pull/39)

## [0.8.0](https://github.com/Hugal31/yara-rust/compare/v0.7.0...v0.8.0) (2021-07-22)

### Features

* add compile options ([6d40365](https://github.com/Hugal31/yara-rust/commit/6d403653f6cf4551ac2530e11309b27c271c3445))
* add set and get configuration ([967b23a](https://github.com/Hugal31/yara-rust/commit/967b23a81c61ce7c60b284feb216ab1826853be6))
* add callback API into Rules and Scanner ([562ec2c](https://github.com/Hugal31/yara-rust/commit/562ec2caf43168d38d59b91b48dcfc8e4f5977c7))

## [0.7.0](https://github.com/Hugal31/yara-rust/compare/v0.6.1...v0.7.0) (2021-07-13)

### Features

* adding deserialize ([10036ad](https://github.com/Hugal31/yara-rust/commit/10036adc3aa96edfe88a4a5364102cd52e7c1398))
* vendored feature now uses v4.1.1 ([05d130a](https://github.com/Hugal31/yara-rust/commit/05d130a24a3c31c91ddda79afb7bdd7bd2fb1b73))

### Bug Fixes

* unit test `scanner_scan_proc` encoding ([bc62faf](https://github.com/Hugal31/yara-rust/commit/bc62fafadf4b03bd23c5a0fdfc10d2244f952870)), closes [#25](https://github.com/Hugal31/yara-rust/issues/25)
* **yara-sys**: show some gcc warnings on vendored build ([a93fa08](https://github.com/Hugal31/yara-rust/commit/a93fa08e1be4f669bddf5447592419a9400cb985))

## [0.6.1](https://github.com/Hugal31/yara-rust/compare/v0.6.0...v0.6.1) (2021-05-06)

### Features

* add 32bit support ([f017299](https://github.com/Hugal31/yara-rust/commit/f0172996af5c28669dc0592526653b95c5bf283e))
* **yara-sys**: add error message when ([42d7c04](https://github.com/Hugal31/yara-rust/commit/42d7c04b980f5eaf1866d4cff2fc86602fa6ed02))

## [0.6.0](https://github.com/Hugal31/yara-rust/compare/v0.5.0...v0.6.0) (2021-04-27)

### Features

* add libyara v4.1.0 support
* add process memory scanning ([8d699c3](https://github.com/Hugal31/yara-rust/commit/8d699c313c1cdb084ba9ff545adb103d2cb965e9))

### ⚠ BREAKING CHANGES

* drop support for libyara v3.X.

# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

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

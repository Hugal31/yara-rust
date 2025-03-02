# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [0.30.0](https://github.com/Hugal31/yara-rust/compare/v0.30.0...v0.29.0) (2025-03-02)

### Features

* Fix intra-doc links to yara_sys, make RulesetRule public
* Expose xor_key value in string instance matches

## [0.29.0](https://github.com/Hugal31/yara-rust/compare/v0.28.0...v0.29.0) (2024-09-26)

### Features

* Change vendored and bundled Yara version to 4.5.2.

### ⚠ BREAKING CHANGES

* The `bunlded-4_5_1` feature as removed in favor of `bunlded-4_5_2`.

## [0.28.0](https://github.com/Hugal31/yara-rust/compare/v0.27.0...v0.28.0) (2024-06-03)

### Features

* Change vendored and bundled Yara version to 4.5.1.

### ⚠ BREAKING CHANGES

* The `bunlded-4_5_0` feature as removed in favor of `bunlded-4_5_1`.

### [0.27.0](https://github.com/Hugal31/yara-rust/compare/v0.26.0...v0.27.0) (2024-05-06)

### Features

* add ability to set module data in scan callback
  ([93e802e](https://github.com/Hugal31/yara-rust/commit/93e802e11bc9432f1f99f14b3ecde3e7bf614725))

## [0.26.0](https://github.com/Hugal31/yara-rust/compare/v0.25.0...v0.26.0) (2024-02-16)

### Features

* update yara dependency to v4.5.0
  ([a28a6d8](https://github.com/Hugal31/yara-rust/commit/a28a6d88772b8d94296e42221c3cc591f2fc8447))

## [0.25.0](https://github.com/Hugal31/yara-rust/compare/v0.24.0...v0.25.0) (2024-02-06)

### Features

* handle `CALLBACK_MSG_CONSOLE_LOG` callback type ([6cdad52](https://github.com/Hugal31/yara-rust/commit/6cdad5245a0e1d32b30d4c1cc4c0812bd9c7d6b9))
* implemented MemoryBlockIterator for Box ([88ea4c6](https://github.com/Hugal31/yara-rust/commit/88ea4c61808934fc0f9fc0742c8b338e799046a0))
* implemented MemoryBlockIterator for &mut T ([8d78f8c](https://github.com/Hugal31/yara-rust/commit/8d78f8c7fe7250485306817533efd97681e224cf))

### ⚠ BREAKING CHANGES

* upgrade Rust edition to 2021 and minimal Rust version to 1.63 ([9ee48d9](https://github.com/Hugal31/yara-rust/commit/9ee48d99b48bd18638715ecfa145e649e17e0e89))

## [0.24.0](https://github.com/Hugal31/yara-rust/compare/v0.23.0...v0.24.0) (2023-11-29)

### Features

* allow to iterate over the ruleset before scanning ([e62b7c6](https://github.com/Hugal31/yara-rust/commit/e62b7c6c82379acf3627cf946610e44ae6054629))

## [0.23.0](https://github.com/Hugal31/yara-rust/compare/v0.22.0...v0.22.1) (2023-11-17)

### Features

* **yara-sys**: add support of static linking with OpenSSL on Windows

## [0.22.0](https://github.com/Hugal31/yara-rust/compare/v0.21.0...v0.22.0) (2023-10-30)


### Features

* add ScanFlags::PROCESS_MEMORY
  ([8538674](https://github.com/Hugal31/yara-rust/commit/8538674d7142ec51f2e403571ee07119f62b28c4))


### Bug Fixes

* fix UB in the scan mem blocks API
  ([801ab5f](https://github.com/Hugal31/yara-rust/commit/801ab5f1360ae732bdcacc91a2742c0e8da7ea67))

## [0.21.0](https://github.com/Hugal31/yara-rust/compare/v0.20.0...v0.21.0) (2023-09-07)


### Features

* Exposed yara_sys::Error ([07ad2c6](https://github.com/Hugal31/yara-rust/commit/07ad2c65e010a171e44aa2070a4fc55f5dca97d3))
* remove unused features of bindgen ([1dc6b44](https://github.com/Hugal31/yara-rust/commit/1dc6b4485c4c8e7c339e434a614a25a1deaac2c5))
* replace globwalk with glob in yara-sys build.rs ([90d977c](https://github.com/Hugal31/yara-rust/commit/90d977ceeab75c73d2d034e8715840d00e4fcdbe))

## [0.20.0](https://github.com/Hugal31/yara-rust/compare/v0.19.0...v0.20.0) (2023-05-12)

### ⚠ BREAKING CHANGES

* change bundled bindings and vendored Yara version to 4.3.1 ([9d972f3](https://github.com/Hugal31/yara-rust/commit/9d972f3ad8269e7fd1763377da68e13eaa8bb75e))

### Features

* handle BoringSSL as crypto lib in yara-sys ([049ddcf](https://github.com/Hugal31/yara-rust/commit/049ddcf0199ee49e1d5ded17515610dffdc44e1b))
* upgrade yara up to 4.3.1 ([9d972f3](https://github.com/Hugal31/yara-rust/commit/9d972f3ad8269e7fd1763377da68e13eaa8bb75e))

## [0.19.0](https://github.com/Hugal31/yara-rust/compare/v0.18.0...v0.19.0) (2023-04-06)

### ⚠ BREAKING CHANGES

* change bundled bindings and vendored Yara version to 4.3.0 ([c2c30a9](https://github.com/Hugal31/yara-rust/commit/c2c30a997d7953b175ce41914a2e897fd6785421))

### Features

* update vendored Yara to 4.3.0 ([b77105](https://github.com/Hugal31/yara-rust/commit/b7710552452f418f677428464de4791cb4e5f30a))
* update bundled bindings to `bundled_4_3_0` ([ce8e481](https://github.com/Hugal31/yara-rust/commit/ce8e481109bcd9ce6235290eb70b97a5a8311836))

### Bug Fixes

* not exactly from our side, but Yara pre-4.3.0 had memory alignment issues (see #112).

## [0.18.0](https://github.com/Hugal31/yara-rust/compare/v0.17.0...v0.18.0) (2023-04-05)

### ⚠ BREAKING CHANGES

* move static linking env flags to cargo feature ([882a89a](https://github.com/Hugal31/yara-rust/commit/882a89af928935d2e77e031e1c7d340d967b2569))
* rework `Yara::set_configuration` to remove enum ([755d4e5](https://github.com/Hugal31/yara-rust/commit/755d4e5d7c68889b8d753373c2212b35b5dbc617))

### Features

* add configuration for `YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK` ([a984dfa](https://github.com/Hugal31/yara-rust/commit/a984dfaf77e3ae306c8c679a8156a2037fe91adf))
* add option to static linking with openssl ([8ffd99a](https://github.com/Hugal31/yara-rust/commit/8ffd99a07fa5a40d46cc403baeb99ca8bb6a74d2))
* show an explicit error when submodule was not cloned ([193d06c](https://github.com/Hugal31/yara-rust/commit/193d06cf242d3418ef9e42c4537d04552854d2d0))


### Bug Fixes

* prevent dynamic linking when targetting musl ([49a6817](https://github.com/Hugal31/yara-rust/commit/49a68177fb16ce6418fae373953d4aa1eb27efc7))
* properly compile YARA on big-endian arch ([754d902](https://github.com/Hugal31/yara-rust/commit/754d9023add667be20b8271bf5de76656c7aefa8))

## [0.17.0](https://github.com/Hugal31/yara-rust/compare/v0.16.2...v0.17.0) (2023-02-13)

### ⚠ BREAKING CHANGES

* enable or disable env flags replace to cargo feature ([e37cbd3](https://github.com/Hugal31/yara-rust/commit/e37cbd3f701b2cd75301dc6c5a5c6dc039dca49b))

### Features

* add CouldNotReadProcessMemory error ([dbb795b](https://github.com/Hugal31/yara-rust/commit/dbb795befeea551b306d69122a85ccee7c6ba342))
* add helpers to get module values on scans ([05e8e3d](https://github.com/Hugal31/yara-rust/commit/05e8e3d6447652434884e358e606081f21e0b4ac))
* add include path to openssl in vendored mode ([47f1cae](https://github.com/Hugal31/yara-rust/commit/47f1caeef44d17735d1e8db16a70f77649bea57a))
* add musl support ([a45bfe0](https://github.com/Hugal31/yara-rust/commit/a45bfe0d460c901da902d8e7dace6d318b7115b9))
* update saved bindings following build.rs changes ([23685e2](https://github.com/Hugal31/yara-rust/commit/23685e222160e068a54302300caf5b4787c94379))


### Bug Fixes

* add base offset for scanning memory chunks ([1e88d7e](https://github.com/Hugal31/yara-rust/commit/1e88d7e0e609305658b1aada72255ec30d838f3e))
* clippy warnings ([4937de7](https://github.com/Hugal31/yara-rust/commit/4937de79f9181ed53859a21737cc693d4ab6115a))

## [0.16.2](https://github.com/Hugal31/yara-rust/compare/v0.16.1...v0.16.2) (2022-10-18)


### Bug Fixes

* fix compilation of 0.16 release on i686 ([#91](https://github.com/Hugal31/yara-rust/issues/91)) ([f464003](https://github.com/Hugal31/yara-rust/commit/f464003d68676fe524ace0b033055ac59b9836ec))

## [0.16.1](https://github.com/Hugal31/yara-rust/compare/v0.16.0...v0.16.1) (2022-10-07)


### Bug Fixes

* fix use after free in `add_rules_file_with_namespace` ([#90](https://github.com/Hugal31/yara-rust/issues/90)) ([123f016](https://github.com/Hugal31/yara-rust/commit/123f016bc35c3722990b984e1791471de88d5df2))

## [0.16.0](https://github.com/Hugal31/yara-rust/compare/v0.15.0...v0.16.0) (2022-09-01)


### Features

* generate bindings per target ([78180df](https://github.com/Hugal31/yara-rust/commit/78180dff375d12bec9ff17144e82d93c89e65fb1))
* pre-generated bindings for target ([867516f](https://github.com/Hugal31/yara-rust/commit/867516f498eb84f0c5093aea1bf81ec66d0fe167))
* upgrade yara to 4.2.3 ([#86](https://github.com/Hugal31/yara-rust/issues/86)) ([be11341](https://github.com/Hugal31/yara-rust/commit/be113419ebe5b9cf5df3b1517db98f2c2b4a3ffc))


### Bug Fixes

* build on aarch64 ([97534cd](https://github.com/Hugal31/yara-rust/commit/97534cd842484c8c726629bfd12143c795f62373))
* do not list private matches in scan results ([99d413a](https://github.com/Hugal31/yara-rust/commit/99d413a0390f339c501a6502960189bdaa6f2201))
* find command ([262b584](https://github.com/Hugal31/yara-rust/commit/262b5844162ffbe34430b05f5ae7fa56ae0aa50a))

## [0.15.0](https://github.com/Hugal31/yara-rust/compare/v0.14.0...v0.15.0) (2022-06-19)


### Features

* generate bindings from ci ([43ec836](https://github.com/Hugal31/yara-rust/commit/43ec836f01e85f517bc82690df1e6e14ab1db259))
* pass message data in some CallbackMsg ([4911879](https://github.com/Hugal31/yara-rust/commit/491187908325e45f5b68729be70b32d28fb19864))

### ⚠ BREAKING CHANGES

* `CallbackMsg::RuleNotMatching` and `TooManyMatches` how have values.

## [0.14.0](https://github.com/Hugal31/yara-rust/compare/v0.13.2...v0.14.0) (2022-06-14)


### ⚠ BREAKING CHANGES

* Feature `bundled-4_1_3` is deleted in favor of `bundled-4_2_1`.

### Features

* Upgrade yara to 4.2.1 ([598d75a](https://github.com/Hugal31/yara-rust/commit/598d75ab0a33860bb17e6ec003ea32a044145df5))
* Merge pull request #72 from ikrivosheev/feature/upgrade_yara ([34ef96f](https://github.com/Hugal31/yara-rust/commit/34ef96f437d6ecf99022021b83af303030fb044b)), closes [#72](https://github.com/Hugal31/yara-rust/issues/72)

## [0.13.2](https://github.com/Hugal31/yara-rust/compare/v0.13.1...v0.13.2) (2022-06-06)


### Bug Fixes

* fix YR_STRING conversion that was picking only the first string ([daea8e2](https://github.com/Hugal31/yara-rust/commit/daea8e23d1bf96c0775895173da566fa934abe5f))

## [0.13.1](https://github.com/Hugal31/yara-rust/compare/v0.13.0...v0.13.1) (2022-06-05)


### Bug Fixes

* fix undefined behavior with custom scanners ([5503c1b](https://github.com/Hugal31/yara-rust/commit/5503c1baea7a220c2a08efdb404c6e41b8ae06d6))

## [0.13.0](https://github.com/Hugal31/yara-rust/compare/v0.12.0...v0.13.0) (2022-02-02)

### ⚠ BREAKING CHANGES

* **yara-sys**: for the vendored feaure, `YARA_ENABLE_HASH` is now enabled by default.

### Features

* **yara-sys:** recompile if ENV change ([a669bd3](https://github.com/Hugal31/yara-rust/commit/a669bd3aacc4141a0b5a7eb2beb7306abc74a652))
* **yara-sys:** add support wincrypt and common crypto ([34d2664](https://github.com/Hugal31/yara-rust/commit/34d26645e8a0bf7071cdea7d27a45bc3d96a3cdf))

### Bug Fixes

* **yara-sys** improve `cargo_rerun_if_env_changed` to support targets ([ef8e51e](https://github.com/Hugal31/yara-rust/commit/ef8e51e63e432fe9f4fb684d33bb05fff9e7754f))
* **yara-sys** fix vendored build symlink issue on Windows ([9e1954b](https://github.com/Hugal31/yara-rust/commit/9e1954b5732a5b677c07c642974a5b83b0a0e0f2))

## [0.12.0](https://github.com/Hugal31/yara-rust/compare/v0.11.1...v0.12.0) (2021-10-29)


### Features

* upgrade yara to 4.1.3 ([18b869d](https://github.com/Hugal31/yara-rust/commit/18b869d24f9c61aeac06eb0640d12ff353eb057d))

### [0.11.1](https://github.com/Hugal31/yara-rust/compare/v0.11.0...v0.11.1) (2021-10-29)


### Bug Fixes

* fix timeout type ([edbc0f2](https://github.com/Hugal31/yara-rust/commit/edbc0f2e09673902a6c791fb781768dede2e929c))
* pid type ([467d783](https://github.com/Hugal31/yara-rust/commit/467d783ddefb0811c6a27d8fc85295d2ad5f9be1))

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

// Inspired from https://github.com/jgallagher/rusqlite/blob/master/libsqlite3-sys/build.rs

fn main() {
    build::build_and_link();
    bindings::add_bindings();
}

pub fn cargo_rerun_if_env_changed(env_var: &str) {
    let target = std::env::var("TARGET").unwrap();
    println!("cargo:rerun-if-env-changed={env_var}");
    println!("cargo:rerun-if-env-changed={env_var}_{target}");
    println!(
        "cargo:rerun-if-env-changed={}_{}",
        env_var,
        target.replace('-', "_")
    );
}

pub fn get_target_env_var(env_var: &str) -> Option<String> {
    let target = std::env::var("TARGET").unwrap();
    std::env::var(format!("{env_var}_{target}"))
        .or_else(|_| std::env::var(format!("{}_{}", env_var, target.replace('-', "_"))))
        .or_else(|_| std::env::var(env_var))
        .ok()
}

#[cfg(feature = "vendored")]
mod build {
    use fs_extra::dir::{copy, CopyOptions};

    use std::path::PathBuf;

    use super::cargo_rerun_if_env_changed;
    use super::get_target_env_var;

    enum CryptoLib {
        OpenSSL,
        BoringSSL,
        Wincrypt,
        CommonCrypto,
        None,
    }

    fn get_crypto_lib() -> CryptoLib {
        match get_target_env_var("YARA_CRYPTO_LIB")
            .map(|v| v.to_lowercase())
            .as_deref()
        {
            Some("openssl") => CryptoLib::OpenSSL,
            Some("boringssl") => CryptoLib::BoringSSL,
            Some("wincrypt") => CryptoLib::Wincrypt,
            Some("commoncrypto") => CryptoLib::CommonCrypto,
            Some(_) => CryptoLib::None,
            None => {
                // defaults to target family's crypto lib if not specified
                match std::env::var("CARGO_CFG_TARGET_OS").ok().unwrap().as_str() {
                    "linux" | "freebsd" | "android" | "openbsd" | "netbsd" => CryptoLib::OpenSSL,
                    "windows" => CryptoLib::Wincrypt,
                    "macos" | "ios" => CryptoLib::CommonCrypto,
                    _ => {
                        println!("cargo:warning=Can't determine crypto lib to use during compilation for your target platform, please specify one via YARA_CRYPTO_LIB or disable it via YARA_CRYPTO_LIB=disable");
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    fn handle_openssl(cc: &mut cc::Build) {
        // If OPENSSL_DIR is set, use it to extrapolate lib and include dir
        if let Some(openssl_dir) = get_target_env_var("YARA_OPENSSL_DIR") {
            let openssl_dir = PathBuf::from(openssl_dir);

            cc.include(openssl_dir.join("include"));
            println!(
                "cargo:rustc-link-search=native={}",
                openssl_dir.join("lib").display()
            );
        } else {
            // Otherwise, retrieve OPENSSL_INCLUDE_DIR and OPENSSL_LIB_DIR
            if let Some(include_dir) = get_target_env_var("YARA_OPENSSL_INCLUDE_DIR") {
                cc.include(&include_dir);
            }
            if let Some(openssl_lib_dir) = get_target_env_var("YARA_OPENSSL_LIB_DIR") {
                println!(
                    "cargo:rustc-link-search=native={}",
                    PathBuf::from(openssl_lib_dir).display()
                );
            }
        }

        cc.define("HAVE_LIBCRYPTO", "1");
        if std::env::var("CARGO_CFG_TARGET_FAMILY")
            .ok()
            .unwrap()
            .as_str()
            == "windows"
        {
            println!("cargo:rustc-link-lib=dylib=Crypt32");
            println!("cargo:rustc-link-lib=dylib=Ws2_32");
            if cfg!(feature = "openssl-static") {
                // since both static and dynamic linking force the linker to use "libssl.lib" and "libcrypto.lib"
                // make sure you are linking against the static version:
                // - libssl.lib is actually libssl_static.lib/libsslMT.lib
                // - libcrypto.lib is actually libcrypto_static.lib/libcryptoMT.lib
                // SA: https://github.com/Kitware/CMake/blob/32342fa728e636a220f3cbd8380097e8aa7852ad/Modules/FindOpenSSL.cmake#L387-L410
                println!("cargo:rustc-link-lib=static=libssl");
                println!("cargo:rustc-link-lib=static=libcrypto");
            } else {
                println!("cargo:rustc-link-lib=dylib=libssl");
                println!("cargo:rustc-link-lib=dylib=libcrypto");
            }
        } else if cfg!(feature = "openssl-static") {
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");
        } else {
            println!("cargo:rustc-link-lib=dylib=ssl");
            println!("cargo:rustc-link-lib=dylib=crypto");
        }
    }

    pub fn build_and_link() {
        let old_basedir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("yara");
        // check the yara source folder is not empty
        if old_basedir
            .read_dir()
            .unwrap_or_else(|e| {
                panic!(
                    "can't open yara submodule folder {}: {}",
                    old_basedir.display(),
                    e
                )
            })
            .count()
            == 0
        {
            panic!("yara submodule folder {} is empty, please initialize it with `git submodule init && git submodule update`", old_basedir.display());
        }
        let out_dir = std::env::var("OUT_DIR").map(PathBuf::from).unwrap();
        let basedir = out_dir.join("yara");
        if !basedir.exists() {
            let mut opt = CopyOptions::new();
            opt.overwrite = true;
            opt.copy_inside = true;
            copy(old_basedir, &basedir, &opt).unwrap();
        }
        let basedir = basedir.join("libyara");

        let mut cc = cc::Build::new();
        cc.include(&basedir)
            .include(basedir.join("include"))
            .include(basedir.join("modules"));

        let mut exclude: Vec<PathBuf> = vec![
            basedir.join("modules").join("pb_tests").join("pb_tests.c"),
            basedir
                .join("modules")
                .join("pb_tests")
                .join("pb_tests.pb-c.c"),
            basedir.join("modules").join("demo").join("demo.c"),
        ];

        // Use correct proc functions
        match std::env::var("CARGO_CFG_TARGET_OS").ok().unwrap().as_str() {
            "windows" => cc
                .file(basedir.join("proc").join("windows.c"))
                .define("USE_WINDOWS_PROC", ""),
            "linux" => cc
                .file(basedir.join("proc").join("linux.c"))
                .define("USE_LINUX_PROC", ""),
            "macos" => cc
                .file(basedir.join("proc").join("mach.c"))
                .define("USE_MACH_PROC", ""),
            _ => cc
                .file(basedir.join("libyara/proc/none.c"))
                .define("USE_NO_PROC", ""),
        };

        if std::env::var("CARGO_CFG_TARGET_FAMILY")
            .ok()
            .unwrap()
            .as_str()
            != "windows"
        {
            cc.define("POSIX", "");
        };

        #[cfg(target_endian = "big")]
        cc.define("WORDS_BIGENDIAN", "");

        cc.define("BUCKETS_128", "1");
        cc.define("CHECKSUM_1B", "1");

        let mut enable_crypto = false;
        let mut use_authenticode = false;
        match get_crypto_lib() {
            CryptoLib::OpenSSL => {
                enable_crypto = true;
                use_authenticode = true;
                handle_openssl(&mut cc);
            }
            CryptoLib::BoringSSL => {
                enable_crypto = true;
                // This is required by YARA to distinguish OpenSSL from BoringSSL.
                cc.define("BORINGSSL", "1");
                // Do not enable authenticode, this needs OpenSSL.
                use_authenticode = false;
                handle_openssl(&mut cc);
            }
            CryptoLib::Wincrypt => {
                enable_crypto = true;
                cc.define("HAVE_WINCRYPT_H", "1");
                println!("cargo:rustc-link-lib=dylib=crypt32");
            }
            CryptoLib::CommonCrypto => {
                enable_crypto = true;
                cc.define("HAVE_COMMONCRYPTO_COMMONCRYPTO_H", "1");
                println!("cargo:rustc-link-lib=dylib=System");
            }
            CryptoLib::None => {}
        }

        if !use_authenticode {
            // authenticode parser part of the PE module only works with OpenSSL.
            let dir = basedir
                .join("modules")
                .join("pe")
                .join("authenticode-parser");
            for entry in glob::glob(&format!("{}/*.c", dir.display()))
                .unwrap()
                .flatten()
            {
                exclude.push(entry);
            }
        }

        if cfg!(feature = "module-hash") && enable_crypto {
            cc.define("HASH_MODULE", "1");
        } else {
            exclude.push(basedir.join("modules").join("hash").join("hash.c"));
        }
        if cfg!(feature = "profiling") {
            cc.define("YR_PROFILING_ENABLED", "1");
        }
        if cfg!(feature = "module-magic") {
            cc.define("MAGIC_MODULE", "1");
            println!("cargo:rustc-link-lib=dylib=magic");
        } else {
            exclude.push(basedir.join("modules").join("magic").join("magic.c"));
        }
        if cfg!(feature = "module-cuckoo") {
            cc.define("CUCKOO_MODULE", "1");
            println!("cargo:rustc-link-lib=dylib=jansson");
        } else {
            exclude.push(basedir.join("modules").join("cuckoo").join("cuckoo.c"));
        }
        if cfg!(feature = "module-dotnet") {
            cc.define("DOTNET_MODULE", "1");
        } else {
            exclude.push(basedir.join("modules").join("dotnet").join("dotnet.c"));
        }
        if cfg!(feature = "module-dex") {
            cc.define("DEX_MODULE", "1");
            if cfg!(feature = "module-debug-dex") {
                cc.define("DEBUG_DEX_MODULE", "1");
            }
        } else {
            exclude.push(basedir.join("modules").join("dex").join("dex.c"));
        }
        if cfg!(feature = "module-macho") {
            cc.define("MACHO_MODULE", "1");
        } else {
            exclude.push(basedir.join("modules").join("macho").join("macho.c"));
        }
        if cfg!(feature = "ndebug") {
            cc.define("NDEBUG", "1");
        }

        let verbosity =
            get_target_env_var("YARA_DEBUG_VERBOSITY").unwrap_or_else(|| "0".to_string());
        cc.define("YR_DEBUG_VERBOSITY", verbosity.as_str());

        for entry in glob::glob(&format!("{}/proc/*", basedir.display()))
            .unwrap()
            .flatten()
        {
            exclude.push(entry);
        }
        for entry in glob::glob(&format!("{}/**/*.c", basedir.display()))
            .unwrap()
            .flatten()
        {
            if !exclude.contains(&entry) {
                cc.file(entry);
            }
        }

        // Unfortunately, YARA compilation produces lots of warnings
        // Ignore some of them.
        cc.flag_if_supported("-Wno-deprecated-declarations")
            .flag_if_supported("-Wno-unused-parameter")
            .flag_if_supported("-Wno-unused-function")
            .flag_if_supported("-Wno-cast-function-type")
            .flag_if_supported("-Wno-type-limits")
            .flag_if_supported("-Wno-tautological-constant-out-of-range-compare")
            .flag_if_supported("-Wno-sign-compare"); // maybe this one shouldn't be silenced.

        cc.compile("yara");

        let include_dir = basedir.join("include");
        let lib_dir = std::env::var("OUT_DIR").unwrap();

        cargo_rerun_if_env_changed("YARA_DEBUG_VERBOSITY");
        cargo_rerun_if_env_changed("YARA_OPENSSL_DIR");
        cargo_rerun_if_env_changed("YARA_OPENSSL_LIB_DIR");
        cargo_rerun_if_env_changed("YARA_OPENSSL_INCLUDE_DIR");
        cargo_rerun_if_env_changed("YARA_LIBRARY_PATH");
        cargo_rerun_if_env_changed("YARA_CRYPTO_LIB");

        println!("cargo:rustc-link-search=native={lib_dir}");
        println!("cargo:rustc-link-lib=static=yara");
        println!("cargo:include={}", include_dir.display());
        println!("cargo:lib={lib_dir}");

        // tell the add_bindings phase to generate bindings from `include_dir`.
        std::env::set_var("YARA_INCLUDE_DIR", include_dir);
    }
}

#[cfg(not(feature = "vendored"))]
mod build {
    use super::cargo_rerun_if_env_changed;
    use super::get_target_env_var;

    /// Tell cargo to tell rustc to link the system yara
    /// shared library.
    pub fn build_and_link() {
        if cfg!(feature = "yara-static") {
            println!("cargo:rustc-link-lib=static=yara");
        } else if std::env::var("CARGO_CFG_TARGET_ENV").unwrap() == "musl" {
            panic!(
                "musl target does not support dynamic linking, please use feature `yara-static`"
            );
        } else {
            println!("cargo:rustc-link-lib=dylib=yara");
        }

        // Add the environment variable YARA_LIBRARY_PATH to the library search path.
        if let Some(yara_library_path) =
            get_target_env_var("YARA_LIBRARY_PATH").filter(|path| !path.is_empty())
        {
            println!("cargo:rustc-link-search=native={}", yara_library_path);
        }
        cargo_rerun_if_env_changed("YARA_LIBRARY_PATH");
    }
}

#[cfg(feature = "bundled-4_5_0")]
mod bindings {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    pub fn add_bindings() {
        let binding_file = format!("yara-4.5.0-{}.rs", env::var("TARGET").unwrap());
        let binding_path = PathBuf::from("bindings").join(binding_file);
        let out_dir = env::var("OUT_DIR").expect("$OUT_DIR should be defined");
        let out_path = PathBuf::from(out_dir).join("bindings.rs");
        if binding_path.is_file() {
            fs::copy(binding_path, out_path).expect("Could not copy bindings to output directory");
        } else {
            println!(
                "cargo:warning=Bindigs for target=\"{}\" does not exists",
                env::var("TARGET").unwrap()
            );
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "bundled-4_5_0"))]
mod bindings {
    use std::env;
    use std::path::PathBuf;

    use super::cargo_rerun_if_env_changed;
    use super::get_target_env_var;

    pub fn add_bindings() {
        let mut builder = bindgen::Builder::default()
            .header("wrapper.h")
            .allowlist_var("CALLBACK_.*")
            .allowlist_var("ERROR_.*")
            .allowlist_var("META_TYPE_.*")
            .allowlist_var("META_FLAGS_LAST_IN_RULE")
            .allowlist_var("OBJECT_TYPE_.*")
            .allowlist_var("STRING_FLAGS_LAST_IN_RULE")
            .allowlist_var("RULE_FLAGS_NULL")
            .allowlist_var("YARA_ERROR_LEVEL_.*")
            .allowlist_var("SCAN_FLAGS_.*")
            .allowlist_var("YR_CONFIG_.*")
            .allowlist_var("_YR_CONFIG_.*")
            .allowlist_var("_YR_CONFIG_NAME")
            .allowlist_var("YR_CONFIG_NAME")
            .allowlist_var("YR_CONFIG_STACK_SIZE")
            .allowlist_var("YR_UNDEFINED")
            .allowlist_function("yr_set_configuration_uint32")
            .allowlist_function("yr_set_configuration_uint64")
            .allowlist_function("yr_get_configuration_uint32")
            .allowlist_function("yr_get_configuration_uint64")
            .allowlist_function("yr_initialize")
            .allowlist_function("yr_finalize")
            .allowlist_function("yr_finalize_thread")
            .allowlist_function("yr_compiler_.*")
            .allowlist_function("yr_rule_.*")
            .allowlist_function("yr_rules_.*")
            .allowlist_function("yr_scanner_.*")
            .allowlist_type("YR_MATCH")
            .allowlist_type("YR_META")
            .allowlist_type("YR_OBJECT")
            .allowlist_type("YR_OBJECT_STRUCTURE")
            .allowlist_type("YR_OBJECT_ARRAY")
            .allowlist_type("YR_OBJECT_DICTIONARY")
            .allowlist_type("YR_RULES")
            // XXX: Ideally, YR_COMPILER would be marked as opaque. Unfortunately, because it
            // contains a jmp_buf that is, on x64 windows msvc, aligned on 16-bytes, this generates
            // a u128 array, which triggers many improper_ctypes warnings.
            // To avoid those warnings, the YR_COMPILER is not opaque, but we try to make its
            // direct dependencies opaque, to avoid bloating the filesize.
            .allowlist_type("YR_ARENA")
            .allowlist_type("YR_AC_AUTOMATON")
            .allowlist_type("YR_AC_MATCH")
            .allowlist_type("YR_ATOMS_CONFIG")
            .allowlist_type("YR_MODULE_IMPORT")
            .opaque_type("YR_AC_.*")
            .opaque_type("YR_ATOMS_CONFIG")
            .opaque_type("YR_FIXUP")
            .opaque_type("YR_LOOP_CONTEXT")
            .size_t_is_usize(false);

        if let Some(yara_include_dir) =
            get_target_env_var("YARA_INCLUDE_DIR").filter(|dir| !dir.is_empty())
        {
            builder = builder.clang_arg(format!("-I{yara_include_dir}"))
        }

        let bindings = builder.generate().expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");

        cargo_rerun_if_env_changed("YARA_INCLUDE_DIR");
    }
}

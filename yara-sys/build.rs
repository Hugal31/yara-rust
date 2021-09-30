// Inspired from https://github.com/jgallagher/rusqlite/blob/master/libsqlite3-sys/build.rs

fn main() {
    build::build_and_link();
    bindings::add_bindings();
}

fn get_env_var(env_var: &str) -> Option<String> {
    let target = std::env::var("TARGET").unwrap();
    std::env::var(format!("{}_{}", env_var, target))
        .or(std::env::var(format!(
            "{}_{}",
            env_var,
            target.replace("-", "_")
        )))
        .or(std::env::var(env_var))
        .ok()
}

fn is_enable(env_var: &str, default: bool) -> bool {
    match get_env_var(env_var).as_deref() {
        Some("0") => false,
        Some(_) => true,
        None => default,
    }
}

#[cfg(feature = "vendored")]
mod build {
    use super::get_env_var;
    use super::is_enable;
    use std::path::PathBuf;

    use globwalk;
    use libloading::Library;
    use std::env::consts::DLL_SUFFIX;
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;

    pub fn build_and_link() {
        let old_basedir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("yara");
        let out_dir = std::env::var("OUT_DIR").map(PathBuf::from).unwrap();
        let basedir = out_dir.join("yara");
        if !basedir.exists() {
            symlink_dir(old_basedir, &basedir).unwrap();
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
                .define("USE_WINDOWS_PROC", "")
                .define("HAVE_WINCRYPT_H", ""),
            "linux" => cc
                .file(basedir.join("proc").join("linux.c"))
                .define("USE_LINUX_PROC", ""),
            "macos" => cc
                .file(basedir.join("proc").join("mach.c"))
                .define("USE_MACH_PROC", "")
                .define("HAVE_COMMONCRYPTO_COMMONCRYPTO_H", ""),
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

        let mut enable_crypto = false;
        if is_enable("YARA_ENABLE_CRYPTO", true) {
            let mut libcrypto = format!("libcrypto{}", DLL_SUFFIX);
            if let Some(openssl_lib_dir) = get_env_var("OPENSSL_LIB_DIR") {
                let mut buffer = PathBuf::from(openssl_lib_dir);
                println!("cargo:rustc-link-search=native={}", buffer.display());
                buffer.push(libcrypto);
                libcrypto = buffer.to_str().unwrap().to_string();
            }

            let load_result = unsafe { Library::new(libcrypto) };
            if let Err(err) = load_result {
                println!("cargo:warning=Please install OpenSSL library");
                println!("cargo:warning={:?}", err);
                std::process::exit(1);
            }
            else {
                enable_crypto = true;
                cc.define("HAVE_LIBCRYPTO", "1");
                if std::env::var("CARGO_CFG_TARGET_FAMILY")
                    .ok()
                    .unwrap()
                    .as_str()
                    == "windows"
                {
                    println!("cargo:rustc-link-lib=dylib=libssl");
                    println!("cargo:rustc-link-lib=dylib=libcrypto");
                    println!("cargo:rustc-link-lib=dylib=Crypt32");
                    println!("cargo:rustc-link-lib=dylib=Ws2_32")
                } else {
                    println!("cargo:rustc-link-lib=dylib=ssl");
                    println!("cargo:rustc-link-lib=dylib=crypto");
                }
            }
        }

        if is_enable("YARA_ENABLE_HASH", false) && enable_crypto {
            cc.define("HASH_MODULE", "1");
        } else {
            exclude.push(basedir.join("modules").join("hash").join("hash.c"));
        }
        if is_enable("YARA_ENABLE_PROFILING", false) {
            cc.define("YR_PROFILING_ENABLED", "1");
        }
        if is_enable("YARA_ENABLE_MAGIC", false) {
            cc.define("MAGIC_MODULE", "1");
            println!("cargo:rustc-link-lib=dylib=magic");
        } else {
            exclude.push(basedir.join("modules").join("magic").join("magic.c"));
        }
        if is_enable("YARA_ENABLE_CUCKOO", false) {
            cc.define("CUCKOO_MODULE", "1");
            println!("cargo:rustc-link-lib=dylib=jansson");
        } else {
            exclude.push(basedir.join("modules").join("cuckoo").join("cuckoo.c"));
        }
        if is_enable("YARA_ENABLE_DOTNET", true) {
            cc.define("DOTNET_MODULE", "1");
        } else {
            exclude.push(basedir.join("modules").join("dotnet").join("dotnet.c"));
        }
        if is_enable("YARA_ENABLE_DEX", true) {
            cc.define("DEX_MODULE", "1");
            if is_enable("YARA_ENABLE_DEX_DEBUG", false) {
                cc.define("DEBUG_DEX_MODULE", "1");
            }
        } else {
            exclude.push(basedir.join("modules").join("dex").join("dex.c"));
        }
        if is_enable("YARA_ENABLE_MACHO", true) {
            cc.define("MACHO_MODULE", "1");
        } else {
            exclude.push(basedir.join("modules").join("macho").join("macho.c"));
        }
        if is_enable("YARA_ENABLE_NDEBUG", true) {
            cc.define("NDEBUG", "1");
        }

        let verbosity = get_env_var("YARA_DEBUG_VERBOSITY").unwrap_or("0".to_string());
        cc.define("YR_DEBUG_VERBOSITY", verbosity.as_str());

        let walker = globwalk::GlobWalkerBuilder::from_patterns(&basedir, &["**/*.c", "!proc/*"])
            .build()
            .unwrap()
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| !exclude.contains(&e.path().to_path_buf()));
        for entry in walker {
            cc.file(entry.path());
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

        println!("cargo:rustc-link-search=native={}", lib_dir);
        println!("cargo:rustc-link-lib=static=yara");
        println!("cargo:include={}", include_dir.display());
        println!("cargo:lib={}", lib_dir);

        // tell the add_bindings phase to generate bindings from `include_dir`.
        std::env::set_var("YARA_INCLUDE_DIR", include_dir);
    }
}

#[cfg(not(feature = "vendored"))]
mod build {
    use super::get_env_var;
    use super::is_enable;

    /// Tell cargo to tell rustc to link the system yara
    /// shared library.
    pub fn build_and_link() {
        let kind = if is_enable("LIBYARA_STATIC", false) {
            "static"
        } else {
            "dylib"
        };
        println!("cargo:rustc-link-lib={}=yara", kind);

        // Add the environment variable YARA_LIBRARY_PATH to the library search path.
        if let Some(yara_library_path) =
            get_env_var("YARA_LIBRARY_PATH").filter(|path| !path.is_empty())
        {
            println!("cargo:rustc-link-search=native={}", yara_library_path);
        }
    }
}

#[cfg(feature = "bundled-4_1_2")]
mod bindings {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    pub fn add_bindings() {
        let binding_file = match env::var("CARGO_CFG_TARGET_FAMILY").unwrap().as_ref() {
            "unix" => "yara-4.1.2-unix.rs",
            "windows" => "yara-4.1.2-windows.rs",
            f => panic!("no bundled bindings for family {}", f),
        };
        let out_dir = env::var("OUT_DIR").expect("$OUT_DIR should be defined");
        let out_path = PathBuf::from(out_dir).join("bindings.rs");
        fs::copy(PathBuf::from("bindings").join(binding_file), out_path)
            .expect("Could not copy bindings to output directory");
    }
}

#[cfg(not(feature = "bundled-4_1_2"))]
mod bindings {
    extern crate bindgen;

    use std::env;
    use std::path::PathBuf;

    use crate::get_env_var;

    pub fn add_bindings() {
        let mut builder = bindgen::Builder::default()
            .header("wrapper.h")
            .allowlist_var("CALLBACK_.*")
            .allowlist_var("ERROR_.*")
            .allowlist_var("META_TYPE_.*")
            .allowlist_var("META_FLAGS_LAST_IN_RULE")
            .allowlist_var("STRING_FLAGS_LAST_IN_RULE")
            .allowlist_var("YARA_ERROR_LEVEL_.*")
            .allowlist_var("SCAN_FLAGS_.*")
            .allowlist_var("YR_CONFIG_.*")
            .allowlist_function("yr_set_configuration")
            .allowlist_function("yr_get_configuration")
            .allowlist_function("yr_initialize")
            .allowlist_function("yr_finalize")
            .allowlist_function("yr_finalize_thread")
            .allowlist_function("yr_compiler_.*")
            .allowlist_function("yr_rule_.*")
            .allowlist_function("yr_rules_.*")
            .allowlist_function("yr_scanner_.*")
            .allowlist_type("YR_ARENA")
            .allowlist_type("YR_EXTERNAL_VARIABLE")
            .allowlist_type("YR_MATCH")
            .opaque_type("YR_COMPILER")
            .opaque_type("YR_AC_MATCH_TABLE")
            .opaque_type("YR_AC_TRANSITION_TABLE")
            .opaque_type("_YR_EXTERNAL_VARIABLE");

        if let Some(yara_include_dir) =
            get_env_var("YARA_INCLUDE_DIR").filter(|dir| !dir.is_empty())
        {
            builder = builder.clang_arg(format!("-I{}", yara_include_dir))
        }

        let bindings = builder.generate().expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}

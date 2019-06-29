fn main() {

    // Tell cargo to tell rustc to link statically to the Yara lib and its dependencies
    #[cfg(target_os = "macos")]
    {
        // These are the locations of individual libraries installed by Homebrew.
        // macOS OpenSSL shenanigans means it's best to just explicitly say where each of
        // the dependencies lives.
        // Install depedencies with `brew install yara openssl jansson libmagic zlib`
        println!("cargo:rustc-link-search=/usr/local/opt/jansson/lib");
        println!("cargo:rustc-link-search=/usr/local/opt/libmagic/lib");
        println!("cargo:rustc-link-search=/usr/local/opt/openssl/lib");
        println!("cargo:rustc-link-search=/usr/local/opt/yara/lib");
        println!("cargo:rustc-link-search=/usr/local/opt/zlib/lib");
    }
    #[cfg(target_os = "openbsd")]
    {
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-search=/usr/lib");
    }
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu/");
        println!("cargo:rustc-link-search=/usr/local/lib");
    }
    
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=jansson");
    println!("cargo:rustc-link-lib=static=magic");
    println!("cargo:rustc-link-lib=static=yara");
    println!("cargo:rustc-link-lib=static=z");

    build::add_bindings();
}

mod build {
    extern crate bindgen;

    use std::env;
    use std::path::PathBuf;

    pub fn add_bindings() {

        // Initialise some bindings with the header wrapper
        let mut bindings = bindgen::Builder::default()
            .header("wrapper.h");

        // Whitelist specific variables
        for wlvar in &[
            "CALLBACK_.*",
            "ERROR_.*",
            "META_TYPE_.*",
            "STRING_GFLAGS_NULL",
            "YARA_ERROR_LEVEL_.*"
        ] {
            bindings = bindings.whitelist_var(wlvar);
        }

        // Whitelist specific functions
        for wlfunc in &[
            "yr_initialize",
            "yr_finalize",
            "yr_compiler_.*",
            "yr_rule_.*",
            "yr_rules_.*",
            "yr_get_tidx"
        ] {
            bindings = bindings.whitelist_function(wlfunc);
        }

        // Opaque types
        for opqtype in &[
            "YR_COMPILER",
            "YR_ARENA",
            "YR_AC_MATCH_TABLE",
            "YR_AC_TRANSITION_TABLE"
        ] {
            bindings = bindings.opaque_type(opqtype);
        }

        // macOS explicit homebrew include paths
        #[cfg(target_os = "macos")]
        {
            for path in &[
                "/usr/local/opt/jansson/include",
                "/usr/local/opt/libmagic/include",
                "/usr/local/opt/openssl/include",
                "/usr/local/opt/yara/include",
                "/usr/local/opt/zlib/include"
            ] {
                let include_path = format!("-I{}", path);
                bindings = bindings.clang_arg(include_path);
            }
        }
        // OpenBSD include path
        #[cfg(target_os = "openbsd")]
        {
            bindings = bindings.clang_arg("-I/usr/local/include");
        }

        // Finalise our bindings
        let bindings = bindings.generate().expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
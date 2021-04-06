// Inspired from https://github.com/jgallagher/rusqlite/blob/master/libsqlite3-sys/build.rs

use std::env;

#[cfg(feature = "vendored")]
extern crate yara_src;

fn main() {
    #[cfg(feature = "vendored")]
    {
        yara_src::build();
        yara_src::set_env();
    }

    // Tell cargo to tell rustc to link the system yara
    // shared library.
    link("yara");

    // Add the environment variable YARA_LIBRARY_PATH to the library search path.
    if let Some(yara_library_path) = std::env::var("YARA_LIBRARY_PATH")
        .ok()
        .filter(|path| !path.is_empty())
    {
        println!("cargo:rustc-link-search=native={}", yara_library_path);
    }

    build::add_bindings();
}

fn link(lib: &str) {
    println!("cargo:rustc-link-lib={}={}", lib_mode(lib), lib);
}

fn lib_mode(lib: &str) -> &'static str {
    let kind = env::var(&format!("LIB{}_STATIC", lib.to_uppercase()));
    match kind.ok().as_deref() {
        Some("0") => "dylib",
        Some(_) => "static",
        None => "dylib",
    }
}

#[cfg(feature = "bundled-4_0")]
mod build {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    const BINDING_FILE: &'static str = "yara-4.0.rs";

    pub fn add_bindings() {
        let out_dir = env::var("OUT_DIR").expect("$OUT_DIR should be defined");
        let out_path = PathBuf::from(out_dir).join("bindings.rs");
        fs::copy(PathBuf::from("bindings").join(BINDING_FILE), out_path)
            .expect("Could not copy bindings to output directory");
    }
}

#[cfg(not(feature = "bundled-4_0"))]
mod build {
    extern crate bindgen;

    use std::env;
    use std::path::PathBuf;

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

        if let Some(yara_include_dir) = env::var("YARA_INCLUDE_DIR")
            .ok()
            .filter(|dir| !dir.is_empty())
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

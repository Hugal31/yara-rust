// Inspired from https://github.com/jgallagher/rusqlite/blob/master/libsqlite3-sys/build.rs

fn main() {
    // Tell cargo to tell rustc to link the system yara
    // shared library.
    println!("cargo:rustc-link-lib=yara");

    build::add_bindings();
}

#[cfg(not(feature = "bindgen"))]
mod build {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    pub fn add_bindings() {
        let out_dir = env::var("OUT_DIR").unwrap();
        let out_path = PathBuf::from(out_dir).join("bindings.rs");
        fs::copy("bindings/yara-3.7.rs", out_path)
            .expect("Could not copy bindings to output directory");
    }
}

#[cfg(feature = "bindgen")]
mod build {
    extern crate bindgen;

    use std::env;
    use std::path::PathBuf;

    pub fn add_bindings() {
        let bindings = bindgen::Builder::default()
            .header("wrapper.h")
            .whitelist_var("CALLBACK_.*")
            .whitelist_var("ERROR_.*")
            .whitelist_var("META_TYPE_.*")
            .whitelist_var("STRING_GFLAGS_NULL")
            .whitelist_var("YARA_ERROR_LEVEL_.*")
            .whitelist_function("yr_initialize")
            .whitelist_function("yr_finalize")
            .whitelist_function("yr_compiler_.*")
            .whitelist_function("yr_rule_.*")
            .whitelist_function("yr_rules_.*")
            .whitelist_function("yr_get_tidx")
            .opaque_type("YR_COMPILER")
            .opaque_type("YR_ARENA")
            .opaque_type("YR_AC_MATCH_TABLE")
            .opaque_type("YR_AC_TRANSITION_TABLE")
            .opaque_type("YR_EXTERNAL_VARIABLE")
            .generate()
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}

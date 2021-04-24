// Inspired from https://github.com/jgallagher/rusqlite/blob/master/libsqlite3-sys/build.rs

fn main() {
    build::build_and_link();
    bindings::add_bindings();
}

#[cfg(feature = "vendored")]
mod build {
    use std::path::PathBuf;

    pub fn build_and_link() {
        let basedir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("yara");

        let mut cc = cc::Build::new();

        cc
            .include(basedir.join("libyara"))
            .include(basedir.join("libyara/include"))

            .file(basedir.join("libyara/ahocorasick.c"))
            .file(basedir.join("libyara/arena.c"))
            .file(basedir.join("libyara/atoms.c"))
            .file(basedir.join("libyara/bitmask.c"))
            .file(basedir.join("libyara/compiler.c"))
            .file(basedir.join("libyara/endian.c"))
            .file(basedir.join("libyara/exec.c"))
            .file(basedir.join("libyara/exefiles.c"))
            .file(basedir.join("libyara/filemap.c"))
            .file(basedir.join("libyara/grammar.c"))
            .file(basedir.join("libyara/hash.c"))
            .file(basedir.join("libyara/hex_grammar.c"))
            .file(basedir.join("libyara/hex_lexer.c"))
            .file(basedir.join("libyara/lexer.c"))
            .file(basedir.join("libyara/libyara.c"))
            .file(basedir.join("libyara/mem.c"))
            .file(basedir.join("libyara/object.c"))
            .file(basedir.join("libyara/parser.c"))
            .file(basedir.join("libyara/proc.c"))
            .file(basedir.join("libyara/re.c"))
            .file(basedir.join("libyara/re_grammar.c"))
            .file(basedir.join("libyara/re_lexer.c"))
            .file(basedir.join("libyara/rules.c"))
            .file(basedir.join("libyara/scan.c"))
            .file(basedir.join("libyara/scanner.c"))
            .file(basedir.join("libyara/sizedstr.c"))
            .file(basedir.join("libyara/stack.c"))
            .file(basedir.join("libyara/stopwatch.c"))
            .file(basedir.join("libyara/stream.c"))
            .file(basedir.join("libyara/strutils.c"))
            .file(basedir.join("libyara/threading.c"))

            .file(basedir.join("libyara/modules.c"))
            .file(basedir.join("libyara/modules/elf.c"))
            .file(basedir.join("libyara/modules/math.c"))
            .file(basedir.join("libyara/modules/pe.c"))
            .file(basedir.join("libyara/modules/pe_utils.c"))
            .file(basedir.join("libyara/modules/tests.c"))
            .file(basedir.join("libyara/modules/time.c"))

            .define("DEX_MODULE", "")
            .file(basedir.join("libyara/modules/dex.c"))

            .define("DOTNET_MODULE", "")
            .file(basedir.join("libyara/modules/dotnet.c"))

            .define("MACHO_MODULE", "")
            .file(basedir.join("libyara/modules/macho.c"))

            .define("NDEBUG", "1");

        // Use correct proc functions
        match std::env::var("CARGO_CFG_TARGET_OS").ok().unwrap().as_str() {
            "windows"
                => cc.file(basedir.join("libyara/proc/windows.c"))
                    .define("USE_WINDOWS_PROC", ""),
            "linux"
                => cc.file(basedir.join("libyara/proc/linux.c"))
                    .define("USE_LINUX_PROC", ""),
            "macos"
                => cc.file(basedir.join("libyara/proc/mach.c"))
                    .define("USE_MACH_PROC", ""),
            _
                => cc.file(basedir.join("libyara/proc/none.c"))
                     .define("USE_NO_PROC", ""),
        };

        if std::env::var("CARGO_CFG_TARGET_FAMILY").ok().unwrap().as_str() != "windows" {
            cc.define("POSIX", "");
        };

        // Unfortunately, YARA compilation produces lots of warnings
        cc.warnings(false);

        cc.compile("yara");

        let include_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("yara/libyara/include");
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
    /// Tell cargo to tell rustc to link the system yara
    /// shared library.
    pub fn build_and_link() {
        let kind = match std::env::var("LIBYARA_STATIC").ok().as_deref() {
            Some("0") => "dylib",
            Some(_) => "static",
            None => "dylib",
        };
        println!("cargo:rustc-link-lib={}=yara", kind);

        // Add the environment variable YARA_LIBRARY_PATH to the library search path.
        if let Some(yara_library_path) = std::env::var("YARA_LIBRARY_PATH")
            .ok()
            .filter(|path| !path.is_empty())
        {
            println!("cargo:rustc-link-search=native={}", yara_library_path);
        }
    }
}

#[cfg(any(feature = "bundled-3_8",
	  feature = "bundled-3_11"))]
mod bindings {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    pub fn add_bindings() {
    #[cfg(feature = "bundled-3_11")]
    let binding_file = match env::var("CARGO_CFG_TARGET_FAMILY").unwrap().as_ref() {
        "windows" => "yara-3.11-windows.rs",
        "unix"    => "yara-3.11-unix.rs",
        f => panic!("no bundled bindings for family {}", f),
    };
    #[cfg(feature = "bundled-3_8")]
    let binding_file = match env::var("CARGO_CFG_TARGET_FAMILY").unwrap().as_ref() {
        "windows" => "yara-3.8-windows.rs",
        "unix"    => "yara-3.8-unix.rs",
        f => panic!("no bundled bindings for family {}", f),
    };
	let out_dir = env::var("OUT_DIR")
	    .expect("$OUT_DIR should be defined");
	let out_path = PathBuf::from(out_dir).join("bindings.rs");
	fs::copy(PathBuf::from("bindings").join(binding_file), out_path)
	    .expect("Could not copy bindings to output directory");
    }
}

#[cfg(not(any(feature = "bundled-3_8",
	      feature = "bundled-3_11")))]
mod bindings {
    extern crate bindgen;

    use std::env;
    use std::path::PathBuf;

    pub fn add_bindings() {
        let mut builder = bindgen::Builder::default()
            .header("wrapper.h")
            .whitelist_var("CALLBACK_.*")
            .whitelist_var("ERROR_.*")
            .whitelist_var("META_TYPE_.*")
            .whitelist_var("STRING_GFLAGS_NULL")
            .whitelist_var("YARA_ERROR_LEVEL_.*")
            .whitelist_var("SCAN_FLAGS_.*")
            .whitelist_function("yr_initialize")
            .whitelist_function("yr_finalize")
            .whitelist_function("yr_finalize_thread")
            .whitelist_function("yr_compiler_.*")
            .whitelist_function("yr_rule_.*")
            .whitelist_function("yr_rules_.*")
            .whitelist_function("yr_scanner_.*")
            .whitelist_function("yr_get_tidx")
            .whitelist_type("YR_EXTERNAL_VARIABLE")
	    .whitelist_type("YR_MATCH")
            .opaque_type("YR_COMPILER")
            .opaque_type("YR_ARENA")
            .opaque_type("YR_AC_MATCH_TABLE")
            .opaque_type("YR_AC_TRANSITION_TABLE")
            .opaque_type("_YR_EXTERNAL_VARIABLE");

	if let Some(yara_include_dir) = env::var("YARA_INCLUDE_DIR")
	    .ok()
	    .filter(|dir| !dir.is_empty())
	{
	    builder = builder.clang_arg(format!("-I{}", yara_include_dir))
	}

	let bindings = builder
            .generate()
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}

extern crate yara;

use yara::{CompileErrorLevel, Error, Yara};

const RULES: &str = "
rule is_awesome: a_tag another_tag {
  strings:
    $rust = \"rust\" nocase

  condition:
    $rust
}

rule is_ok {
  strings:
    $go = \"go\"

  condition:
    $go
}";

#[test]
fn test_initialize() {
    assert!(Yara::create().is_ok());
}

#[test]
fn test_create_compiler() {
    let mut yara = Yara::create().unwrap();
    assert!(yara.new_compiler().is_ok());
}

#[test]
fn test_compile_string_rules() {
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    assert!(compiler.add_rules_str(RULES).is_ok());
    assert!(compiler.add_rules_str("nop.").is_err());
}

#[test]
fn test_compile_error() {
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    let err = compiler.add_rules_str("rule nop {\n").unwrap_err();
    if let Error::Compile(compile_error) = err {
        let first_error = compile_error.iter().next().unwrap();
        assert_eq!(CompileErrorLevel::Error, first_error.level);
    } else {
        panic!("Expected Error::Compile, found {:?}", err);
    }
}

#[test]
fn test_compile_file_rules() {
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    assert!(compiler.add_rules_file("tests/rules.txt").is_ok());
}

#[test]
fn test_scan_mem() {
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    compiler.add_rules_str(RULES).expect("Should be Ok");
    let mut rules = compiler.compile_rules().unwrap();
    let result = rules.scan_mem("I love Rust!".as_bytes(), 10);

    let result = result.expect("Should be Ok");
    assert_eq!(1, result.len());
    assert_eq!("is_awesome", result[0].identifier);
    assert_eq!(&["a_tag", "another_tag"], result[0].tags.as_slice());
    assert_eq!(1, result[0].strings.len());
    assert_eq!("$rust", result[0].strings[0].identifier);
    assert_eq!(1, result[0].strings[0].matches.len());
    assert_eq!(7, result[0].strings[0].matches[0].offset);
    assert_eq!(b"Rust", result[0].strings[0].matches[0].data.as_slice());
}

extern crate yara;

use std::fs::remove_file;

use yara::Yara;

const RULES: &str = "
rule is_awesome {
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
    assert!(compiler.add_rule_str(RULES).is_ok());
    assert!(compiler.add_rule_str("nop.").is_err());
}

#[test]
fn test_save_and_load() {
    const RULES_FILE: &str = "test_save_1.yar";

    let _ = remove_file(RULES_FILE);

    let mut yara = Yara::create().unwrap();

    {
        let mut compiler = yara.new_compiler().unwrap();
        compiler
            .add_rule_str(RULES)
            .expect("add_rule_str should not fail");
        let mut rules = compiler.compile_rules().unwrap();
        rules.save(RULES_FILE).expect("Should be Ok");
    }

    {
        let rules = yara.load_rules(RULES_FILE);
        assert!(rules.is_ok());
    }

    remove_file(RULES_FILE).expect("Should have remove rule file");
}

#[test]
fn test_scan_mem() {
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    compiler.add_rule_str(RULES).expect("Should be Ok");
    let mut rules = compiler.compile_rules().unwrap();
    let result = rules.scan_mem("I love Rust!".as_bytes(), 10);

    let result = result.expect("Should be Ok");
    assert_eq!(1, result.len());
    assert_eq!("is_awesome", result[0].identifier);
    assert_eq!(1, result[0].strings.len());
    assert_eq!("$rust", result[0].strings[0].identifier);
    assert_eq!(1, result[0].strings[0].matches.len());
    assert_eq!(7, result[0].strings[0].matches[0].offset);
    assert_eq!(
        "Rust".as_bytes(),
        result[0].strings[0].matches[0].data.as_slice()
    );
}

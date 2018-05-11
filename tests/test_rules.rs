extern crate yara;

use std::fs::remove_file;

use yara::Yara;

const VALID_RULE: &str = "rule is_awesome {
  strings:
    $rust = \"rust\"

  condition:
    $rust
}";

#[test]
fn test_compile_string_rules() {
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    assert!(compiler.add_rule_str(VALID_RULE).is_ok());
    assert!(compiler.add_rule_str("nop.").is_err());
}

#[test]
fn test_save() {
    const RULES_FILE: &str = "test_save.yar";

    let _ = remove_file(RULES_FILE);

    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    compiler.add_rule_str(VALID_RULE);
    let mut rules = compiler.get_rules().unwrap();
    rules.save(RULES_FILE);

    // TODO Assert file exists
    let _ = remove_file(RULES_FILE);
}

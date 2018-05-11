extern crate yara;

use yara::Yara;

const VALID_RULE: &str = "rule is_awesome {
  strings:
    $rust = \"rust\"

  condition:
    $rust
}";

#[test]
fn test_scan_mem() {
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    compiler.add_rule_str(VALID_RULE);
    let mut rules = compiler.get_rules().unwrap();
    let result = rules.scan_mem("I love rust!".as_bytes(), 10);
    assert!(result.is_ok());
}

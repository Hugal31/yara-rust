extern crate yara;

use std::fs::remove_file;

use yara::Yara;

const RULES_FILE: &str = "test_save_1.yar";

const RULES: &str = "rule a_rule {
  condition:
    filesize > 0
}
";

fn test_save() {
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    compiler
        .add_rules_str(RULES)
        .expect("add_rules_str should not fail");
    let mut rules = compiler.compile_rules().unwrap();
    rules.save(RULES_FILE).expect("Should be Ok");
}

fn test_load() {
    let mut yara = Yara::create().unwrap();
    assert!(yara.load_rules(RULES_FILE).is_ok());
}

#[test]
fn test_save_and_load() {
    let _ = remove_file(RULES_FILE);
    test_save();
    test_load();
    remove_file(RULES_FILE).expect("Should have remove rule file");
}

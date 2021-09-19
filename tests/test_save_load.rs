extern crate yara;

use std::fs::remove_file;

use yara::{Compiler, Rules};

const RULES_FILE: &str = "test_save_1.yar";

const RULES: &str = "rule a_rule {
  condition:
    filesize > 0
}
";

fn test_save() {
    let compiler = Compiler::new()
        .unwrap()
        .add_rules_str(RULES)
        .expect("add_rules_str should not fail");
    let mut rules = compiler.compile_rules().unwrap();
    rules.save(RULES_FILE).expect("Should be Ok");
}

fn test_load() {
    assert!(Rules::load_from_file(RULES_FILE).is_ok());
}

#[test]
fn test_save_and_load() {
    let _ = remove_file(RULES_FILE);
    test_save();
    test_load();
    remove_file(RULES_FILE).expect("Should have remove rule file");
}

use yara::Compiler;

const RULES: &str = r#"
    rule contains_rust {
      strings:
        $rust = "rust" nocase
      condition:
        $rust
    }
"#;
const RULES2: &str = r#"
    rule contains_rust_too {
      strings:
        $more_rust = "rust" nocase
      condition:
        $more_rust
    }
"#;

fn main() {
    let compiler = Compiler::new().unwrap();
    let compiler = compiler
        .add_rules_str(RULES)
        .expect("Should have parsed rule");
    let compiler = compiler
        .add_rules_str(RULES2)
        .expect("Should have parsed rule");
    let ruleset = compiler
        .compile_rules()
        .expect("Should have compiled rules");

    let mut rules = ruleset.get_rules();
    for (i, rule) in rules.iter_mut().enumerate() {
        println!("{}: {}", i, rule.identifier);
        if i % 2 == 1 {
            rule.disable()
        }
    }

    let results = ruleset
        .scan_mem("I love Rust!".as_bytes(), 5)
        .expect("Should have scanned");

    assert_eq!(results.len(), 1);
    assert!(results.iter().any(|r| r.identifier == "contains_rust"));
}

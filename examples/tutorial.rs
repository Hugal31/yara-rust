use yara::Compiler;

const RULES: &str = r#"
    rule contains_rust {
      strings:
        $rust = "rust" nocase
      condition:
        $rust
    }
"#;

fn main() {
    let compiler = Compiler::new().unwrap();
    let compiler = compiler
        .add_rules_str(RULES)
        .expect("Should have parsed rule");
    let rules = compiler
        .compile_rules()
        .expect("Should have compiled rules");
    let results = rules
        .scan_mem("I love Rust!".as_bytes(), 5)
        .expect("Should have scanned");
    assert!(results.iter().any(|r| r.identifier == "contains_rust"));
}

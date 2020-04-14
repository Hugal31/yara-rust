extern crate yara;

use yara::{CompileErrorLevel, Compiler, Error, Metadata, MetadataValue, Rules, Yara};

const RULES: &str = r#"
rule is_awesome {
  strings:
    $rust = /[Rr]ust/

  condition:
    $rust
}

rule is_ok {
  strings:
    $go = "go"

  condition:
    $go
}"#;

fn compile(rule: &str) -> Rules {
    let mut compiler = Compiler::new().expect("Should create compiler");
    compiler.add_rules_str(rule).expect("Should parse rule");
    compiler.compile_rules().expect("Should compile rules")
}

fn get_default_rules() -> Rules {
    compile(RULES)
}

fn compile_with_namespace(rule: &str, namespace: &str) -> Rules {
    let mut compiler = Compiler::new().expect("Should create compiler");
    compiler
        .add_rules_str_with_namespace(rule, namespace)
        .expect("Should parse rule");
    compiler.compile_rules().expect("Should compile rules")
}

#[test]
fn test_initialize() {
    assert!(Yara::new().is_ok());
}

#[test]
fn test_create_compiler() {
    assert!(Compiler::new().is_ok());
}

#[test]
fn test_compile_string_rules() {
    let mut compiler = Compiler::new().unwrap();
    assert!(compiler.add_rules_str(RULES).is_ok());
    assert!(compiler.add_rules_str("nop.").is_err());
}

#[test]
fn test_compile_error() {
    let mut compiler = Compiler::new().unwrap();
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
    let mut compiler = Compiler::new().unwrap();
    assert!(compiler.add_rules_file("tests/rules.txt").is_ok());
}

#[test]
fn test_scan_mem() {
    let rules = get_default_rules();
    let result = rules.scan_mem("I love Rust!".as_bytes(), 10);

    let result = result.expect("Should be Ok");
    let rule = &result[0];
    assert_eq!(1, result.len());
    assert_eq!("is_awesome", rule.identifier);
    assert_eq!(1, rule.strings.len());
    assert_eq!("$rust", rule.strings[0].identifier);
    assert_eq!(1, rule.strings[0].matches.len());
    assert_eq!(7, rule.strings[0].matches[0].offset);
    assert_eq!(b"Rust", rule.strings[0].matches[0].data.as_slice());
}

#[test]
fn test_scan_file() {
    let mut compiler = Compiler::new().unwrap();
    compiler.add_rules_str(RULES).expect("Should be Ok");
    let rules = compiler.compile_rules().unwrap();

    let result = rules
        .scan_file("tests/scanfile.txt", 10)
        .expect("Should have scanned file");
    assert_eq!(1, result.len());
}

#[test]
fn test_tags() {
    let rules = compile(
        "
rule is_empty: file size {
  condition:
    filesize == 0
}",
    );
    let matches = rules.scan_mem(b"", 10).expect("should have scanned");

    assert_eq!(1, matches.len());
    let is_empty_match = &matches[0];
    assert_eq!(&["file", "size"], is_empty_match.tags.as_slice());
}

#[test]
fn test_namespace() {
    let rule = "rule is_empty {
  condition:
    filesize == 0
}";
    let _yara = Yara::new().unwrap();
    {
        let rules = compile(rule);
        let matches = rules.scan_mem(b"", 10).expect("should have scanned");

        assert_eq!(1, matches.len());
        let is_empty_match = &matches[0];
        assert_eq!("default", is_empty_match.namespace);
    }
    {
        let rules = compile_with_namespace(rule, "ns");
        let matches = rules.scan_mem(b"", 10).expect("should have scanned");

        assert_eq!(1, matches.len());
        let is_empty_match = &matches[0];
        assert_eq!("ns", is_empty_match.namespace);
    }
}

#[test]
fn test_metadata() {
    let rules = compile(
        r#"
rule is_three_char_long {
  condition:
    filesize == 3
}
rule contains_abc {
  meta:
    a_string = "value"
    an_integer = 42
    a_bool = true
  strings:
    $abc = "abc"
  condition:
    $abc at 0
}
"#,
    );

    let matches = rules.scan_mem(b"abc", 10).expect("should have scanned");
    assert_eq!(2, matches.len());

    let is_three_char_long = &matches[0];
    assert_eq!(0, is_three_char_long.metadatas.len());

    let contains_a = &matches[1];
    assert_eq!(3, contains_a.metadatas.len());
    assert_eq!(
        Metadata {
            identifier: "a_string",
            value: MetadataValue::String("value")
        },
        contains_a.metadatas[0]
    );
    assert_eq!(
        Metadata {
            identifier: "an_integer",
            value: MetadataValue::Integer(42)
        },
        contains_a.metadatas[1]
    );
    assert_eq!(
        Metadata {
            identifier: "a_bool",
            value: MetadataValue::Boolean(true)
        },
        contains_a.metadatas[2]
    );
}

#[test]
fn test_external_variables() {
    let rule_definition = "
rule IsNCharLong {
  condition:
    filesize == desired_length
}
";

    let mut compiler = Compiler::new().expect("Should create compiler");
    compiler
        .define_variable("desired_length", 5)
        .expect("Should have added a rule");
    compiler
        .add_rules_str(rule_definition)
        .expect("Should parse rule");

    let rules = compiler.compile_rules().expect("Should compile rules");
    let result = rules.scan_mem(b"abcde", 10).expect("Should scan");

    assert_eq!(1, result.len());
}

#[test]
fn test_multithread() {
    use crossbeam::scope;

    let rules = get_default_rules();

    scope(|scope| {
        for _i in 0..10 {
            scope.spawn(|_| {
                let matches = rules.scan_mem(b"rust", 10).expect("should have scanned");
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0].identifier, "is_awesome")
            });
            scope.spawn(|_| {
                let matches = rules.scan_mem(b"go", 10).expect("should have scanned");
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0].identifier, "is_ok")
            });
        }
    })
    .unwrap();
}

#[test]
fn test_rule_load_save_mem() {
    let mut rules = get_default_rules();

    let mut saved_rules = Vec::new();
    rules.save_to_stream(&mut saved_rules).expect("Should save");

    let loaded_rules = Rules::load_from_stream(&saved_rules[..]).expect("Should load");
    test_default_rules(&loaded_rules);
}

#[test]
fn test_rule_load_save_file() {
    let filename = "_compiled_rule.yara";
    std::fs::remove_file(filename).ok();

    {
	let save_file = std::fs::File::create(filename)
	    .expect("should have created the file");
	let mut rules = get_default_rules();
	rules.save_to_stream(save_file).expect("Should save");
    }

    let load_file = std::fs::File::open(filename)
	    .expect("should have opened the file");
    let loaded_rules = Rules::load_from_stream(load_file).expect("Should load");
    std::fs::remove_file(filename).ok();

    test_default_rules(&loaded_rules);
}

fn test_default_rules(rules: &Rules) {
    let scan_mem_result = rules.scan_mem("I love Rust!".as_bytes(), 10);
    let scan_result = scan_mem_result.expect("Should be Ok");
    assert_eq!(1, scan_result.len());
}

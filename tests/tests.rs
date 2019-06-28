extern crate yara;

use yara::{CompileErrorLevel, Error, Metadata, MetadataValue, Rule, Yara};

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

fn compile_and_scan<'a>(yara: &'a mut Yara, rule: &str, mem: &[u8]) -> Vec<Rule<'a>> {
    let mut compiler = yara.new_compiler().expect("Should create compiler");
    compiler.add_rules_str(rule).expect("Should parse rule");
    let mut rules = compiler.compile_rules().expect("Should compile rules");
    rules.scan_mem(mem, 10).expect("Should scan")
}

fn compile_and_scan_with_namespace<'a>(
    yara: &'a mut Yara,
    rule: &str,
    namespace: &str,
    mem: &[u8],
) -> Vec<Rule<'a>> {
    let mut compiler = yara.new_compiler().expect("Should create compiler");
    compiler
        .add_rules_str_with_namespace(rule, namespace)
        .expect("Should parse rule");
    let mut rules = compiler.compile_rules().expect("Should compile rules");
    rules.scan_mem(mem, 10).expect("Should scan")
}

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
    let mut yara = Yara::create().unwrap();
    let mut compiler = yara.new_compiler().unwrap();
    compiler.add_rules_str(RULES).expect("Should be Ok");
    let mut rules = compiler.compile_rules().unwrap();

    let result = rules
        .scan_file("tests/scanfile.txt", 10)
        .expect("Should have scanned file");
    assert_eq!(1, result.len());
}

#[test]
fn test_tags() {
    let mut yara = Yara::create().unwrap();
    let rules = compile_and_scan(
        &mut yara,
        "rule is_empty: file size {
  condition:
    filesize == 0
}",
        b"",
    );

    assert_eq!(1, rules.len());
    let rule = &rules[0];
    assert_eq!(&["file", "size"], rule.tags.as_slice());
}

#[test]
fn test_namespace() {
    let rule = "rule is_empty {
  condition:
    filesize == 0
}";
    let mut yara = Yara::create().unwrap();
    {
        let rules = compile_and_scan(&mut yara, rule, b"");

        assert_eq!(1, rules.len());
        let rule = &rules[0];
        assert_eq!("default", rule.namespace);
    }
    {
        let rules = compile_and_scan_with_namespace(&mut yara, rule, "ns", b"");

        assert_eq!(1, rules.len());
        let rule = &rules[0];
        assert_eq!("ns", rule.namespace);
    }
}

#[test]
fn test_metadata() {
    let mut yara = Yara::create().unwrap();
    let rules = compile_and_scan(
        &mut yara,
        "
rule is_empty {
  condition:
    filesize == 3
}
rule contains_abc {
  meta:
    a_string = \"value\"
    an_integer = 42
    a_bool = true
  strings:
    $abc = \"abc\"
  condition:
    $abc at 0
}
",
        b"abc",
    );

    assert_eq!(2, rules.len());

    let is_empty = &rules[0];
    assert_eq!(0, is_empty.metadatas.len());

    let contains_a = &rules[1];
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

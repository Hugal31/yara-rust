use std::collections::HashMap;

use yara::{
    CallbackMsg, CallbackReturn, CompileErrorLevel, Compiler, Error, MemoryBlock,
    MemoryBlockIterator, MemoryBlockIteratorSized, Metadata, MetadataValue, Rules, ScanFlags, Yara,
    YrObjectValue,
};

const RULES: &str = r#"
import "pe"

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
}

rule re_is_ok {
  strings:
    $go = /[Oo]k/

  condition:
    $go
}
"#;

fn compile(rule: &str) -> Rules {
    Compiler::new()
        .expect("Should create compiler")
        .add_rules_str(rule)
        .expect("Should parse rule")
        .compile_rules()
        .expect("Should compile rules")
}

fn get_default_rules() -> Rules {
    compile(RULES)
}

fn compile_with_namespace(rule: &str, namespace: &str) -> Rules {
    Compiler::new()
        .expect("Should create compiler")
        .add_rules_str_with_namespace(rule, namespace)
        .expect("Should parse rule")
        .compile_rules()
        .expect("Should compile rules")
}

#[test]
fn test_initialize() {
    assert!(Yara::new().is_ok());
}

#[test]
fn test_configuration() {
    let yara = Yara::new().expect("Should be Ok");
    assert_eq!(Ok(()), yara.set_configuration_stack_size(100));
    assert_eq!(Ok(100), yara.get_configuration_stack_size());
    assert_eq!(
        Ok(()),
        yara.set_configuration_max_process_memory_chunk(u64::MAX)
    );
    assert_eq!(
        Ok(u64::MAX),
        yara.get_configuration_max_process_memory_chunk()
    );
}

#[test]
fn test_create_compiler() {
    assert!(Compiler::new().is_ok());
}

#[test]
fn test_compile_string_rules() {
    let mut compiler = Compiler::new().unwrap();
    compiler = compiler.add_rules_str(RULES).expect("should compile");
    compiler
        .add_rules_str("nop.")
        .expect_err("should not compile");
}

#[test]
fn test_compile_error() {
    let compiler = Compiler::new().unwrap();
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
    let compiler = Compiler::new().unwrap();
    assert!(compiler.add_rules_file("tests/rules.txt").is_ok());
}

#[test]
fn test_compile_fd_rules() {
    let compiler = Compiler::new().unwrap();
    let file = std::fs::File::open("tests/rules.txt").unwrap();
    assert!(compiler.add_rules_fd(&file, "tests/rules.txt").is_ok());
}

#[test]
fn test_scan_mem() {
    let rules = get_default_rules();
    let result = rules.scan_mem("I love Rust! And go is ok".as_bytes(), 10);

    let result = result.expect("Should be Ok");
    assert_eq!(3, result.len());
    {
        let rule = &result[0];
        assert_eq!("is_awesome", rule.identifier);
        assert_eq!(1, rule.strings.len());
        assert_eq!("$rust", rule.strings[0].identifier);
        assert_eq!(1, rule.strings[0].matches.len());
        assert_eq!(7, rule.strings[0].matches[0].offset);
        assert_eq!(b"Rust", rule.strings[0].matches[0].data.as_slice());
    }
    {
        let rule = &result[1];
        assert_eq!("is_ok", rule.identifier);
        assert_eq!(b"go", rule.strings[0].matches[0].data.as_slice());
    }
}

#[test]
fn test_scan_mem_callback_abort() {
    let rules = get_default_rules();
    let mut results = Vec::new();
    let callback = |message| {
        if let CallbackMsg::RuleMatching(rule) = message {
            results.push(rule);
        }
        CallbackReturn::Abort
    };

    let result = rules.scan_mem_callback("rust ok".as_bytes(), 10, callback);
    assert!(result.is_ok());
    assert_eq!(1, results.len());
}

#[test]
fn test_scan_mem_callback_error() {
    let rules = get_default_rules();
    let callback = |_| CallbackReturn::Error;
    let result = rules.scan_mem_callback("rust ok".as_bytes(), 10, callback);
    let error = result.expect_err("Should be Err");
    assert_eq!(yara_sys::Error::CallbackError, error.kind);
}

#[test]
fn test_scan_file() {
    let rules = get_default_rules();
    let result = rules
        .scan_file("tests/scanfile.txt", 10)
        .expect("Should have scanned file");
    assert_eq!(1, result.len());
}

#[test]
fn test_scan_fd() {
    let rules = get_default_rules();
    let file = std::fs::File::open("tests/scanfile.txt").unwrap();
    let result = rules.scan_fd(&file, 10).expect("Should have scanned file");
    assert_eq!(1, result.len());
}

#[test]
fn test_scan_mem_blocks() {
    struct TestIter<'a> {
        base: u64,
        current: usize,
        data: &'a [&'a [u8]],
    }

    impl<'a> MemoryBlockIterator for TestIter<'a> {
        fn first(&mut self) -> Option<MemoryBlock> {
            self.next()
        }

        fn next(&mut self) -> Option<MemoryBlock> {
            if self.current == self.data.len() {
                return None;
            }
            let data = self.data[self.current];
            let old_base = self.base;
            self.base += data.len() as u64;
            self.current += 1;
            Some(MemoryBlock::new(old_base, data))
        }
    }

    let rules = get_default_rules();
    let scanner = rules.scanner().expect("Should be ok");
    let iter = TestIter {
        base: 0,
        current: 0,
        data: &[b"go", b"bbb"],
    };
    let result = scanner.scan_mem_blocks(iter).expect("Should be ok");
    assert_eq!(1, result.len());
}

#[test]
fn test_scan_mem_blocks_sized() {
    struct TestIter<'a> {
        base: u64,
        current: usize,
        data: &'a [&'a [u8]],
    }

    impl<'a> MemoryBlockIterator for TestIter<'a> {
        fn first(&mut self) -> Option<MemoryBlock> {
            self.next()
        }

        fn next(&mut self) -> Option<MemoryBlock> {
            if self.current >= self.data.len() {
                return None;
            }
            let data = self.data[self.current];
            let old_base = self.base;
            self.base += data.len() as u64;
            self.current += 1;
            Some(MemoryBlock::new(old_base, data))
        }
    }

    impl<'a> MemoryBlockIteratorSized for TestIter<'a> {
        fn file_size(&mut self) -> u64 {
            self.data.iter().map(|&d| d.len()).sum::<usize>() as u64
        }
    }

    let rules = get_default_rules();
    let scanner = rules.scanner().expect("Should be ok");
    let iter = TestIter {
        base: 0,
        current: 0,
        data: &[b"Rust!", b"bbb", b"bcc"],
    };
    let result = scanner.scan_mem_blocks_sized(iter).expect("Should be ok");
    assert_eq!(1, result.len());
}

#[test]
fn test_scan_mem_console_log() {
    let rule = r#"
import "console"
rule log {
  condition:
    console.log("value: ", 12)
}"#;
    let rules = compile(rule);
    let mut logs = Vec::new();
    let callback = |message| {
        if let CallbackMsg::ConsoleLog(log) = message {
            logs.push(log.to_string_lossy().to_string());
        }
        CallbackReturn::Continue
    };

    let result = rules.scan_mem_callback(b"", 10, callback);
    assert!(result.is_ok());
    assert_eq!(&logs, &["value: 12"]);
}

#[test]
fn test_scan_fast_mode() {
    let test_mem = b"
I love Rust!
I love Rust!
I love Rust!
I love Rust!
I love Rust!
";
    let mut rules = Compiler::new()
        .unwrap()
        .add_rules_str(RULES)
        .expect("Should be Ok")
        .compile_rules()
        .unwrap();
    rules.set_flags(ScanFlags::FAST_MODE);

    let result = rules
        .scan_mem(test_mem, test_mem.len() as i32)
        .expect("Should have scanned byte string");
    assert_eq!(1, result.len());
    let rule = &result[0];
    assert_eq!(1, result.len());
    assert_eq!("is_awesome", rule.identifier);
    assert_eq!(1, rule.strings.len());
    assert_eq!("$rust", rule.strings[0].identifier);

    // In fast mode, it should stop after a single match
    assert_eq!(1, rule.strings[0].matches.len());
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
    {
        let rules = Compiler::new()
            .expect("Should create compiler")
            .add_rules_file_with_namespace("tests/rules.txt", "ns")
            .expect("Should parse file")
            .compile_rules()
            .expect("Should compile rules");
        let matches = rules.scan_mem(b"RUST", 10).expect("should have scanned");

        assert_eq!(1, matches.len());
        assert_eq!("ns", matches[0].namespace);
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
    compiler = compiler
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
        let save_file = std::fs::File::create(filename).expect("should have created the file");
        let mut rules = get_default_rules();
        rules.save_to_stream(save_file).expect("Should save");
    }

    let load_file = std::fs::File::open(filename).expect("should have opened the file");
    let loaded_rules = Rules::load_from_stream(load_file).expect("Should load");
    std::fs::remove_file(filename).ok();

    test_default_rules(&loaded_rules);
}

#[test]
fn test_compile_with_warning() {
    let rule = r#"
rule is_slow
{
    strings:
        $re1 = /state:.*(on|off)/

    condition:
        $re1
}
"#;

    compile(rule);
}

fn test_default_rules(rules: &Rules) {
    let scan_mem_result = rules.scan_mem("I love Rust!".as_bytes(), 10);
    let scan_result = scan_mem_result.expect("Should be Ok");
    assert_eq!(1, scan_result.len());
}

#[test]
fn test_include_callback() {
    let rule_1 = r#"
include "is_ok.yara"

rule is_awesome {
  strings:
    $rust = /[Rr]ust/

  condition:
    $rust
}
"#;

    let rule_2 = r#"
rule is_ok {
  strings:
    $go = "go"

  condition:
    $go
}
"#;

    use std::collections::HashMap;
    let mut rules_cache = HashMap::new();
    rules_cache.insert("is_ok.yara".to_string(), rule_2.to_string());

    let mut compiler = Compiler::new().unwrap();
    compiler.set_include_callback(move |name, _, _| rules_cache.get(name).map(|r| r.to_string()));

    compiler
        .add_rules_str(rule_1)
        .expect("Should be Ok")
        .compile_rules()
        .expect("Compiles OK");
}

#[test]
fn test_disable_include() {
    let rule_1 = r#"
include "is_ok.yara"

rule is_awesome {
  strings:
    $rust = /[Rr]ust/

  condition:
    $rust
}
"#;

    let mut compiler = Compiler::new().unwrap();
    compiler.disable_include_directive();
    let res = compiler.add_rules_str(rule_1);
    assert!(res.is_err());
}

#[test]
fn test_custom_memory_iterator() {
    use libflate::gzip::Decoder;
    use std::io::{self, Read};

    pub struct GZipMemoryBlockIterator<R> {
        offset: u64,
        buffer: Vec<u8>,
        decoder: Decoder<R>,
    }

    impl<R: Read> GZipMemoryBlockIterator<R> {
        pub fn new(reader: R) -> io::Result<Self> {
            Ok(GZipMemoryBlockIterator {
                offset: 0,
                buffer: vec![0; 1024],
                decoder: Decoder::new(reader)?,
            })
        }
    }

    impl<R: Read> MemoryBlockIterator for GZipMemoryBlockIterator<R> {
        fn first(&mut self) -> Option<MemoryBlock> {
            self.next()
        }

        fn next(&mut self) -> Option<MemoryBlock> {
            let size = self.decoder.read(&mut self.buffer).unwrap();
            if size == 0 {
                return None;
            }
            self.offset += size as u64;
            Some(MemoryBlock::new(self.offset, &self.buffer[..size]))
        }
    }

    let file = std::fs::File::open("tests/scanfile.txt.gz").unwrap();
    let iterator = GZipMemoryBlockIterator::new(file).unwrap();
    let rules = compile(RULES);
    let scanner = rules.scanner().unwrap();
    let scan_result = scanner
        .scan_mem_blocks(iterator)
        .expect("should have scanned the gzipped file");
    assert_eq!(1, scan_result.len());
}

#[test]
fn test_callback_rule_not_matching() {
    let rules = get_default_rules();
    let mut matching_rules = vec![];
    let mut not_matching_rules = vec![];

    rules
        .scan_mem_callback(b"gok", 1, |callback_msg| {
            match callback_msg {
                CallbackMsg::RuleMatching(rule) => matching_rules.push(rule.identifier),
                CallbackMsg::RuleNotMatching(rule) => not_matching_rules.push(rule.identifier),
                _ => (),
            };
            CallbackReturn::Continue
        })
        .expect("should scan");

    matching_rules.sort();
    assert_eq!(matching_rules, &["is_ok", "re_is_ok"]);
    assert_eq!(not_matching_rules, &["is_awesome"]);
}

#[test]
fn test_callback_module_imported() {
    let rules = get_default_rules();
    let mut found_module = false;

    rules
        .scan_mem_callback(b"", 1, |callback_msg| {
            if let CallbackMsg::ModuleImported(module) = callback_msg {
                found_module = true;
                assert_eq!(module.identifier().unwrap(), b"pe");
                if let YrObjectValue::Structure(obj) = module.value() {
                    // Convert the vec to a hashmap to ease the tests.
                    let obj: HashMap<_, _> = obj
                        .into_iter()
                        .map(|v| (v.identifier().unwrap().to_vec(), v))
                        .collect();

                    // Do a few tests on the values in the pe module, to check we parse correctly
                    // different values.
                    assert!(matches!(
                        obj.get(b"IMPORT_STANDARD".as_slice()).unwrap().value(),
                        YrObjectValue::Integer(1)
                    ));
                    assert!(matches!(
                        obj.get(b"section_index".as_slice()).unwrap().value(),
                        YrObjectValue::Function
                    ));
                    assert!(matches!(
                        obj.get(b"dll_name".as_slice()).unwrap().value(),
                        YrObjectValue::Undefined
                    ));
                    assert!(matches!(
                        obj.get(b"version_info".as_slice()).unwrap().value(),
                        YrObjectValue::Dictionary(_)
                    ));
                    assert!(matches!(
                        obj.get(b"sections".as_slice()).unwrap().value(),
                        YrObjectValue::Array(_)
                    ));
                    assert!(obj.get(b"non_existing_key".as_slice()).is_none());
                } else {
                    panic!(
                        "the returned module on a ModuleImported callback msg should \
                        be of type structure"
                    );
                }
            }
            CallbackReturn::Continue
        })
        .expect("should scan");

    assert!(
        found_module,
        "should have add a ModuleImported callback msg"
    );
}

extern crate yara;

use yara::Yara;

#[test]
fn test_initialize() {
    assert!(Yara::create().is_ok());
}

#[test]
fn test_create_compiler() {
    let mut yara = Yara::create().unwrap();
    assert!(yara.new_compiler().is_ok());
}

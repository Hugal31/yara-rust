extern crate yara_sys;

#[test]
fn test_initialize() {
    assert_eq!(0, unsafe { yara_sys::yr_initialize() });
    assert_eq!(0, unsafe { yara_sys::yr_finalize() });
    assert_eq!(31, unsafe { yara_sys::yr_finalize() });
}

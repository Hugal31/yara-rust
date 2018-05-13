use yara_sys;

#[derive(Clone, Copy, Debug, Fail, Eq, PartialEq)]
#[fail(display = "{}", kind)]
pub struct YaraError {
    pub kind: yara_sys::Error,
}

impl From<yara_sys::Error> for YaraError {
    fn from(error: yara_sys::Error) -> Self {
        YaraError {
            kind: error,
        }
    }
}

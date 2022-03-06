use serde::Serialize;
use std::io::{self, Write};

pub struct MessageNotation {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CsvFormat<'a> {
    pub filepath: &'a str,
    pub date: &'a str,
    pub eventid: &'a str,
    pub message: &'a str,
    pub result: &'a str,
    pub command: &'a str,
}

impl MessageNotation {
    pub fn alert<W: Write>(w: &mut W, contents: String) -> io::Result<()> {
        writeln!(w, "[ERROR] {}", contents)
    }
    pub fn warn<W: Write>(w: &mut W, contents: String) -> io::Result<()> {
        writeln!(w, "[WARN] {}", contents)
    }
    pub fn info_noheader<W: Write>(w: &mut W, contents: String) -> io::Result<()> {
        writeln!(w, "{}", contents)
    }
}

#[cfg(test)]
mod tests {
    use crate::detections::print::MessageNotation;

    #[test]
    fn test_error_message() {
        let mut buf = Vec::<u8>::new();
        let input = "test";
        let result = MessageNotation::alert(&mut buf, input.to_string());
        assert!(result.is_ok());
        assert_eq!(buf, b"[ERROR] test\n");
    }

    #[test]
    fn test_info_noheader_message() {
        let mut buf = Vec::<u8>::new();
        let input = "info-test";
        let result = MessageNotation::info_noheader(&mut buf, input.to_string());
        assert!(result.is_ok());
        assert_eq!(buf, b"info-test\n");
    }
    #[test]
    fn test_warn_message() {
        let mut buf = Vec::<u8>::new();
        let input = "warn-test";
        let result = MessageNotation::warn(&mut buf, input.to_string());
        assert!(result.is_ok());
        assert_eq!(buf, b"[WARN] warn-test\n");
    }
}

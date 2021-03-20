use std::io::{self, Write};

pub struct MessageNotation {}

impl MessageNotation {
    pub fn alert<W: Write>(w: &mut W, contents: String) -> io::Result<()> {
        writeln!(w, "[ERROR] {}", contents)
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
        let result = MessageNotation::alert(&mut buf, format!("{}", input.to_string()));
        assert!(result.is_ok());
        assert_eq!(buf, b"[ERROR] test\n");
    }

    #[test]
    fn test_info_noheader_message() {
        let mut buf = Vec::<u8>::new();
        let input = "info-test";
        let result = MessageNotation::info_noheader(&mut buf, format!("{}", input.to_string()));
        assert!(result.is_ok());
        assert_eq!(buf, b"info-test\n");
    }
}

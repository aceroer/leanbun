#![forbid(unsafe_code)]

use leanbun_core::DiagnosticCode;
use std::collections::BTreeMap;
use std::fmt;

pub const MAX_JSON_DEPTH: usize = 128;
pub const MAX_JSON_NODES: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonNumber(String);

impl JsonNumber {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrictJson {
    Null,
    Bool(bool),
    Number(JsonNumber),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictJsonError {
    pub code: DiagnosticCode,
    pub message: String,
}

impl StrictJsonError {
    fn new(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StrictJsonError {}

pub fn parse_strict_json(text: &str) -> Result<StrictJson, StrictJsonError> {
    let mut parser = Parser {
        input: text.as_bytes(),
        position: 0,
        nodes: 0,
    };
    parser.skip_whitespace();
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.position != parser.input.len() {
        return Err(parser.error("trailing content after JSON value"));
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    nodes: usize,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<StrictJson, StrictJsonError> {
        if depth > MAX_JSON_DEPTH {
            return Err(self.error("JSON nesting exceeds limit"));
        }
        self.nodes += 1;
        if self.nodes > MAX_JSON_NODES {
            return Err(self.error("JSON node count exceeds limit"));
        }
        self.skip_whitespace();
        match self.peek() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(StrictJson::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(StrictJson::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(StrictJson::Bool(false))
            }
            Some(b'"') => self.parse_string().map(StrictJson::String),
            Some(b'[') => self.parse_array(depth),
            Some(b'{') => self.parse_object(depth),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(StrictJson::Number),
            _ => Err(self.error("expected JSON value")),
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<StrictJson, StrictJsonError> {
        self.consume(b'[')?;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.take_if(b']') {
            return Ok(StrictJson::Array(values));
        }
        loop {
            values.push(self.parse_value(depth + 1)?);
            self.skip_whitespace();
            if self.take_if(b']') {
                return Ok(StrictJson::Array(values));
            }
            self.consume(b',')?;
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<StrictJson, StrictJsonError> {
        self.consume(b'{')?;
        self.skip_whitespace();
        let mut values = BTreeMap::new();
        if self.take_if(b'}') {
            return Ok(StrictJson::Object(values));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            if values.contains_key(&key) {
                return Err(self.error(&format!("duplicate JSON object key: {key}")));
            }
            self.skip_whitespace();
            self.consume(b':')?;
            let value = self.parse_value(depth + 1)?;
            values.insert(key, value);
            self.skip_whitespace();
            if self.take_if(b'}') {
                return Ok(StrictJson::Object(values));
            }
            self.consume(b',')?;
        }
    }

    fn parse_string(&mut self) -> Result<String, StrictJsonError> {
        self.consume(b'"')?;
        let mut output = Vec::new();
        loop {
            let byte = self
                .next()
                .ok_or_else(|| self.error("unterminated JSON string"))?;
            match byte {
                b'"' => {
                    return String::from_utf8(output)
                        .map_err(|_| self.error("JSON string is not valid UTF-8"));
                }
                b'\\' => self.parse_escape(&mut output)?,
                0x00..=0x1f => return Err(self.error("unescaped control byte in JSON string")),
                _ => output.push(byte),
            }
        }
    }

    fn parse_escape(&mut self, output: &mut Vec<u8>) -> Result<(), StrictJsonError> {
        let escaped = self
            .next()
            .ok_or_else(|| self.error("unterminated JSON escape"))?;
        match escaped {
            b'"' | b'\\' | b'/' => output.push(escaped),
            b'b' => output.push(0x08),
            b'f' => output.push(0x0c),
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b't' => output.push(b'\t'),
            b'u' => {
                let first = self.hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    self.consume(b'\\')?;
                    self.consume(b'u')?;
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(self.error("invalid low surrogate in JSON string"));
                    }
                    0x1_0000 + (u32::from(first - 0xd800) << 10) + u32::from(second - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(self.error("lone low surrogate in JSON string"));
                } else {
                    u32::from(first)
                };
                let character = char::from_u32(scalar)
                    .ok_or_else(|| self.error("invalid Unicode scalar in JSON string"))?;
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
            _ => return Err(self.error("invalid JSON string escape")),
        }
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u16, StrictJsonError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = match self.next() {
                Some(b'0'..=b'9') => u16::from(self.input[self.position - 1] - b'0'),
                Some(b'a'..=b'f') => u16::from(self.input[self.position - 1] - b'a' + 10),
                Some(b'A'..=b'F') => u16::from(self.input[self.position - 1] - b'A' + 10),
                _ => return Err(self.error("invalid JSON Unicode escape")),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<JsonNumber, StrictJsonError> {
        let start = self.position;
        self.take_if(b'-');
        match self.peek() {
            Some(b'0') => {
                self.position += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.error("leading zero in JSON number"));
                }
            }
            Some(b'1'..=b'9') => self.consume_digits(),
            _ => return Err(self.error("invalid JSON number integer part")),
        }
        if self.take_if(b'.') {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("missing JSON fraction digits"));
            }
            self.consume_digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("missing JSON exponent digits"));
            }
            self.consume_digits();
        }
        let lexical = std::str::from_utf8(&self.input[start..self.position])
            .map_err(|_| self.error("JSON number is not UTF-8"))?;
        Ok(JsonNumber(lexical.to_owned()))
    }

    fn consume_digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), StrictJsonError> {
        if self
            .input
            .get(self.position..self.position + expected.len())
            == Some(expected)
        {
            self.position += expected.len();
            Ok(())
        } else {
            Err(self.error("invalid JSON literal"))
        }
    }

    fn consume(&mut self, expected: u8) -> Result<(), StrictJsonError> {
        self.skip_whitespace();
        if self.take_if(expected) {
            Ok(())
        } else {
            Err(self.error(&format!("expected byte 0x{expected:02x}")))
        }
    }

    fn take_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.position += 1;
        Some(value)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn error(&self, detail: &str) -> StrictJsonError {
        StrictJsonError::new(
            DiagnosticCode::JSON_MALFORMED,
            format!(
                "strict JSON parse failed at byte {}: {detail}",
                self.position
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_accepts_full_grammar_and_preserves_numbers() {
        let parsed = parse_strict_json(
            r#"{"schemaVersion":1,"number":-0.25e+2,"items":[true,null,"\uD83D\uDE00"]}"#,
        );
        assert!(parsed.is_ok());
        let number = parse_strict_json("-0.25e+2");
        assert_eq!(
            number,
            Ok(StrictJson::Number(JsonNumber("-0.25e+2".to_owned())))
        );
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_trailing_values_and_bad_numbers() {
        for invalid in [
            r#"{"schemaVersion":1,"schemaVersion":1}"#,
            "{} []",
            "01",
            "1.",
            "1e",
            r#""\uD800""#,
        ] {
            assert_eq!(
                parse_strict_json(invalid).map_err(|error| error.code),
                Err(DiagnosticCode::JSON_MALFORMED),
                "case: {invalid}"
            );
        }
    }

    #[test]
    fn strict_json_enforces_recursion_and_node_limits() {
        let nested = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        assert_eq!(
            parse_strict_json(&nested).map_err(|error| error.code),
            Err(DiagnosticCode::JSON_MALFORMED)
        );
        let nodes = format!("[{}]", "null,".repeat(MAX_JSON_NODES));
        assert_eq!(
            parse_strict_json(&nodes).map_err(|error| error.code),
            Err(DiagnosticCode::JSON_MALFORMED)
        );
    }
}

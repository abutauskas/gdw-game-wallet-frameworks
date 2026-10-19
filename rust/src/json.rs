//! A deterministic JSON value with canonical (JCS-style) encoding.
//!
//! Objects are stored in a `BTreeMap`, so key ordering is deterministic and
//! ascending by Unicode code point for free. Numbers are integers only; floats
//! and exponents are rejected, as the specification requires (SPEC.md §2.2).
//!
//! SPDX-License-Identifier: CC-BY-4.0

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::errors::{GdwError, GdwResult};

/// A JSON value in canonical GDW form.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn object() -> Json {
        Json::Object(BTreeMap::new())
    }

    pub fn array() -> Json {
        Json::Array(Vec::new())
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn array_of_strings<I, S>(values: I) -> Json
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Json::Array(values.into_iter().map(|v| Json::Str(v.into())).collect())
    }

    /// Insert a key into an object (no-op for non-objects). Returns `&mut self`
    /// for chaining.
    pub fn set(&mut self, key: impl Into<String>, value: Json) -> &mut Json {
        if let Json::Object(map) = self {
            map.insert(key.into(), value);
        }
        self
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn has(&self, key: &str) -> bool {
        matches!(self, Json::Object(map) if map.contains_key(key))
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Json::Str(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Json::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Json::Object(_))
    }

    pub fn items(&self) -> &[Json] {
        match self {
            Json::Array(items) => items,
            _ => &[],
        }
    }

    /// Iterate over object entries in canonical (sorted) order.
    pub fn entries(&self) -> Box<dyn Iterator<Item = (&String, &Json)> + '_> {
        match self {
            Json::Object(map) => Box::new(map.iter()),
            _ => Box::new(std::iter::empty()),
        }
    }

    /// Canonical serialisation (sorted keys, no whitespace, integers only).
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Json::Str(s) => write_string(out, s),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(map) => {
                out.push('{');
                let mut first = true;
                for (key, value) in map {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    write_string(out, key);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }

    // ---- parsing ----------------------------------------------------------

    /// Parse a JSON document. Rejects floats/exponents (integers only) and any
    /// non-canonical number form, matching the other frameworks.
    pub fn parse(text: &str) -> GdwResult<Json> {
        let mut p = Parser {
            bytes: text.as_bytes(),
            pos: 0,
        };
        p.skip_ws();
        let value = p.parse_value()?;
        p.skip_ws();
        if p.pos != p.bytes.len() {
            return Err(GdwError::Malformed);
        }
        Ok(value)
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> GdwResult<Json> {
        match self.peek() {
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(b't') => self.parse_literal("true", Json::Bool(true)),
            Some(b'f') => self.parse_literal("false", Json::Bool(false)),
            Some(b'"') => self.parse_string().map(Json::Str),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            _ => Err(GdwError::Malformed),
        }
    }

    fn parse_literal(&mut self, word: &str, value: Json) -> GdwResult<Json> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(GdwError::Malformed)
        }
    }

    fn parse_number(&mut self) -> GdwResult<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digit_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digit_start {
            return Err(GdwError::Malformed);
        }
        // A float/exponent makes this an invalid GDW integer.
        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E')) {
            return Err(GdwError::Malformed);
        }
        let text =
            std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| GdwError::Malformed)?;
        // Reject non-canonical forms like "-0" or leading zeros.
        let canonical_int = match text.strip_prefix('-') {
            Some(rest) => {
                if rest == "0" || (rest.len() > 1 && rest.starts_with('0')) {
                    return Err(GdwError::Malformed);
                }
                true
            }
            None => !(text.len() > 1 && text.starts_with('0')),
        };
        if !canonical_int {
            return Err(GdwError::Malformed);
        }
        let value = text.parse::<i64>().map_err(|_| GdwError::Malformed)?;
        // SPEC.md §2.2: integers are limited to the JSON-safe range.
        const MAX_SAFE: i64 = 9_007_199_254_740_991; // 2^53 - 1
        if value < -MAX_SAFE || value > MAX_SAFE {
            return Err(GdwError::Malformed);
        }
        Ok(Json::Int(value))
    }

    fn parse_string(&mut self) -> GdwResult<String> {
        if self.peek() != Some(b'"') {
            return Err(GdwError::Malformed);
        }
        self.pos += 1;
        let mut out = String::new();
        loop {
            let b = self.peek().ok_or(GdwError::Malformed)?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek().ok_or(GdwError::Malformed)?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.parse_hex4()?;
                            let c = if (0xD800..=0xDBFF).contains(&hi) {
                                // surrogate pair
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                    if self.peek() == Some(b'u') {
                                        self.pos += 1;
                                        let lo = self.parse_hex4()?;
                                        char::from_u32(
                                            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00),
                                        )
                                    } else {
                                        return Err(GdwError::Malformed);
                                    }
                                } else {
                                    return Err(GdwError::Malformed);
                                }
                            } else {
                                char::from_u32(hi)
                            };
                            out.push(c.ok_or(GdwError::Malformed)?);
                        }
                        _ => return Err(GdwError::Malformed),
                    }
                }
                _ if b < 0x20 => return Err(GdwError::Malformed),
                _ => {
                    // Copy one UTF-8 scalar.
                    let remaining = &self.bytes[self.pos..];
                    let s = std::str::from_utf8(remaining).map_err(|_| GdwError::Malformed)?;
                    let ch = s.chars().next().ok_or(GdwError::Malformed)?;
                    self.pos += ch.len_utf8();
                    out.push(ch);
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> GdwResult<u32> {
        let mut value = 0u32;
        for _ in 0..4 {
            let b = self.peek().ok_or(GdwError::Malformed)?;
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => return Err(GdwError::Malformed),
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    fn parse_array(&mut self) -> GdwResult<Json> {
        self.pos += 1; // [
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(GdwError::Malformed),
            }
        }
    }

    fn parse_object(&mut self) -> GdwResult<Json> {
        self.pos += 1; // {
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(GdwError::Malformed);
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(map));
                }
                _ => return Err(GdwError::Malformed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_sorts_and_escapes() {
        let mut obj = Json::object();
        obj.set("b", Json::Int(2));
        obj.set("a", Json::Int(1));
        let mut nested = Json::object();
        nested.set("y", Json::str("ü"));
        obj.set("c", nested);
        assert_eq!(obj.canonical(), "{\"a\":1,\"b\":2,\"c\":{\"y\":\"ü\"}}");
    }

    #[test]
    fn rejects_floats() {
        assert!(Json::parse("1.5").is_err());
        assert!(Json::parse("1e3").is_err());
        assert!(Json::parse("-0").is_err());
        assert!(Json::parse("01").is_err());
        assert_eq!(
            Json::parse("9007199254740991").unwrap().canonical(),
            "9007199254740991"
        );
        assert_eq!(
            Json::parse("-9007199254740991").unwrap().canonical(),
            "-9007199254740991"
        );
        // SPEC.md §2.2: the limit is +/- (2^53 - 1).
        assert!(Json::parse("9007199254740992").is_err());
        assert!(Json::parse("-9007199254740992").is_err());
        assert!(Json::parse("9223372036854775807").is_err());
    }

    #[test]
    fn round_trip() {
        let text = "{\"a\":1,\"b\":[true,null,\"x\"]}";
        assert_eq!(Json::parse(text).unwrap().canonical(), text);
    }
}

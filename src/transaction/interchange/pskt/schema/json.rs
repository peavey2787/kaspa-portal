//! Restricted canonical-JSON syntax validator shared by host and embedded
//! PSKT decoders.

use core::fmt;

use super::MAX_JSON_NESTING;

/// Restricted JSON syntax error shared by host and hardware PSKT decoders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonSyntaxError {
    UnexpectedToken,
    InvalidNumber,
    InvalidString,
    DuplicateKey,
    NestingTooDeep,
    TrailingData,
}

impl fmt::Display for JsonSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnexpectedToken => "invalid canonical JSON structure",
            Self::InvalidNumber => "PSKT JSON numbers must be canonical non-negative integers",
            Self::InvalidString => "PSKT JSON strings must be printable ASCII without escapes",
            Self::DuplicateKey => "duplicate JSON object key",
            Self::NestingTooDeep => "PSKT JSON exceeds maximum nesting depth",
            Self::TrailingData => "PSKT JSON contains trailing data",
        })
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    /// The unread suffix of `input`; reading only ever shortens it.
    rest: &'a [u8],
    /// Off only while re-reading members an enclosing object already
    /// validated, to find an earlier copy of a key.
    check_duplicates: bool,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8], pos: usize, check_duplicates: bool) -> Self {
        Self {
            input,
            rest: &input[pos..],
            check_duplicates,
        }
    }

    /// Offset of the next unread byte within `input`.
    const fn pos(&self) -> usize {
        self.input.len() - self.rest.len()
    }

    fn skip(&mut self, count: usize) {
        self.rest = &self.rest[count..];
    }

    fn ws(&mut self) {
        let blank = self
            .rest
            .iter()
            .take_while(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
            .count();
        self.skip(blank);
    }

    fn byte(&mut self, expected: u8) -> Result<(), JsonSyntaxError> {
        self.ws();
        if self.consume_if(expected) {
            Ok(())
        } else {
            Err(JsonSyntaxError::UnexpectedToken)
        }
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        let matched = self.rest.first() == Some(&expected);
        if matched {
            self.skip(1);
        }
        matched
    }

    /// A printable-ASCII string without escapes; returns its content range.
    fn string(&mut self) -> Result<(usize, usize), JsonSyntaxError> {
        self.byte(b'"')?;
        let start = self.pos();
        let length = self
            .rest
            .iter()
            .position(|byte| !matches!(byte, b' '..=b'~') || matches!(byte, b'"' | b'\\'))
            .filter(|&index| self.rest[index] == b'"')
            .ok_or(JsonSyntaxError::InvalidString)?;
        self.skip(length + 1);
        Ok((start, start + length))
    }

    /// A canonical non-negative integer: `0` or a digit run without a leading
    /// zero, and no fraction, exponent or sign after it.
    fn number(&mut self) -> Result<(), JsonSyntaxError> {
        let digits = self
            .rest
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let leading_zero = self.rest.first() == Some(&b'0');
        self.skip(digits);
        if (leading_zero && digits > 1)
            || matches!(self.rest.first(), Some(b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            return Err(JsonSyntaxError::InvalidNumber);
        }
        Ok(())
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), JsonSyntaxError> {
        if !self.rest.starts_with(literal) {
            return Err(JsonSyntaxError::UnexpectedToken);
        }
        self.skip(literal.len());
        Ok(())
    }

    /// One value at nesting `depth`; containers open one level deeper.
    fn value(&mut self, depth: usize) -> Result<(), JsonSyntaxError> {
        self.ws();
        match self.rest.first().copied() {
            Some(b'{') => self.object(nested(depth)?),
            Some(b'[') => self.array(nested(depth)?),
            Some(b'"') => self.string().map(|_| ()),
            Some(b'0'..=b'9') => self.number(),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            _ => Err(JsonSyntaxError::UnexpectedToken),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), JsonSyntaxError> {
        self.byte(b'{')?;
        self.ws();
        if self.consume_if(b'}') {
            return Ok(());
        }
        let members_start = self.pos();
        loop {
            self.object_member(depth, members_start)?;
            if self.list_end(b'}')? {
                return Ok(());
            }
        }
    }

    fn object_member(&mut self, depth: usize, members_start: usize) -> Result<(), JsonSyntaxError> {
        self.ws();
        let key_token_start = self.pos();
        let (key_start, key_end) = self.string()?;
        if self.check_duplicates
            && key_seen_before(
                self.input,
                members_start,
                key_token_start,
                &self.input[key_start..key_end],
                depth,
            )?
        {
            return Err(JsonSyntaxError::DuplicateKey);
        }
        self.byte(b':')?;
        self.value(depth)
    }

    /// After a list item: `,` continues the list and `close` ends it.
    fn list_end(&mut self, close: u8) -> Result<bool, JsonSyntaxError> {
        self.ws();
        if self.consume_if(b',') {
            Ok(false)
        } else if self.consume_if(close) {
            Ok(true)
        } else {
            Err(JsonSyntaxError::UnexpectedToken)
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), JsonSyntaxError> {
        self.byte(b'[')?;
        self.ws();
        if self.consume_if(b']') {
            return Ok(());
        }
        loop {
            self.value(depth)?;
            if self.list_end(b']')? {
                return Ok(());
            }
        }
    }
}

/// The depth of a container opened inside a value at `depth`.
fn nested(depth: usize) -> Result<usize, JsonSyntaxError> {
    if depth < MAX_JSON_NESTING {
        Ok(depth + 1)
    } else {
        Err(JsonSyntaxError::NestingTooDeep)
    }
}

/// Whether `key` already names a member between `members_start` and the
/// current key token. Those members were validated before the current key was
/// reached, so each is re-read without its own duplicate checks.
fn key_seen_before(
    input: &[u8],
    members_start: usize,
    current_key_token_start: usize,
    key: &[u8],
    depth: usize,
) -> Result<bool, JsonSyntaxError> {
    let mut members = Cursor::new(input, members_start, false);
    loop {
        members.ws();
        if members.pos() >= current_key_token_start {
            return Ok(false);
        }
        let (start, end) = members.string()?;
        if &input[start..end] == key {
            return Ok(true);
        }
        members.byte(b':')?;
        members.value(depth)?;
        members.byte(b',')?;
    }
}

/// Validate the exact restricted JSON grammar used by both PSKT decoders,
/// including recursive duplicate-key rejection.
pub fn validate_canonical_json(input: &[u8]) -> Result<(), JsonSyntaxError> {
    let mut cursor = Cursor::new(input, 0, true);
    cursor.value(0)?;
    cursor.ws();
    if !cursor.rest.is_empty() {
        return Err(JsonSyntaxError::TrailingData);
    }
    Ok(())
}

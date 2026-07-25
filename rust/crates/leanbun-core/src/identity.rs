use core::fmt;

use crate::sha256::Sha256Hasher;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    Sha256,
    ExecutionId,
    BuildTarget,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Sha256 => "expected 64 lowercase hexadecimal SHA-256 characters",
            Self::ExecutionId => "expected a lowercase RFC 4122 UUID version 4",
            Self::BuildTarget => "invalid Lean/Lake build target",
        })
    }
}

impl std::error::Error for ValidationError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256([u8; 32]);

impl Sha256 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let bytes = value.as_bytes();
        if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(ValidationError::Sha256);
        }
        if bytes.iter().any(|byte| matches!(byte, b'A'..=b'F')) {
            return Err(ValidationError::Sha256);
        }

        let mut digest = [0_u8; 32];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        Ok(Self(digest))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.0 {
            formatter.write_str(
                core::str::from_utf8(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
                    .map_err(|_| fmt::Error)?,
            )?;
        }
        Ok(())
    }
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

macro_rules! sha_identity {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Sha256);

        impl $name {
            #[must_use]
            pub const fn from_digest(digest: Sha256) -> Self {
                Self(digest)
            }

            pub fn parse(value: &str) -> Result<Self, ValidationError> {
                Sha256::parse(value).map(Self)
            }

            #[must_use]
            pub const fn digest(&self) -> Sha256 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

sha_identity!(ImageId);
sha_identity!(ProjectId);

#[must_use]
pub fn project_id(canonical_path: &str) -> ProjectId {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-project-v1\0");
    hasher.update(canonical_path.as_bytes());
    ProjectId::from_digest(hasher.finalize())
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionId([u8; 36]);

impl ExecutionId {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let bytes = value.as_bytes();
        let hyphens = [8, 13, 18, 23];
        let shape_valid = bytes.len() == 36
            && bytes.iter().enumerate().all(|(index, byte)| {
                if hyphens.contains(&index) {
                    *byte == b'-'
                } else {
                    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
                }
            });
        if !shape_valid || bytes[14] != b'4' || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
            return Err(ValidationError::ExecutionId);
        }

        let mut canonical = [0_u8; 36];
        canonical.copy_from_slice(bytes);
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BuildTarget(String);

impl BuildTarget {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if !valid_build_target(value) {
            return Err(ValidationError::BuildTarget);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BuildTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[must_use]
pub fn valid_build_target(value: &str) -> bool {
    let utf16_length = value.encode_utf16().count();
    utf16_length > 0
        && utf16_length <= 256
        && !value.starts_with('-')
        && !value.contains("..")
        && !value
            .chars()
            .any(|character| matches!(character, '\u{0000}'..='\u{001f}' | '\u{007f}'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_lowercase_and_round_trips() {
        let text = "0123456789abcdef".repeat(4);
        let digest = Sha256::parse(&text);
        assert!(digest.is_ok());
        assert_eq!(digest.map(|value| value.to_string()), Ok(text));
        assert!(Sha256::parse(&"A".repeat(64)).is_err());
        assert!(Sha256::parse("00").is_err());
    }

    #[test]
    fn execution_id_requires_uuid_v4_and_rfc_variant() {
        assert!(ExecutionId::parse("15f79d6e-b3ea-4277-8db2-b5e08355c2db").is_ok());
        assert!(ExecutionId::parse("15f79d6e-b3ea-3277-8db2-b5e08355c2db").is_err());
        assert!(ExecutionId::parse("15F79D6E-B3EA-4277-8DB2-B5E08355C2DB").is_err());
        assert!(ExecutionId::parse("15f79d6e-b3ea-4277-7db2-b5e08355c2db").is_err());
    }

    #[test]
    fn build_target_matches_bun_utf16_boundary() {
        assert!(BuildTarget::parse("LeanBunMathlibFixture").is_ok());
        assert!(BuildTarget::parse(&"a".repeat(256)).is_ok());
        assert!(BuildTarget::parse(&"😀".repeat(128)).is_ok());
        assert!(BuildTarget::parse(&"😀".repeat(129)).is_err());
        for invalid in ["", "-bad", "a..b", "bad\0target", "bad\u{7f}target"] {
            assert!(BuildTarget::parse(invalid).is_err());
        }
    }

    #[test]
    fn project_id_matches_path_only_v1_contract() {
        assert_eq!(
            project_id("/isolated/project").to_string(),
            "91bb718055f9ebca42d29f8d4a62a8bdf9b3322a6f2c5860ac39ebdd54ca4bd7"
        );
    }
}

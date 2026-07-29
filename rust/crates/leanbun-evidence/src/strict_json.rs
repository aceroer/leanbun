use std::path::Path;

use crate::{CanonicalDirectory, EvidenceError, StableTextFile, read_stable_text};

pub use leanbun_codec::{
    JsonNumber, MAX_JSON_DEPTH, MAX_JSON_NODES, StrictJson, StrictJsonError, parse_strict_json,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableJsonFile {
    pub file: StableTextFile,
    pub value: StrictJson,
}

pub fn read_strict_json(
    root: &CanonicalDirectory,
    candidate: impl AsRef<Path>,
    maximum_bytes: u64,
) -> Result<StableJsonFile, EvidenceError> {
    let file = read_stable_text(root, candidate, maximum_bytes)?;
    let value = parse_strict_json(&file.text)?;
    Ok(StableJsonFile { file, value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize_directory;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> std::io::Result<Self> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("leanbun-json-{}-{id}", std::process::id()));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn stable_json_keeps_file_hash_and_parser_in_one_result()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let text = r#"{"schemaVersion":1}"#;
        fs::write(fixture.0.join("manifest.json"), text)?;
        let root = canonicalize_directory(&fixture.0)?;
        let observed = read_strict_json(&root, "manifest.json", 1024)?;
        assert_eq!(observed.file.text, text);
        assert_eq!(observed.file.size, 19);
        assert_eq!(
            observed.file.sha256.to_string(),
            "0e9561cfb83d50990a103b3896fe249a11fe27fa28985448187f93ec12116d72"
        );
        assert!(matches!(observed.value, StrictJson::Object(_)));
        Ok(())
    }
}

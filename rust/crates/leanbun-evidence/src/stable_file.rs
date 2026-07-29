use leanbun_codec::StrictJsonError;
use leanbun_core::{DiagnosticCode, Sha256, Sha256Hasher};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::SystemTime;

use crate::path::{CanonicalDirectory, CanonicalPath, canonicalize_contained};

pub const MAX_STABLE_TEXT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceError {
    pub code: DiagnosticCode,
    pub message: String,
}

impl EvidenceError {
    pub(crate) fn new(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EvidenceError {}

impl From<StrictJsonError> for EvidenceError {
    fn from(error: StrictJsonError) -> Self {
        Self::new(error.code, error.message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableTextFile {
    pub source: CanonicalPath,
    pub text: String,
    pub size: u64,
    pub sha256: Sha256,
    pub modified_at: SystemTime,
}

pub fn read_stable_text(
    root: &CanonicalDirectory,
    candidate: impl AsRef<Path>,
    maximum_bytes: u64,
) -> Result<StableTextFile, EvidenceError> {
    read_stable_text_with_hook(root, candidate.as_ref(), maximum_bytes, || {})
}

fn read_stable_text_with_hook(
    root: &CanonicalDirectory,
    candidate: &Path,
    maximum_bytes: u64,
    before_read: impl FnOnce(),
) -> Result<StableTextFile, EvidenceError> {
    if maximum_bytes > MAX_STABLE_TEXT_BYTES {
        return Err(EvidenceError::new(
            DiagnosticCode::EVIDENCE_TOO_LARGE,
            format!(
                "requested evidence limit {maximum_bytes} exceeds hard limit {MAX_STABLE_TEXT_BYTES}"
            ),
        ));
    }
    let requested = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.as_path().join(candidate)
    };
    let path_before = fs::symlink_metadata(&requested).map_err(map_io_error)?;
    if path_before.file_type().is_symlink() || !path_before.is_file() {
        return Err(EvidenceError::new(
            DiagnosticCode::EVIDENCE_NOT_REGULAR_FILE,
            format!(
                "evidence is not a direct regular file: {}",
                requested.display()
            ),
        ));
    }

    let source = canonicalize_contained(root, &requested)?;
    let mut file = File::open(source.as_path()).map_err(map_io_error)?;
    let before = file.metadata().map_err(map_io_error)?;
    verify_open_path(root, &requested, &source, &path_before, &before)?;
    if before.len() > maximum_bytes {
        return Err(EvidenceError::new(
            DiagnosticCode::EVIDENCE_TOO_LARGE,
            format!(
                "evidence exceeds {maximum_bytes} bytes: {}",
                source.as_path().display()
            ),
        ));
    }

    before_read();

    let read_limit = maximum_bytes.checked_add(1).ok_or_else(|| {
        EvidenceError::new(
            DiagnosticCode::EVIDENCE_TOO_LARGE,
            "evidence limit cannot be represented",
        )
    })?;
    let mut bytes = Vec::new();
    let mut hasher = Sha256Hasher::new();
    let mut reader = (&mut file).take(read_limit);
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut chunk).map_err(map_io_error)?;
        if count == 0 {
            break;
        }
        hasher.update(&chunk[..count]);
        bytes.extend_from_slice(&chunk[..count]);
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
        return Err(EvidenceError::new(
            DiagnosticCode::EVIDENCE_TOO_LARGE,
            format!(
                "evidence grew beyond {maximum_bytes} bytes while reading: {}",
                source.as_path().display()
            ),
        ));
    }

    let after = file.metadata().map_err(map_io_error)?;
    verify_after_read(root, &requested, &source, &before, &after, bytes.len())?;
    let text = String::from_utf8(bytes).map_err(|error| {
        EvidenceError::new(
            DiagnosticCode::EVIDENCE_READ_FAILED,
            format!("evidence is not valid UTF-8: {error}"),
        )
    })?;
    Ok(StableTextFile {
        source,
        size: after.len(),
        sha256: hasher.finalize(),
        modified_at: after.modified().map_err(map_io_error)?,
        text,
    })
}

fn verify_open_path(
    root: &CanonicalDirectory,
    requested: &Path,
    source: &CanonicalPath,
    path_before: &Metadata,
    opened: &Metadata,
) -> Result<(), EvidenceError> {
    let path_after = fs::symlink_metadata(requested).map_err(map_io_error)?;
    let source_after = canonicalize_contained(root, requested)?;
    if path_after.file_type().is_symlink()
        || identity(path_before) != identity(opened)
        || identity(&path_after) != identity(opened)
        || source_after != *source
    {
        return Err(changed(requested, "path changed while opening"));
    }
    Ok(())
}

fn verify_after_read(
    root: &CanonicalDirectory,
    requested: &Path,
    source: &CanonicalPath,
    before: &Metadata,
    after: &Metadata,
    bytes_read: usize,
) -> Result<(), EvidenceError> {
    let path_after = fs::symlink_metadata(requested).map_err(map_io_error)?;
    let source_after = canonicalize_contained(root, requested)?;
    let byte_count = u64::try_from(bytes_read).unwrap_or(u64::MAX);
    if path_after.file_type().is_symlink()
        || identity(before) != identity(after)
        || identity(&path_after) != identity(after)
        || source_after != *source
        || byte_count != after.len()
    {
        return Err(changed(requested, "path or file changed while reading"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn identity(metadata: &Metadata) -> MetadataIdentity {
    MetadataIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn changed(path: &Path, detail: &str) -> EvidenceError {
    EvidenceError::new(
        DiagnosticCode::EVIDENCE_CHANGED_DURING_READ,
        format!("{detail}: {}", path.display()),
    )
}

fn map_io_error(error: io::Error) -> EvidenceError {
    let code = if error.kind() == io::ErrorKind::NotFound {
        DiagnosticCode::EVIDENCE_MISSING
    } else {
        DiagnosticCode::EVIDENCE_READ_FAILED
    };
    EvidenceError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonicalize_contained, canonicalize_directory};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        path: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> io::Result<Self> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "leanbun-evidence-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self { path })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn canonical_containment_rejects_lexical_and_resolved_escape()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("containment")?;
        let root_path = fixture.path.join("root");
        let outside = fixture.path.join("outside");
        fs::create_dir(&root_path)?;
        fs::create_dir(&outside)?;
        fs::write(root_path.join("inside.txt"), "inside")?;
        fs::write(outside.join("outside.txt"), "outside")?;
        symlink(&outside, root_path.join("link"))?;
        let root = canonicalize_directory(&root_path)?;

        assert!(canonicalize_contained(&root, "inside.txt").is_ok());
        assert_eq!(
            canonicalize_contained(&root, "../outside/outside.txt").map_err(|error| error.code),
            Err(DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT)
        );
        assert_eq!(
            canonicalize_contained(&root, "link/outside.txt").map_err(|error| error.code),
            Err(DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT)
        );
        Ok(())
    }

    #[test]
    fn stable_reader_enforces_regular_utf8_and_size() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("stable")?;
        let file = fixture.path.join("evidence.txt");
        let linked = fixture.path.join("linked.txt");
        fs::write(&file, "evidence")?;
        symlink(&file, &linked)?;
        let root = canonicalize_directory(&fixture.path)?;

        let observed = read_stable_text(&root, "evidence.txt", 8)?;
        assert_eq!(observed.text, "evidence");
        assert_eq!(observed.size, 8);
        assert_eq!(
            observed.sha256.to_string(),
            "ee8250fb76e094b34b471f13a73dbbe51d1ae142e9df59d7c0d31ec20f0a0a8e"
        );
        assert_eq!(
            read_stable_text(&root, "evidence.txt", 7).map_err(|error| error.code),
            Err(DiagnosticCode::EVIDENCE_TOO_LARGE)
        );
        assert_eq!(
            read_stable_text(&root, "evidence.txt", MAX_STABLE_TEXT_BYTES + 1)
                .map_err(|error| error.code),
            Err(DiagnosticCode::EVIDENCE_TOO_LARGE)
        );
        assert_eq!(
            read_stable_text(&root, "linked.txt", 8).map_err(|error| error.code),
            Err(DiagnosticCode::EVIDENCE_NOT_REGULAR_FILE)
        );
        fs::write(&file, [0xff])?;
        assert_eq!(
            read_stable_text(&root, "evidence.txt", 8).map_err(|error| error.code),
            Err(DiagnosticCode::EVIDENCE_READ_FAILED)
        );
        Ok(())
    }

    #[test]
    fn stable_reader_detects_same_size_content_change() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("content-race")?;
        let file = fixture.path.join("evidence.txt");
        fs::write(&file, "alpha")?;
        let root = canonicalize_directory(&fixture.path)?;
        let result = read_stable_text_with_hook(&root, Path::new("evidence.txt"), 5, || {
            let _ = fs::write(&file, "bravo");
        });
        assert_eq!(
            result.map_err(|error| error.code),
            Err(DiagnosticCode::EVIDENCE_CHANGED_DURING_READ)
        );
        Ok(())
    }

    #[test]
    fn stable_reader_detects_path_replacement() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("path-race")?;
        let file = fixture.path.join("evidence.txt");
        let moved = fixture.path.join("moved.txt");
        fs::write(&file, "alpha")?;
        let root = canonicalize_directory(&fixture.path)?;
        let result = read_stable_text_with_hook(&root, Path::new("evidence.txt"), 5, || {
            let _ = fs::rename(&file, &moved);
            let _ = fs::write(&file, "bravo");
        });
        assert_eq!(
            result.map_err(|error| error.code),
            Err(DiagnosticCode::EVIDENCE_CHANGED_DURING_READ)
        );
        Ok(())
    }
}

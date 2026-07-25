use leanbun_core::{DiagnosticCode, Sha256, Sha256Hasher};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::{CanonicalDirectory, EvidenceError, canonicalize_contained};

pub const PROJECT_INPUT_TREE_SCHEMA: &str = "leanbun-project-input-tree-v1";
pub const MAX_PROJECT_TREE_ENTRIES: u64 = 500_000;
pub const MAX_PROJECT_TREE_FILE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_PROJECT_TREE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInputTreeHash {
    pub schema: &'static str,
    pub tree_hash: Sha256,
    pub entry_count: u64,
    pub file_count: u64,
    pub byte_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeEntry {
    path: PathBuf,
    relative_path: String,
    kind: EntryKind,
    identity: MetadataIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Directory,
    File,
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

pub fn hash_project_input_tree(
    root: &CanonicalDirectory,
) -> Result<ProjectInputTreeHash, EvidenceError> {
    hash_project_input_tree_with_hook(root, || {})
}

fn hash_project_input_tree_with_hook(
    root: &CanonicalDirectory,
    after_collection: impl FnOnce(),
) -> Result<ProjectInputTreeHash, EvidenceError> {
    let entries = collect_entries(root)?;
    after_collection();
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"{\"schema\":\"leanbun-project-input-tree-v1\"}\n");
    let mut file_count = 0_u64;
    let mut byte_count = 0_u64;

    for entry in &entries {
        let metadata = fs::symlink_metadata(&entry.path).map_err(map_io_error)?;
        if identity(&metadata) != entry.identity {
            return Err(changed(&entry.path, "tree entry changed after collection"));
        }
        let observed_kind = classify(&metadata, &entry.path)?;
        if observed_kind != entry.kind {
            return Err(changed(
                &entry.path,
                "tree entry type changed during hashing",
            ));
        }
        let mode = metadata.mode() & 0o7777;
        match entry.kind {
            EntryKind::Directory => {
                let line = directory_record(&entry.relative_path, mode);
                hasher.update(line.as_bytes());
            }
            EntryKind::File => {
                let (size, digest) = hash_stable_file(root, &entry.path, &metadata)?;
                byte_count = byte_count.checked_add(size).ok_or_else(tree_too_large)?;
                if byte_count > MAX_PROJECT_TREE_BYTES {
                    return Err(tree_too_large());
                }
                file_count += 1;
                let line = file_record(&entry.relative_path, mode, size, digest);
                hasher.update(line.as_bytes());
            }
        }
    }
    verify_entries_unchanged(&entries)?;

    Ok(ProjectInputTreeHash {
        schema: PROJECT_INPUT_TREE_SCHEMA,
        tree_hash: hasher.finalize(),
        entry_count: u64::try_from(entries.len()).unwrap_or(u64::MAX),
        file_count,
        byte_count,
    })
}

fn collect_entries(root: &CanonicalDirectory) -> Result<Vec<TreeEntry>, EvidenceError> {
    let mut entries = Vec::new();
    let mut pending = vec![(root.as_path().to_path_buf(), String::from("."))];
    while let Some((path, relative_path)) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).map_err(map_io_error)?;
        let kind = classify(&metadata, &path)?;
        if relative_path != "." && excluded(&relative_path, kind) {
            continue;
        }
        entries.push(TreeEntry {
            path: path.clone(),
            relative_path: relative_path.clone(),
            kind,
            identity: identity(&metadata),
        });
        if entries.len() as u64 > MAX_PROJECT_TREE_ENTRIES {
            return Err(EvidenceError::new(
                DiagnosticCode::TREE_HASH_LIMIT_EXCEEDED,
                format!(
                    "project input tree exceeds {MAX_PROJECT_TREE_ENTRIES} entries: {}",
                    root.as_path().display()
                ),
            ));
        }
        if kind == EntryKind::Directory {
            let mut children = Vec::new();
            for child in fs::read_dir(&path).map_err(map_io_error)? {
                let child = child.map_err(map_io_error)?;
                let name = child.file_name().into_string().map_err(|_| {
                    EvidenceError::new(
                        DiagnosticCode::EVIDENCE_READ_FAILED,
                        format!(
                            "tree entry name is not valid UTF-8: {}",
                            child.path().display()
                        ),
                    )
                })?;
                let child_relative = if relative_path == "." {
                    name
                } else {
                    format!("{relative_path}/{name}")
                };
                children.push((child.path(), child_relative));
            }
            children.sort_by(|left, right| left.1.as_bytes().cmp(right.1.as_bytes()));
            pending.extend(children.into_iter().rev());
        }
    }
    entries.sort_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });
    Ok(entries)
}

fn verify_entries_unchanged(entries: &[TreeEntry]) -> Result<(), EvidenceError> {
    for entry in entries {
        let metadata = fs::symlink_metadata(&entry.path).map_err(map_io_error)?;
        if identity(&metadata) != entry.identity || classify(&metadata, &entry.path)? != entry.kind
        {
            return Err(changed(
                &entry.path,
                "tree entry changed before snapshot completion",
            ));
        }
    }
    Ok(())
}

fn excluded(relative_path: &str, kind: EntryKind) -> bool {
    let name = relative_path.rsplit('/').next().unwrap_or(relative_path);
    match kind {
        EntryKind::Directory => {
            name == ".git" || name == ".lake" || relative_path == ".leanbun/tmp"
        }
        EntryKind::File => name == ".DS_Store",
    }
}

fn classify(metadata: &Metadata, path: &Path) -> Result<EntryKind, EvidenceError> {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        Ok(EntryKind::Directory)
    } else if file_type.is_file() {
        Ok(EntryKind::File)
    } else {
        Err(EvidenceError::new(
            if file_type.is_symlink() {
                DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT
            } else {
                DiagnosticCode::EVIDENCE_NOT_REGULAR_FILE
            },
            format!("unsupported project input tree entry: {}", path.display()),
        ))
    }
}

fn hash_stable_file(
    root: &CanonicalDirectory,
    requested: &Path,
    path_before: &Metadata,
) -> Result<(u64, Sha256), EvidenceError> {
    if path_before.len() > MAX_PROJECT_TREE_FILE_BYTES {
        return Err(tree_too_large());
    }
    let source = canonicalize_contained(root, requested)?;
    let mut file = File::open(source.as_path()).map_err(map_io_error)?;
    let before = file.metadata().map_err(map_io_error)?;
    let path_opened = fs::symlink_metadata(requested).map_err(map_io_error)?;
    if path_opened.file_type().is_symlink()
        || identity(path_before) != identity(&before)
        || identity(&path_opened) != identity(&before)
    {
        return Err(changed(requested, "tree file changed while opening"));
    }

    let mut hasher = Sha256Hasher::new();
    let mut reader = (&mut file).take(MAX_PROJECT_TREE_FILE_BYTES + 1);
    let mut bytes_read = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut chunk).map_err(map_io_error)?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or_else(tree_too_large)?;
        if bytes_read > MAX_PROJECT_TREE_FILE_BYTES {
            return Err(tree_too_large());
        }
        hasher.update(&chunk[..count]);
    }

    let after = file.metadata().map_err(map_io_error)?;
    let path_after = fs::symlink_metadata(requested).map_err(map_io_error)?;
    let source_after = canonicalize_contained(root, requested)?;
    if path_after.file_type().is_symlink()
        || identity(&before) != identity(&after)
        || identity(&path_after) != identity(&after)
        || source_after != source
        || bytes_read != after.len()
    {
        return Err(changed(requested, "tree file changed while reading"));
    }
    Ok((bytes_read, hasher.finalize()))
}

fn directory_record(path: &str, mode: u32) -> String {
    let mut output = String::from("{\"owner\":\"project\",\"path\":");
    push_json_string(&mut output, path);
    output.push_str(",\"type\":\"directory\",\"mode\":");
    output.push_str(&mode.to_string());
    output.push_str("}\n");
    output
}

fn file_record(path: &str, mode: u32, size: u64, digest: Sha256) -> String {
    let mut output = String::from("{\"owner\":\"project\",\"path\":");
    push_json_string(&mut output, path);
    output.push_str(",\"type\":\"file\",\"mode\":");
    output.push_str(&mode.to_string());
    output.push_str(",\"size\":");
    output.push_str(&size.to_string());
    output.push_str(",\"sha256\":\"");
    output.push_str(&digest.to_string());
    output.push_str("\"}\n");
    output
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            _ => output.push(character),
        }
    }
    output.push('"');
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

fn tree_too_large() -> EvidenceError {
    EvidenceError::new(
        DiagnosticCode::TREE_HASH_LIMIT_EXCEEDED,
        "project input tree exceeds byte limit",
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
    use crate::canonicalize_directory;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> io::Result<Self> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("leanbun-tree-{label}-{}-{id}", std::process::id()));
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
            Ok(Self(path))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    fn decode_hex(value: &str) -> io::Result<Vec<u8>> {
        if !value.len().is_multiple_of(2) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "odd hex length"));
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                u8::from_str_radix(text, 16)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })
            .collect()
    }

    #[test]
    fn shared_project_input_tree_matches_bun_oracle() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("golden")?;
        let golden = include_str!("../../../golden/project-input-tree.tsv");
        let mut expected = None;
        let mut expected_counts = None;
        for line in golden.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.as_slice() {
                ["expected", digest] => expected = Some(*digest),
                ["counts", entries, files, bytes] => {
                    expected_counts = Some((
                        entries.parse::<u64>()?,
                        files.parse::<u64>()?,
                        bytes.parse::<u64>()?,
                    ));
                }
                ["dir" | "excluded-dir", mode, relative] => {
                    let path = fixture.0.join(relative);
                    fs::create_dir_all(&path)?;
                    fs::set_permissions(
                        &path,
                        fs::Permissions::from_mode(u32::from_str_radix(mode, 8)?),
                    )?;
                }
                ["file" | "excluded-file", mode, relative, hex] => {
                    let path = fixture.0.join(relative);
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    write(&path, &decode_hex(hex)?, u32::from_str_radix(mode, 8)?)?;
                }
                _ => {}
            }
        }
        write(&fixture.0.join(".git/ignored"), b"git", 0o644)?;
        write(&fixture.0.join(".lake/ignored"), b"lake", 0o644)?;
        write(&fixture.0.join(".leanbun/tmp/ignored"), b"tmp", 0o644)?;

        let root = canonicalize_directory(&fixture.0)?;
        let observed = hash_project_input_tree(&root)?;
        assert_eq!(Some(observed.tree_hash.to_string().as_str()), expected);
        assert_eq!(
            Some((
                observed.entry_count,
                observed.file_count,
                observed.byte_count
            )),
            expected_counts
        );
        Ok(())
    }

    #[test]
    fn hashes_project_input_and_excludes_generated_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("content")?;
        fs::create_dir(fixture.0.join(".lake"))?;
        fs::create_dir_all(fixture.0.join(".leanbun/tmp"))?;
        write(&fixture.0.join("Main.lean"), b"def value := 1\n", 0o644)?;
        write(&fixture.0.join(".lake/output"), b"first", 0o644)?;
        write(&fixture.0.join(".leanbun/tmp/log"), b"first", 0o644)?;
        let root = canonicalize_directory(&fixture.0)?;
        let first = hash_project_input_tree(&root)?;
        write(&fixture.0.join(".lake/output"), b"second", 0o644)?;
        write(&fixture.0.join(".leanbun/tmp/log"), b"second", 0o644)?;
        assert_eq!(hash_project_input_tree(&root)?.tree_hash, first.tree_hash);
        write(&fixture.0.join("Main.lean"), b"def value := 2\n", 0o644)?;
        assert_ne!(hash_project_input_tree(&root)?.tree_hash, first.tree_hash);
        Ok(())
    }

    #[test]
    fn rejects_directory_changes_after_collection() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("directory-race")?;
        write(&fixture.0.join("Main.lean"), b"def value := 1\n", 0o644)?;
        let root = canonicalize_directory(&fixture.0)?;
        let result = hash_project_input_tree_with_hook(&root, || {
            let _ = write(&fixture.0.join("Added.lean"), b"def added := 2\n", 0o644);
        });
        assert_eq!(
            result.map_err(|error| error.code),
            Err(DiagnosticCode::EVIDENCE_CHANGED_DURING_READ)
        );
        Ok(())
    }

    #[test]
    fn rejects_symlinks_before_following_them() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("symlink")?;
        write(&fixture.0.join("target"), b"target", 0o644)?;
        symlink(fixture.0.join("target"), fixture.0.join("link"))?;
        let root = canonicalize_directory(&fixture.0)?;
        assert_eq!(
            hash_project_input_tree(&root).map_err(|error| error.code),
            Err(DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT)
        );
        Ok(())
    }

    #[test]
    fn rejects_non_file_non_directory_entries() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::net::UnixListener;

        let fixture = Fixture::new("socket")?;
        let _listener = UnixListener::bind(fixture.0.join("control.sock"))?;
        let root = canonicalize_directory(&fixture.0)?;
        assert_eq!(
            hash_project_input_tree(&root).map_err(|error| error.code),
            Err(DiagnosticCode::EVIDENCE_NOT_REGULAR_FILE)
        );
        Ok(())
    }
}

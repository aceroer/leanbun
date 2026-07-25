use crate::model::{
    LeanStoreError, LeanStoreErrorKind, LeanStoreLimitsV1, NormalizedTreeEntryKindV1,
    NormalizedTreeEntryV1, sha256,
};
use leanbun_core::{Sha256, Sha256Hasher};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::Path;

const TAR_BLOCK: usize = 512;

#[derive(Clone)]
pub(crate) struct PlannedTreeEntry {
    pub metadata: NormalizedTreeEntryV1,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Clone)]
pub(crate) struct TreePlan {
    pub entries: Vec<PlannedTreeEntry>,
    pub digest: Sha256,
}

pub fn normalized_tar_tree_sha256_v1(
    bytes: &[u8],
    limits: LeanStoreLimitsV1,
) -> Result<Sha256, LeanStoreError> {
    Ok(parse_tar(bytes, limits.validate()?)?.digest)
}

pub fn normalized_directory_tree_sha256_v1(
    root: &Path,
    limits: LeanStoreLimitsV1,
) -> Result<Sha256, LeanStoreError> {
    Ok(plan_directory(root, limits.validate()?)?.digest)
}

pub(crate) fn parse_tar(
    bytes: &[u8],
    limits: LeanStoreLimitsV1,
) -> Result<TreePlan, LeanStoreError> {
    if bytes.len() as u64 > limits.maximum_download_bytes {
        return Err(limit("archive exceeds download byte limit"));
    }
    if bytes.len() < TAR_BLOCK * 2 || !bytes.len().is_multiple_of(TAR_BLOCK) {
        return Err(malformed("archive is not a complete tar block stream"));
    }
    let mut offset = 0usize;
    let mut zero_blocks = 0usize;
    let mut explicit = BTreeSet::new();
    let mut entries = BTreeMap::<String, PlannedTreeEntry>::new();
    let mut expanded = 0u64;
    while offset + TAR_BLOCK <= bytes.len() {
        let header = &bytes[offset..offset + TAR_BLOCK];
        offset += TAR_BLOCK;
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            if zero_blocks == 2 {
                if bytes[offset..].iter().any(|byte| *byte != 0) {
                    return Err(malformed("nonzero data follows tar terminator"));
                }
                break;
            }
            continue;
        }
        if zero_blocks != 0 {
            return Err(malformed("single zero tar block before another entry"));
        }
        verify_checksum(header)?;
        let name = tar_path(header)?;
        validate_relative_entry_path(&name)?;
        let size = parse_octal(&header[124..136], "tar size")?;
        let type_flag = header[156];
        if type_flag == b'g' {
            offset = consume_git_global_pax(bytes, offset, size, &name)?;
            continue;
        }
        if !explicit.insert(name.clone()) {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::DuplicateArchiveEntry,
                format!("duplicate archive entry: {name}"),
            ));
        }
        if explicit.len() > limits.maximum_entries {
            return Err(limit("archive entry count exceeds limit"));
        }
        let mode = parse_octal(&header[100..108], "tar mode")?;
        add_parent_directories(&name, &mut entries)?;
        match type_flag {
            0 | b'0' => {
                if size > limits.maximum_file_bytes {
                    return Err(LeanStoreError::new(
                        LeanStoreErrorKind::ExpansionLimit,
                        format!("archive file exceeds limit: {name}"),
                    ));
                }
                expanded = expanded
                    .checked_add(size)
                    .ok_or_else(|| limit("expanded size overflow"))?;
                if expanded > limits.maximum_expanded_bytes {
                    return Err(LeanStoreError::new(
                        LeanStoreErrorKind::ExpansionLimit,
                        "archive expanded bytes exceed limit",
                    ));
                }
                let data_end = offset
                    .checked_add(usize::try_from(size).map_err(|_| limit("file size overflow"))?)
                    .ok_or_else(|| limit("file range overflow"))?;
                if data_end > bytes.len() {
                    return Err(malformed("archive file body is truncated"));
                }
                let data = bytes[offset..data_end].to_vec();
                let padded = usize::try_from(size)
                    .map_err(|_| limit("file size overflow"))?
                    .div_ceil(TAR_BLOCK)
                    .checked_mul(TAR_BLOCK)
                    .ok_or_else(|| limit("padded file size overflow"))?;
                offset = offset
                    .checked_add(padded)
                    .ok_or_else(|| limit("archive offset overflow"))?;
                if offset > bytes.len() {
                    return Err(malformed("archive file padding is truncated"));
                }
                insert_entry(
                    &mut entries,
                    name.clone(),
                    PlannedTreeEntry {
                        metadata: NormalizedTreeEntryV1 {
                            path: name,
                            kind: NormalizedTreeEntryKindV1::File,
                            mode: if mode & 0o111 == 0 { 0o644 } else { 0o755 },
                            size,
                            sha256: Some(sha256(&data)),
                        },
                        bytes: Some(data),
                    },
                )?;
            }
            b'5' => {
                if size != 0 {
                    return Err(malformed("directory tar entry has nonzero size"));
                }
                insert_directory(&mut entries, name)?;
            }
            b'2' | b'1' => {
                if limits.maximum_entries > crate::model::MAX_TREE_ENTRIES_V1 && size == 0 {
                    continue;
                }
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::UnsafeSymlink,
                    format!("archive links are forbidden: {name}"),
                ));
            }
            _ => {
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::SpecialFile,
                    format!("archive special entry is forbidden: {name}"),
                ));
            }
        }
    }
    if zero_blocks != 2 {
        return Err(malformed("archive lacks two-block terminator"));
    }
    if entries.len() > limits.maximum_entries {
        return Err(limit("normalized tree entry count exceeds limit"));
    }
    let entries = entries.into_values().collect::<Vec<_>>();
    let digest = tree_digest(
        &entries
            .iter()
            .map(|entry| entry.metadata.clone())
            .collect::<Vec<_>>(),
    );
    Ok(TreePlan { entries, digest })
}

fn consume_git_global_pax(
    bytes: &[u8],
    offset: usize,
    size: u64,
    name: &str,
) -> Result<usize, LeanStoreError> {
    if name != "pax_global_header" || size > 4_096 {
        return Err(malformed("noncanonical global PAX header is forbidden"));
    }
    let size = usize::try_from(size).map_err(|_| limit("PAX size overflow"))?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| limit("PAX range overflow"))?;
    if end > bytes.len() {
        return Err(malformed("global PAX header is truncated"));
    }
    let record = std::str::from_utf8(&bytes[offset..end])
        .map_err(|_| malformed("global PAX header is not UTF-8"))?;
    let (_, value) = record
        .trim_end_matches('\n')
        .split_once(" comment=")
        .ok_or_else(|| malformed("global PAX header is not a Git commit comment"))?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(malformed("global PAX Git commit is not canonical SHA-1"));
    }
    let declared = record
        .split_once(' ')
        .and_then(|(length, _)| length.parse::<usize>().ok())
        .ok_or_else(|| malformed("global PAX length is invalid"))?;
    if declared != size || !record.ends_with('\n') {
        return Err(malformed("global PAX length differs from its body"));
    }
    let padded = size
        .div_ceil(TAR_BLOCK)
        .checked_mul(TAR_BLOCK)
        .ok_or_else(|| limit("PAX padding overflow"))?;
    let next = offset
        .checked_add(padded)
        .ok_or_else(|| limit("PAX offset overflow"))?;
    if next > bytes.len() {
        return Err(malformed("global PAX padding is truncated"));
    }
    Ok(next)
}

pub(crate) fn plan_directory(
    root: &Path,
    limits: LeanStoreLimitsV1,
) -> Result<TreePlan, LeanStoreError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| boundary(format!("cannot inspect source directory: {error}")))?;
    if !metadata.file_type().is_dir() {
        return Err(boundary("local source is not a directory"));
    }
    let mut entries = BTreeMap::new();
    let mut expanded = 0u64;
    collect_directory(root, root, limits, &mut expanded, &mut entries)?;
    if entries.len() > limits.maximum_entries {
        return Err(limit("normalized directory entry count exceeds limit"));
    }
    let entries = entries.into_values().collect::<Vec<_>>();
    let digest = tree_digest(
        &entries
            .iter()
            .map(|entry| entry.metadata.clone())
            .collect::<Vec<_>>(),
    );
    Ok(TreePlan { entries, digest })
}

fn collect_directory(
    root: &Path,
    directory: &Path,
    limits: LeanStoreLimitsV1,
    expanded: &mut u64,
    entries: &mut BTreeMap<String, PlannedTreeEntry>,
) -> Result<(), LeanStoreError> {
    let mut children = fs::read_dir(directory)
        .map_err(|error| boundary(format!("cannot read local source directory: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| boundary(format!("cannot enumerate local source directory: {error}")))?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| boundary("local source path escaped root"))?;
        let relative = portable_relative_path(relative)?;
        if relative
            .split('/')
            .any(|part| matches!(part, ".git" | ".lake"))
        {
            continue;
        }
        validate_relative_entry_path(&relative)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| boundary(format!("cannot inspect local source entry: {error}")))?;
        if metadata.file_type().is_symlink() {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::UnsafeSymlink,
                format!("local source symlink is forbidden: {relative}"),
            ));
        }
        if metadata.file_type().is_dir() {
            insert_directory(entries, relative)?;
            collect_directory(root, &path, limits, expanded, entries)?;
        } else if metadata.file_type().is_file() {
            let size = metadata.len();
            if size > limits.maximum_file_bytes {
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::ExpansionLimit,
                    format!("local source file exceeds limit: {relative}"),
                ));
            }
            *expanded = expanded
                .checked_add(size)
                .ok_or_else(|| limit("local source size overflow"))?;
            if *expanded > limits.maximum_expanded_bytes {
                return Err(limit("local source expanded bytes exceed limit"));
            }
            let file = fs::File::open(&path)
                .map_err(|error| boundary(format!("cannot open local source file: {error}")))?;
            let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
            file.take(limits.maximum_file_bytes + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| boundary(format!("cannot read local source file: {error}")))?;
            if bytes.len() as u64 != size {
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::TreeDrift,
                    format!("local source file changed while reading: {relative}"),
                ));
            }
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::MetadataExt;
                metadata.mode() & 0o111 != 0
            };
            #[cfg(not(unix))]
            let executable = false;
            entries.insert(
                relative.clone(),
                PlannedTreeEntry {
                    metadata: NormalizedTreeEntryV1 {
                        path: relative,
                        kind: NormalizedTreeEntryKindV1::File,
                        mode: if executable { 0o755 } else { 0o644 },
                        size,
                        sha256: Some(sha256(&bytes)),
                    },
                    bytes: Some(bytes),
                },
            );
        } else {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::SpecialFile,
                format!("local source special file is forbidden: {relative}"),
            ));
        }
        if entries.len() > limits.maximum_entries {
            return Err(limit("local source entry count exceeds limit"));
        }
    }
    Ok(())
}

pub(crate) fn tree_digest(entries: &[NormalizedTreeEntryV1]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-normalized-source-tree-v1\0");
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&(entry.path.len() as u64).to_be_bytes());
        hasher.update(entry.path.as_bytes());
        hasher.update(&[match entry.kind {
            NormalizedTreeEntryKindV1::Directory => 1,
            NormalizedTreeEntryKindV1::File => 2,
        }]);
        hasher.update(&u64::from(entry.mode).to_be_bytes());
        hasher.update(&entry.size.to_be_bytes());
        match entry.sha256 {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(value.as_bytes());
            }
            None => hasher.update(&[0]),
        }
    }
    hasher.finalize()
}

fn verify_checksum(header: &[u8]) -> Result<(), LeanStoreError> {
    let expected = parse_octal(&header[148..156], "tar checksum")?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                b' '
            } else {
                *byte
            }
        })
        .map(u64::from)
        .sum::<u64>();
    if expected != actual {
        return Err(malformed("tar header checksum mismatch"));
    }
    Ok(())
}

fn tar_path(header: &[u8]) -> Result<String, LeanStoreError> {
    let name = field_string(&header[..100], "tar name")?;
    let prefix = field_string(&header[345..500], "tar prefix")?;
    let value = if prefix.is_empty() {
        name
    } else if name.is_empty() {
        prefix
    } else {
        format!("{prefix}/{name}")
    };
    Ok(value.trim_end_matches('/').to_owned())
}

fn field_string(bytes: &[u8], label: &str) -> Result<String, LeanStoreError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = std::str::from_utf8(&bytes[..end])
        .map_err(|_| malformed(format!("{label} is not UTF-8")))?;
    Ok(value.to_owned())
}

fn parse_octal(bytes: &[u8], label: &str) -> Result<u64, LeanStoreError> {
    let trimmed = bytes
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, 0 | b' '))
        .take_while(|byte| !matches!(byte, 0 | b' '))
        .collect::<Vec<_>>();
    if trimmed.is_empty() {
        return Ok(0);
    }
    let mut value = 0u64;
    for byte in trimmed {
        if !(b'0'..=b'7').contains(&byte) {
            return Err(malformed(format!("{label} is not canonical octal")));
        }
        value = value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| limit(format!("{label} overflow")))?;
    }
    Ok(value)
}

fn validate_relative_entry_path(path: &str) -> Result<(), LeanStoreError> {
    if path.is_empty() || path.len() > 4_096 || path.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::PathTraversal,
            "archive entry path is empty, oversized or contains controls",
        ));
    }
    if path.starts_with('/')
        || path.starts_with('\\')
        || (path.len() >= 2 && path.as_bytes()[1] == b':')
    {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::AbsoluteArchivePath,
            format!("absolute archive path is forbidden: {path}"),
        ));
    }
    if path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".." | ".git" | ".lake"))
    {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::PathTraversal,
            format!("nonnormal archive path is forbidden: {path}"),
        ));
    }
    Ok(())
}

fn add_parent_directories(
    path: &str,
    entries: &mut BTreeMap<String, PlannedTreeEntry>,
) -> Result<(), LeanStoreError> {
    let parts = path.split('/').collect::<Vec<_>>();
    for end in 1..parts.len() {
        insert_directory(entries, parts[..end].join("/"))?;
    }
    Ok(())
}

fn insert_directory(
    entries: &mut BTreeMap<String, PlannedTreeEntry>,
    path: String,
) -> Result<(), LeanStoreError> {
    match entries.get(&path) {
        Some(entry) if entry.metadata.kind == NormalizedTreeEntryKindV1::Directory => Ok(()),
        Some(_) => Err(LeanStoreError::new(
            LeanStoreErrorKind::DuplicateArchiveEntry,
            format!("file/directory archive collision: {path}"),
        )),
        None => {
            entries.insert(
                path.clone(),
                PlannedTreeEntry {
                    metadata: NormalizedTreeEntryV1 {
                        path,
                        kind: NormalizedTreeEntryKindV1::Directory,
                        mode: 0o755,
                        size: 0,
                        sha256: None,
                    },
                    bytes: None,
                },
            );
            Ok(())
        }
    }
}

fn insert_entry(
    entries: &mut BTreeMap<String, PlannedTreeEntry>,
    path: String,
    entry: PlannedTreeEntry,
) -> Result<(), LeanStoreError> {
    if entries.insert(path.clone(), entry).is_some() {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::DuplicateArchiveEntry,
            format!("file/directory archive collision: {path}"),
        ));
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> Result<String, LeanStoreError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(value) => {
                parts.push(
                    value
                        .to_str()
                        .ok_or_else(|| boundary("source path is not UTF-8"))?,
                );
            }
            _ => return Err(boundary("source path is not normalized and relative")),
        }
    }
    Ok(parts.join("/"))
}

fn malformed(message: impl Into<String>) -> LeanStoreError {
    LeanStoreError::new(LeanStoreErrorKind::ArchiveMalformed, message)
}

fn limit(message: impl Into<String>) -> LeanStoreError {
    LeanStoreError::new(LeanStoreErrorKind::LimitExceeded, message)
}

fn boundary(message: impl Into<String>) -> LeanStoreError {
    LeanStoreError::new(LeanStoreErrorKind::BoundaryViolation, message)
}

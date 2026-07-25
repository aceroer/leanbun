use leanbun_core::DiagnosticCode;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::EvidenceError;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalDirectory(PathBuf);

impl CanonicalDirectory {
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Display for CanonicalDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalPath(PathBuf);

impl CanonicalPath {
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(formatter)
    }
}

pub fn canonicalize_directory(path: impl AsRef<Path>) -> Result<CanonicalDirectory, EvidenceError> {
    let requested = path.as_ref();
    let canonical = fs::canonicalize(requested).map_err(|error| {
        EvidenceError::new(
            DiagnosticCode::PROJECT_NOT_FOUND,
            format!(
                "project directory cannot be resolved: {}: {error}",
                requested.display()
            ),
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        EvidenceError::new(
            DiagnosticCode::EVIDENCE_READ_FAILED,
            format!("canonical directory cannot be inspected: {error}"),
        )
    })?;
    if !metadata.is_dir() {
        return Err(EvidenceError::new(
            DiagnosticCode::PROJECT_NOT_DIRECTORY,
            format!("project is not a directory: {}", canonical.display()),
        ));
    }
    Ok(CanonicalDirectory(canonical))
}

pub fn canonicalize_contained(
    root: &CanonicalDirectory,
    candidate: impl AsRef<Path>,
) -> Result<CanonicalPath, EvidenceError> {
    let candidate = candidate.as_ref();
    let requested = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.as_path().join(candidate)
    };
    let lexical = lexical_normalize(&requested);
    if !lexical.starts_with(root.as_path()) {
        return Err(EvidenceError::new(
            DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT,
            format!(
                "path escapes allowed root before resolution: {}",
                requested.display()
            ),
        ));
    }

    let canonical = fs::canonicalize(&requested).map_err(|error| {
        EvidenceError::new(
            DiagnosticCode::EVIDENCE_MISSING,
            format!("path cannot be resolved: {}: {error}", requested.display()),
        )
    })?;
    if !canonical.starts_with(root.as_path()) {
        return Err(EvidenceError::new(
            DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT,
            format!(
                "resolved path escapes allowed root: {} -> {}",
                requested.display(),
                canonical.display()
            ),
        ));
    }
    Ok(CanonicalPath(canonical))
}

pub fn canonicalize_contained_directory(
    root: &CanonicalDirectory,
    candidate: impl AsRef<Path>,
) -> Result<CanonicalDirectory, EvidenceError> {
    let canonical = canonicalize_contained(root, candidate)?;
    let metadata = fs::metadata(canonical.as_path()).map_err(|error| {
        EvidenceError::new(
            DiagnosticCode::EVIDENCE_READ_FAILED,
            format!("contained directory cannot be inspected: {error}"),
        )
    })?;
    if !metadata.is_dir() {
        return Err(EvidenceError::new(
            DiagnosticCode::PROJECT_NOT_DIRECTORY,
            format!(
                "contained path is not a directory: {}",
                canonical.as_path().display()
            ),
        ));
    }
    Ok(CanonicalDirectory(canonical.0))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => output.push(prefix.as_os_str()),
            Component::RootDir => output.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            Component::Normal(value) => output.push(value),
        }
    }
    output
}

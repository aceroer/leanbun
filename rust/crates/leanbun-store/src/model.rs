use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lock::PackageKeyV1;
use leanbun_resolver::{LeanExactSourceV1, LeanPackageCandidateV1, LeanResolutionGraphV1};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::{fmt, time::Duration};

pub const MAX_FETCH_BYTES_V1: u64 = 64 * 1_024 * 1_024;
pub const MAX_EXPANDED_BYTES_V1: u64 = 256 * 1_024 * 1_024;
pub const MAX_FILE_BYTES_V1: u64 = 64 * 1_024 * 1_024;
pub const MAX_TREE_ENTRIES_V1: usize = 4_096;
pub const MAX_HTTP_HEADER_BYTES_V1: usize = 32 * 1_024;
const MAX_REGISTERED_TREE_ENTRIES_V1: usize = 262_144;
const MAX_REGISTERED_FETCH_BYTES_V1: u64 = 256 * 1_024 * 1_024;
const MAX_REGISTERED_EXPANDED_BYTES_V1: u64 = 512 * 1_024 * 1_024;
const MAX_REGISTERED_GIT_TIMEOUT_V1: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeanStoreErrorKind {
    InvalidField,
    BoundaryViolation,
    LimitExceeded,
    Cancelled,
    TaskIdentityConflict,
    TerminalTaskFailure,
    DownloadFailed,
    HttpProtocol,
    IntegrityMismatch,
    GitFailed,
    ArchiveMalformed,
    PathTraversal,
    AbsoluteArchivePath,
    UnsafeSymlink,
    SpecialFile,
    DuplicateArchiveEntry,
    ExpansionLimit,
    TreeDigestMismatch,
    TreeDrift,
    StoreObjectConflict,
    FileSyncFailed,
    DirectorySyncFailed,
    RenameFailed,
    IndeterminatePublication,
    FaultInjected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanStoreError {
    pub kind: LeanStoreErrorKind,
    pub message: String,
}

impl LeanStoreError {
    pub(crate) fn new(kind: LeanStoreErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for LeanStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LeanStoreError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeanStoreLimitsV1 {
    pub maximum_download_bytes: u64,
    pub maximum_expanded_bytes: u64,
    pub maximum_file_bytes: u64,
    pub maximum_entries: usize,
    pub maximum_retries: u8,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub git_timeout: Duration,
}

impl Default for LeanStoreLimitsV1 {
    fn default() -> Self {
        Self {
            maximum_download_bytes: MAX_FETCH_BYTES_V1,
            maximum_expanded_bytes: MAX_EXPANDED_BYTES_V1,
            maximum_file_bytes: MAX_FILE_BYTES_V1,
            maximum_entries: MAX_TREE_ENTRIES_V1,
            maximum_retries: 2,
            connect_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(5),
            git_timeout: Duration::from_secs(10),
        }
    }
}

impl LeanStoreLimitsV1 {
    #[must_use]
    pub const fn registered_provider() -> Self {
        Self {
            maximum_download_bytes: MAX_REGISTERED_FETCH_BYTES_V1,
            maximum_expanded_bytes: MAX_REGISTERED_EXPANDED_BYTES_V1,
            maximum_file_bytes: MAX_FILE_BYTES_V1,
            maximum_entries: MAX_REGISTERED_TREE_ENTRIES_V1,
            maximum_retries: 2,
            connect_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(5),
            git_timeout: MAX_REGISTERED_GIT_TIMEOUT_V1,
        }
    }

    pub fn validate(self) -> Result<Self, LeanStoreError> {
        let defaults = Self::default();
        if self.maximum_download_bytes == 0
            || self.maximum_download_bytes > MAX_REGISTERED_FETCH_BYTES_V1
            || self.maximum_expanded_bytes == 0
            || self.maximum_expanded_bytes > MAX_REGISTERED_EXPANDED_BYTES_V1
            || self.maximum_file_bytes == 0
            || self.maximum_file_bytes > defaults.maximum_file_bytes
            || self.maximum_entries == 0
            || self.maximum_entries > MAX_REGISTERED_TREE_ENTRIES_V1
            || self.maximum_retries > 3
            || self.connect_timeout.is_zero()
            || self.connect_timeout > defaults.connect_timeout
            || self.io_timeout.is_zero()
            || self.io_timeout > defaults.io_timeout
            || self.git_timeout.is_zero()
            || self.git_timeout > MAX_REGISTERED_GIT_TIMEOUT_V1
        {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::LimitExceeded,
                "store limits must be positive and no broader than v1 maxima",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeanFetchSourceV1 {
    LocalArchive { path: PathBuf },
    LoopbackHttp { url: String },
    LocalGit { repository: PathBuf },
    LocalDirectory { path: PathBuf },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanFetchRequestV1 {
    package: PackageKeyV1,
    candidate: LeanPackageCandidateV1,
    graph_identity: Sha256,
    source: LeanFetchSourceV1,
    allowed_source_root: PathBuf,
    limits: LeanStoreLimitsV1,
    identity: Sha256,
}

impl LeanFetchRequestV1 {
    pub fn from_graph(
        graph: &LeanResolutionGraphV1,
        package: &PackageKeyV1,
        source: LeanFetchSourceV1,
        allowed_source_root: impl Into<PathBuf>,
        limits: LeanStoreLimitsV1,
    ) -> Result<Self, LeanStoreError> {
        let limits = limits.validate()?;
        let resolved = graph
            .packages()
            .iter()
            .find(|candidate| candidate.key() == package)
            .ok_or_else(|| {
                LeanStoreError::new(
                    LeanStoreErrorKind::InvalidField,
                    "fetch package is absent from the M33 graph",
                )
            })?;
        match (&source, resolved.source()) {
            (LeanFetchSourceV1::LocalDirectory { .. }, LeanExactSourceV1::Path { .. }) => {}
            (
                LeanFetchSourceV1::LocalArchive { .. }
                | LeanFetchSourceV1::LoopbackHttp { .. }
                | LeanFetchSourceV1::LocalGit { .. },
                LeanExactSourceV1::Git { .. },
            ) => {}
            _ => {
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::InvalidField,
                    "fetch source kind differs from the exact M33 source",
                ));
            }
        }
        let allowed_source_root = allowed_source_root.into();
        let identity = request_identity(
            graph.identity(),
            package,
            resolved.candidate().identity(),
            &source,
            &allowed_source_root,
            limits,
        )?;
        Ok(Self {
            package: package.clone(),
            candidate: resolved.candidate().clone(),
            graph_identity: graph.identity(),
            source,
            allowed_source_root,
            limits,
            identity,
        })
    }

    #[must_use]
    pub fn package(&self) -> &PackageKeyV1 {
        &self.package
    }
    #[must_use]
    pub const fn candidate(&self) -> &LeanPackageCandidateV1 {
        &self.candidate
    }
    #[must_use]
    pub const fn graph_identity(&self) -> Sha256 {
        self.graph_identity
    }
    #[must_use]
    pub const fn source(&self) -> &LeanFetchSourceV1 {
        &self.source
    }
    #[must_use]
    pub fn allowed_source_root(&self) -> &Path {
        &self.allowed_source_root
    }
    #[must_use]
    pub const fn limits(&self) -> LeanStoreLimitsV1 {
        self.limits
    }
    #[must_use]
    pub const fn identity(&self) -> Sha256 {
        self.identity
    }
}

#[derive(Clone, Default)]
pub struct LeanFetchCancellationV1(Arc<AtomicBool>);

impl LeanFetchCancellationV1 {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LeanFetchFaultV1 {
    #[default]
    None,
    Download,
    Extract,
    FileSync,
    DirectorySync,
    Rename,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeanStorePublicationV1 {
    Published,
    Reused,
    Deduplicated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDownloadBlobV1 {
    sha256: Sha256,
    size: u64,
}

impl VerifiedDownloadBlobV1 {
    #[must_use]
    pub const fn sha256(&self) -> Sha256 {
        self.sha256
    }
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
    pub(crate) const fn new(sha256: Sha256, size: u64) -> Self {
        Self { sha256, size }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NormalizedTreeEntryKindV1 {
    Directory,
    File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTreeEntryV1 {
    pub(crate) path: String,
    pub(crate) kind: NormalizedTreeEntryKindV1,
    pub(crate) mode: u32,
    pub(crate) size: u64,
    pub(crate) sha256: Option<Sha256>,
}

impl NormalizedTreeEntryV1 {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub const fn kind(&self) -> NormalizedTreeEntryKindV1 {
        self.kind
    }
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
    #[must_use]
    pub const fn sha256(&self) -> Option<Sha256> {
        self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPackageObjectV1 {
    package: PackageKeyV1,
    candidate_identity: Sha256,
    source_tree_sha256: Sha256,
    store_object_sha256: Sha256,
    object_path: PathBuf,
    tree_path: PathBuf,
    entries: Vec<NormalizedTreeEntryV1>,
    download: Option<VerifiedDownloadBlobV1>,
    publication: LeanStorePublicationV1,
}

impl VerifiedPackageObjectV1 {
    #[must_use]
    pub fn package(&self) -> &PackageKeyV1 {
        &self.package
    }
    #[must_use]
    pub const fn candidate_identity(&self) -> Sha256 {
        self.candidate_identity
    }
    #[must_use]
    pub const fn source_tree_sha256(&self) -> Sha256 {
        self.source_tree_sha256
    }
    #[must_use]
    pub const fn store_object_sha256(&self) -> Sha256 {
        self.store_object_sha256
    }
    #[must_use]
    pub fn object_path(&self) -> &Path {
        &self.object_path
    }
    #[must_use]
    pub fn tree_path(&self) -> &Path {
        &self.tree_path
    }
    #[must_use]
    pub fn entries(&self) -> &[NormalizedTreeEntryV1] {
        &self.entries
    }
    #[must_use]
    pub const fn download(&self) -> Option<&VerifiedDownloadBlobV1> {
        self.download.as_ref()
    }
    #[must_use]
    pub const fn publication(&self) -> LeanStorePublicationV1 {
        self.publication
    }
    pub(crate) fn with_publication(mut self, publication: LeanStorePublicationV1) -> Self {
        self.publication = publication;
        self
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        package: PackageKeyV1,
        candidate_identity: Sha256,
        source_tree_sha256: Sha256,
        store_object_sha256: Sha256,
        object_path: PathBuf,
        tree_path: PathBuf,
        entries: Vec<NormalizedTreeEntryV1>,
        download: Option<VerifiedDownloadBlobV1>,
        publication: LeanStorePublicationV1,
    ) -> Self {
        Self {
            package,
            candidate_identity,
            source_tree_sha256,
            store_object_sha256,
            object_path,
            tree_path,
            entries,
            download,
            publication,
        }
    }
}

fn request_identity(
    graph: Sha256,
    package: &PackageKeyV1,
    candidate: Sha256,
    source: &LeanFetchSourceV1,
    allowed_root: &Path,
    limits: LeanStoreLimitsV1,
) -> Result<Sha256, LeanStoreError> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-fetch-request-v1\0");
    hasher.update(graph.as_bytes());
    hash_string(&mut hasher, package.scope());
    hash_string(&mut hasher, package.name());
    hasher.update(candidate.as_bytes());
    let root = allowed_root.to_str().ok_or_else(|| {
        LeanStoreError::new(
            LeanStoreErrorKind::InvalidField,
            "allowed source root must be UTF-8",
        )
    })?;
    hash_string(&mut hasher, root);
    match source {
        LeanFetchSourceV1::LocalArchive { path } => {
            hasher.update(&[1]);
            hash_path(&mut hasher, path)?;
        }
        LeanFetchSourceV1::LoopbackHttp { url } => {
            hasher.update(&[2]);
            if url.is_empty()
                || url.len() > 4_096
                || url.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::InvalidField,
                    "loopback URL is invalid",
                ));
            }
            hash_string(&mut hasher, url);
        }
        LeanFetchSourceV1::LocalGit { repository } => {
            hasher.update(&[3]);
            hash_path(&mut hasher, repository)?;
        }
        LeanFetchSourceV1::LocalDirectory { path } => {
            hasher.update(&[4]);
            hash_path(&mut hasher, path)?;
        }
    }
    for value in [
        limits.maximum_download_bytes,
        limits.maximum_expanded_bytes,
        limits.maximum_file_bytes,
        limits.maximum_entries as u64,
        u64::from(limits.maximum_retries),
    ] {
        hasher.update(&value.to_be_bytes());
    }
    Ok(hasher.finalize())
}

fn hash_path(hasher: &mut Sha256Hasher, path: &Path) -> Result<(), LeanStoreError> {
    let value = path.to_str().ok_or_else(|| {
        LeanStoreError::new(
            LeanStoreErrorKind::InvalidField,
            "source path must be UTF-8",
        )
    })?;
    if value.is_empty() || value.len() > 4_096 || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::InvalidField,
            "source path is invalid",
        ));
    }
    hash_string(hasher, value);
    Ok(())
}

fn hash_string(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

pub(crate) fn sha256(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

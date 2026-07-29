use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use std::collections::BTreeMap;

use crate::{CanonicalSourceUrlV1, LeanBunLockV1, PackageKeyV1, ResolvedPackageSourceV1};

pub const MAX_RESERVOIR_BINDINGS_V1: usize = 4_096;
const MAX_VERSION_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservoirBindingV1ErrorKind {
    InvalidField,
    LimitExceeded,
    DuplicatePackage,
    MissingPackage,
    IncompatibleLock,
    NonCanonicalText,
    DigestMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservoirBindingV1Error {
    pub kind: ReservoirBindingV1ErrorKind,
    pub message: String,
}

impl ReservoirBindingV1Error {
    fn new(kind: ReservoirBindingV1ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for ReservoirBindingV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReservoirBindingV1Error {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReservoirRegistryIdentityV1(Sha256);

impl ReservoirRegistryIdentityV1 {
    #[must_use]
    pub const fn new(identity: Sha256) -> Self {
        Self(identity)
    }

    #[must_use]
    pub const fn sha256(self) -> Sha256 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservoirBindingV1 {
    registry: ReservoirRegistryIdentityV1,
    package: PackageKeyV1,
    requested_version: String,
    metadata_sha256: Sha256,
    resolved_url: CanonicalSourceUrlV1,
    exact_commit: String,
    download_integrity: Sha256,
    source_tree_sha256: Sha256,
    selected_source_identity: Sha256,
    identity: Sha256,
}

impl ReservoirBindingV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: ReservoirRegistryIdentityV1,
        package: PackageKeyV1,
        requested_version: impl Into<String>,
        metadata_sha256: Sha256,
        resolved_url: CanonicalSourceUrlV1,
        exact_commit: impl Into<String>,
        download_integrity: Sha256,
        source_tree_sha256: Sha256,
        selected_source_identity: Sha256,
    ) -> Result<Self, ReservoirBindingV1Error> {
        let requested_version = requested_version.into();
        validate_text(
            &requested_version,
            MAX_VERSION_BYTES,
            "requested Reservoir version",
        )?;
        let exact_commit = exact_commit.into();
        validate_commit(&exact_commit)?;
        let identity = binding_identity(
            registry,
            &package,
            &requested_version,
            metadata_sha256,
            &resolved_url,
            &exact_commit,
            download_integrity,
            source_tree_sha256,
            selected_source_identity,
        );
        Ok(Self {
            registry,
            package,
            requested_version,
            metadata_sha256,
            resolved_url,
            exact_commit,
            download_integrity,
            source_tree_sha256,
            selected_source_identity,
            identity,
        })
    }

    #[must_use]
    pub const fn registry(&self) -> ReservoirRegistryIdentityV1 {
        self.registry
    }
    #[must_use]
    pub fn package(&self) -> &PackageKeyV1 {
        &self.package
    }
    #[must_use]
    pub fn requested_version(&self) -> &str {
        &self.requested_version
    }
    #[must_use]
    pub const fn metadata_sha256(&self) -> Sha256 {
        self.metadata_sha256
    }
    #[must_use]
    pub fn resolved_url(&self) -> &CanonicalSourceUrlV1 {
        &self.resolved_url
    }
    #[must_use]
    pub fn exact_commit(&self) -> &str {
        &self.exact_commit
    }
    #[must_use]
    pub const fn download_integrity(&self) -> Sha256 {
        self.download_integrity
    }
    #[must_use]
    pub const fn source_tree_sha256(&self) -> Sha256 {
        self.source_tree_sha256
    }
    #[must_use]
    pub const fn selected_source_identity(&self) -> Sha256 {
        self.selected_source_identity
    }
    #[must_use]
    pub const fn identity(&self) -> Sha256 {
        self.identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservoirBindingDocumentV1 {
    lock_v1_identity: Sha256,
    bindings: Vec<ReservoirBindingV1>,
    identity: Sha256,
}

impl ReservoirBindingDocumentV1 {
    pub fn new(
        lock: &LeanBunLockV1,
        mut bindings: Vec<ReservoirBindingV1>,
    ) -> Result<Self, ReservoirBindingV1Error> {
        if bindings.is_empty() || bindings.len() > MAX_RESERVOIR_BINDINGS_V1 {
            return Err(ReservoirBindingV1Error::new(
                ReservoirBindingV1ErrorKind::LimitExceeded,
                "Reservoir binding document must contain a bounded non-empty binding set",
            ));
        }
        bindings.sort_by(|left, right| left.package.cmp(&right.package));
        if bindings
            .windows(2)
            .any(|pair| pair[0].package == pair[1].package)
        {
            return Err(ReservoirBindingV1Error::new(
                ReservoirBindingV1ErrorKind::DuplicatePackage,
                "duplicate Reservoir binding package",
            ));
        }
        let locked = lock
            .packages()
            .iter()
            .map(|package| (package.key(), package))
            .collect::<BTreeMap<_, _>>();
        for binding in &bindings {
            let package = locked.get(binding.package()).ok_or_else(|| {
                ReservoirBindingV1Error::new(
                    ReservoirBindingV1ErrorKind::MissingPackage,
                    "Reservoir binding package is absent from the accompanied V1 lock",
                )
            })?;
            let ResolvedPackageSourceV1::Git {
                url,
                exact_revision,
                ..
            } = package.resolved_source()
            else {
                return Err(ReservoirBindingV1Error::new(
                    ReservoirBindingV1ErrorKind::IncompatibleLock,
                    "Reservoir binding requires a locked exact Git source",
                ));
            };
            if url != binding.resolved_url()
                || exact_revision != binding.exact_commit()
                || package.download_integrity() != Some(binding.download_integrity())
                || package.source_tree_sha256() != binding.source_tree_sha256()
                || package.selected_source_identity() != binding.selected_source_identity()
            {
                return Err(ReservoirBindingV1Error::new(
                    ReservoirBindingV1ErrorKind::IncompatibleLock,
                    "Reservoir binding exact content facts differ from the accompanied V1 lock",
                ));
            }
        }
        let lock_v1_identity = lock.identity();
        let identity = document_identity(lock_v1_identity, &bindings);
        Ok(Self {
            lock_v1_identity,
            bindings,
            identity,
        })
    }

    #[must_use]
    pub const fn lock_v1_identity(&self) -> Sha256 {
        self.lock_v1_identity
    }
    #[must_use]
    pub fn bindings(&self) -> &[ReservoirBindingV1] {
        &self.bindings
    }
    #[must_use]
    pub const fn identity(&self) -> Sha256 {
        self.identity
    }

    #[must_use]
    pub fn to_canonical_text(&self) -> String {
        let mut output = String::from("leanbun-reservoir-bindings-v1\t1\n");
        line(
            &mut output,
            "lock-v1-identity",
            &[&self.lock_v1_identity.to_string()],
        );
        output.push_str(&format!("binding-count\t{}\n", self.bindings.len()));
        for binding in &self.bindings {
            line(
                &mut output,
                "binding",
                &[
                    &hex(binding.package.scope().as_bytes()),
                    &hex(binding.package.name().as_bytes()),
                ],
            );
            line(
                &mut output,
                "registry-identity",
                &[&binding.registry.sha256().to_string()],
            );
            line(
                &mut output,
                "requested-version",
                &[&hex(binding.requested_version.as_bytes())],
            );
            line(
                &mut output,
                "metadata-sha256",
                &[&binding.metadata_sha256.to_string()],
            );
            line(
                &mut output,
                "resolved-url",
                &[&hex(binding.resolved_url.as_str().as_bytes())],
            );
            line(&mut output, "exact-commit", &[&binding.exact_commit]);
            line(
                &mut output,
                "download-integrity",
                &[&binding.download_integrity.to_string()],
            );
            line(
                &mut output,
                "source-tree-sha256",
                &[&binding.source_tree_sha256.to_string()],
            );
            line(
                &mut output,
                "selected-source-identity",
                &[&binding.selected_source_identity.to_string()],
            );
            line(
                &mut output,
                "binding-identity",
                &[&binding.identity.to_string()],
            );
            output.push_str("end-binding\n");
        }
        line(
            &mut output,
            "document-identity",
            &[&self.identity.to_string()],
        );
        output.push_str("end-reservoir-bindings\n");
        output
    }

    pub fn from_canonical_text(
        text: &str,
        lock: &LeanBunLockV1,
    ) -> Result<Self, ReservoirBindingV1Error> {
        let parsed = parse_document(text, lock)?;
        if parsed.to_canonical_text() != text {
            return Err(ReservoirBindingV1Error::new(
                ReservoirBindingV1ErrorKind::NonCanonicalText,
                "Reservoir binding text is valid but not canonical",
            ));
        }
        Ok(parsed)
    }
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), ReservoirBindingV1Error> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(char::is_control)
        || value.contains('\0')
    {
        return Err(ReservoirBindingV1Error::new(
            ReservoirBindingV1ErrorKind::InvalidField,
            format!("{label} is empty, oversized or contains control characters"),
        ));
    }
    Ok(())
}

fn validate_commit(value: &str) -> Result<(), ReservoirBindingV1Error> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ReservoirBindingV1Error::new(
            ReservoirBindingV1ErrorKind::InvalidField,
            "Reservoir exact commit must be lowercase 40-hex Git identity",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn binding_identity(
    registry: ReservoirRegistryIdentityV1,
    package: &PackageKeyV1,
    requested_version: &str,
    metadata_sha256: Sha256,
    resolved_url: &CanonicalSourceUrlV1,
    exact_commit: &str,
    download_integrity: Sha256,
    source_tree_sha256: Sha256,
    selected_source_identity: Sha256,
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-reservoir-binding-v1\0");
    hasher.update(registry.sha256().as_bytes());
    hash_string(&mut hasher, package.scope());
    hash_string(&mut hasher, package.name());
    hash_string(&mut hasher, requested_version);
    hasher.update(metadata_sha256.as_bytes());
    hash_string(&mut hasher, resolved_url.as_str());
    hash_string(&mut hasher, exact_commit);
    hasher.update(download_integrity.as_bytes());
    hasher.update(source_tree_sha256.as_bytes());
    hasher.update(selected_source_identity.as_bytes());
    hasher.finalize()
}

fn document_identity(lock_v1_identity: Sha256, bindings: &[ReservoirBindingV1]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-reservoir-binding-document-v1\0");
    hasher.update(lock_v1_identity.as_bytes());
    hash_usize(&mut hasher, bindings.len());
    for binding in bindings {
        hasher.update(binding.identity.as_bytes());
    }
    hasher.finalize()
}

fn hash_string(hasher: &mut Sha256Hasher, value: &str) {
    hash_usize(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn hash_usize(hasher: &mut Sha256Hasher, value: usize) {
    hasher.update(&u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

fn line(output: &mut String, label: &str, fields: &[&str]) {
    output.push_str(label);
    for field in fields {
        output.push('\t');
        output.push_str(field);
    }
    output.push('\n');
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn unhex(value: &str) -> Result<String, ReservoirBindingV1Error> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(noncanonical("invalid canonical hex text"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        bytes.push((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?);
    }
    String::from_utf8(bytes).map_err(|_| noncanonical("canonical text is not UTF-8"))
}

fn hex_digit(value: u8) -> Result<u8, ReservoirBindingV1Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(noncanonical("invalid canonical hex digit")),
    }
}

struct Cursor<'a> {
    lines: Vec<&'a str>,
    position: usize,
}

impl<'a> Cursor<'a> {
    fn expect(
        &mut self,
        label: &str,
        field_count: usize,
    ) -> Result<Vec<&'a str>, ReservoirBindingV1Error> {
        let raw = self
            .lines
            .get(self.position)
            .ok_or_else(|| noncanonical(format!("missing {label} line")))?;
        self.position += 1;
        let fields = raw.split('\t').collect::<Vec<_>>();
        if fields.first().copied() != Some(label) || fields.len() != field_count + 1 {
            return Err(noncanonical(format!("invalid {label} line")));
        }
        Ok(fields[1..].to_vec())
    }
}

fn parse_document(
    text: &str,
    lock: &LeanBunLockV1,
) -> Result<ReservoirBindingDocumentV1, ReservoirBindingV1Error> {
    let mut cursor = Cursor {
        lines: text.lines().collect(),
        position: 0,
    };
    if cursor.expect("leanbun-reservoir-bindings-v1", 1)? != ["1"] {
        return Err(noncanonical("unsupported Reservoir binding schema"));
    }
    let lock_identity = parse_sha(cursor.expect("lock-v1-identity", 1)?[0])?;
    if lock_identity != lock.identity() {
        return Err(ReservoirBindingV1Error::new(
            ReservoirBindingV1ErrorKind::IncompatibleLock,
            "Reservoir binding document names another V1 lock identity",
        ));
    }
    let binding_count = parse_usize(cursor.expect("binding-count", 1)?[0])?;
    if binding_count == 0 || binding_count > MAX_RESERVOIR_BINDINGS_V1 {
        return Err(ReservoirBindingV1Error::new(
            ReservoirBindingV1ErrorKind::LimitExceeded,
            "Reservoir binding count is outside the supported range",
        ));
    }
    let mut bindings = Vec::with_capacity(binding_count);
    for _ in 0..binding_count {
        let key = cursor.expect("binding", 2)?;
        let package = PackageKeyV1::new(unhex(key[0])?, unhex(key[1])?)
            .map_err(|error| noncanonical(error.to_string()))?;
        let registry =
            ReservoirRegistryIdentityV1::new(parse_sha(cursor.expect("registry-identity", 1)?[0])?);
        let requested_version = unhex(cursor.expect("requested-version", 1)?[0])?;
        let metadata_sha256 = parse_sha(cursor.expect("metadata-sha256", 1)?[0])?;
        let resolved_url =
            CanonicalSourceUrlV1::parse(unhex(cursor.expect("resolved-url", 1)?[0])?)
                .map_err(|error| noncanonical(error.to_string()))?;
        let exact_commit = cursor.expect("exact-commit", 1)?[0].to_owned();
        let download_integrity = parse_sha(cursor.expect("download-integrity", 1)?[0])?;
        let source_tree_sha256 = parse_sha(cursor.expect("source-tree-sha256", 1)?[0])?;
        let selected_source_identity = parse_sha(cursor.expect("selected-source-identity", 1)?[0])?;
        let expected_identity = parse_sha(cursor.expect("binding-identity", 1)?[0])?;
        cursor.expect("end-binding", 0)?;
        let binding = ReservoirBindingV1::new(
            registry,
            package,
            requested_version,
            metadata_sha256,
            resolved_url,
            exact_commit,
            download_integrity,
            source_tree_sha256,
            selected_source_identity,
        )?;
        if binding.identity() != expected_identity {
            return Err(ReservoirBindingV1Error::new(
                ReservoirBindingV1ErrorKind::DigestMismatch,
                "Reservoir binding identity does not match its fields",
            ));
        }
        bindings.push(binding);
    }
    let expected_document = parse_sha(cursor.expect("document-identity", 1)?[0])?;
    cursor.expect("end-reservoir-bindings", 0)?;
    if cursor.position != cursor.lines.len() {
        return Err(noncanonical("trailing Reservoir binding content"));
    }
    let document = ReservoirBindingDocumentV1::new(lock, bindings)?;
    if document.identity() != expected_document {
        return Err(ReservoirBindingV1Error::new(
            ReservoirBindingV1ErrorKind::DigestMismatch,
            "Reservoir binding document identity does not match its fields",
        ));
    }
    Ok(document)
}

fn parse_sha(value: &str) -> Result<Sha256, ReservoirBindingV1Error> {
    Sha256::parse(value).map_err(|_| noncanonical("invalid SHA-256"))
}

fn parse_usize(value: &str) -> Result<usize, ReservoirBindingV1Error> {
    if value.is_empty()
        || (value.starts_with('0') && value != "0")
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(noncanonical("invalid canonical count"));
    }
    value
        .parse()
        .map_err(|_| noncanonical("canonical count exceeds usize"))
}

fn noncanonical(message: impl Into<String>) -> ReservoirBindingV1Error {
    ReservoirBindingV1Error::new(ReservoirBindingV1ErrorKind::NonCanonicalText, message)
}

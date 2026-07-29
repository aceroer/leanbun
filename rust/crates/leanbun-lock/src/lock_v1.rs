use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_LOCK_PACKAGES_V1: usize = 4_096;
pub const MAX_PACKAGE_DEPENDENCIES_V1: usize = 4_096;
pub const MAX_GRAPH_DEPTH_V1: usize = 128;
pub const MAX_PATH_PROVENANCE_ENTRIES_V1: usize = MAX_LOCK_PACKAGES_V1 * 3;
const MAX_NAME_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_SUBDIR_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeanBunLockV1ErrorKind {
    InvalidField,
    LimitExceeded,
    DuplicatePackage,
    DuplicateDependency,
    MissingPackage,
    ExtraPackage,
    DependencyCycle,
    GraphTooDeep,
    AbsolutePortablePath,
    DuplicateProvenance,
    IncompatibleProvenance,
    AmbiguousSelection,
    MissingDecision,
    DuplicateDecision,
    PathOutsideGenerationRoot,
    NonCanonicalText,
    DigestMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanBunLockV1Error {
    pub kind: LeanBunLockV1ErrorKind,
    pub message: String,
}

impl LeanBunLockV1Error {
    fn new(kind: LeanBunLockV1ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for LeanBunLockV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LeanBunLockV1Error {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageKeyV1 {
    scope: String,
    name: String,
}

impl PackageKeyV1 {
    pub fn new(
        scope: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, LeanBunLockV1Error> {
        let scope = scope.into();
        let name = name.into();
        validate_atom(&scope, MAX_NAME_BYTES, true, "package scope")?;
        validate_atom(&name, MAX_NAME_BYTES, false, "package name")?;
        Ok(Self { scope, name })
    }

    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalSourceUrlV1(String);

impl CanonicalSourceUrlV1 {
    pub fn parse(value: impl Into<String>) -> Result<Self, LeanBunLockV1Error> {
        let mut value = value.into();
        validate_atom(&value, MAX_TEXT_BYTES, false, "source URL")?;
        let Some(remainder) = value.strip_prefix("https://") else {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::InvalidField,
                "source URL must use canonical HTTPS",
            ));
        };
        let Some((host, path)) = remainder.split_once('/') else {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::InvalidField,
                "source URL must contain a host and repository path",
            ));
        };
        if host.is_empty()
            || !host.is_ascii()
            || host.bytes().any(|byte| {
                !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-'))
            })
            || host
                .split('.')
                .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
            || path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            || value.contains('#')
            || value.contains('?')
            || value.contains('%')
            || value.contains('\\')
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::InvalidField,
                "source URL must be normalized HTTPS with a lowercase ASCII host and direct path segments",
            ));
        }
        if value.ends_with(".git") {
            value.truncate(value.len() - 4);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestedPackageSourceV1 {
    Git {
        url: CanonicalSourceUrlV1,
        requested_revision: Option<String>,
    },
    PathSnapshot {
        portable_path_token: String,
    },
}

impl RequestedPackageSourceV1 {
    pub fn git(
        url: CanonicalSourceUrlV1,
        requested_revision: Option<String>,
    ) -> Result<Self, LeanBunLockV1Error> {
        if let Some(value) = requested_revision.as_deref() {
            validate_atom(value, MAX_TEXT_BYTES, false, "requested revision")?;
        }
        Ok(Self::Git {
            url,
            requested_revision,
        })
    }

    pub fn path_snapshot(token: impl Into<String>) -> Result<Self, LeanBunLockV1Error> {
        let portable_path_token = token.into();
        validate_portable_path(&portable_path_token)?;
        Ok(Self::PathSnapshot {
            portable_path_token,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResolvedPackageSourceV1 {
    Git {
        url: CanonicalSourceUrlV1,
        exact_revision: String,
        subdir: Option<String>,
    },
    PathSnapshot {
        portable_path_token: String,
    },
}

impl ResolvedPackageSourceV1 {
    pub fn git(
        url: CanonicalSourceUrlV1,
        exact_revision: impl Into<String>,
        subdir: Option<String>,
    ) -> Result<Self, LeanBunLockV1Error> {
        let exact_revision = exact_revision.into();
        validate_git_revision(&exact_revision)?;
        if let Some(value) = subdir.as_deref() {
            validate_relative_path(value, MAX_SUBDIR_BYTES, "Git subdir")?;
        }
        Ok(Self::Git {
            url,
            exact_revision,
            subdir,
        })
    }

    pub fn path_snapshot(token: impl Into<String>) -> Result<Self, LeanBunLockV1Error> {
        let portable_path_token = token.into();
        validate_portable_path(&portable_path_token)?;
        Ok(Self::PathSnapshot {
            portable_path_token,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageDependencyV1(PackageKeyV1);

impl PackageDependencyV1 {
    #[must_use]
    pub fn new(package: PackageKeyV1) -> Self {
        Self(package)
    }

    #[must_use]
    pub fn package(&self) -> &PackageKeyV1 {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackagePathProvenanceKindV1 {
    Manifest,
    WorkspaceOverride,
    RuntimeOverride,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagePathProvenanceV1 {
    package: PackageKeyV1,
    kind: PackagePathProvenanceKindV1,
    source_identity: Sha256,
    bun_generated: bool,
}

impl PackagePathProvenanceV1 {
    #[must_use]
    pub fn manifest(package: PackageKeyV1, source_identity: Sha256) -> Self {
        Self {
            package,
            kind: PackagePathProvenanceKindV1::Manifest,
            source_identity,
            bun_generated: false,
        }
    }

    #[must_use]
    pub fn workspace_override(package: PackageKeyV1, source_identity: Sha256) -> Self {
        Self {
            package,
            kind: PackagePathProvenanceKindV1::WorkspaceOverride,
            source_identity,
            bun_generated: false,
        }
    }

    #[must_use]
    pub fn bun_generated_runtime(package: PackageKeyV1, source_identity: Sha256) -> Self {
        Self {
            package,
            kind: PackagePathProvenanceKindV1::RuntimeOverride,
            source_identity,
            bun_generated: true,
        }
    }

    #[must_use]
    pub fn package(&self) -> &PackageKeyV1 {
        &self.package
    }
    #[must_use]
    pub const fn kind(&self) -> PackagePathProvenanceKindV1 {
        self.kind
    }
    #[must_use]
    pub const fn source_identity(&self) -> Sha256 {
        self.source_identity
    }
    #[must_use]
    pub const fn is_bun_generated(&self) -> bool {
        self.bun_generated
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagePathProvenanceSetV1 {
    entries: Vec<PackagePathProvenanceV1>,
    digest: Sha256,
}

impl PackagePathProvenanceSetV1 {
    pub fn new(mut entries: Vec<PackagePathProvenanceV1>) -> Result<Self, LeanBunLockV1Error> {
        if entries.len() > MAX_PATH_PROVENANCE_ENTRIES_V1 {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::LimitExceeded,
                "path provenance count exceeds limit",
            ));
        }
        entries
            .sort_by(|left, right| (&left.package, left.kind).cmp(&(&right.package, right.kind)));
        for pair in entries.windows(2) {
            if pair[0].package == pair[1].package && pair[0].kind == pair[1].kind {
                return Err(LeanBunLockV1Error::new(
                    LeanBunLockV1ErrorKind::DuplicateProvenance,
                    "a package has duplicate provenance in one layer",
                ));
            }
        }
        if entries.iter().any(|entry| {
            entry.kind == PackagePathProvenanceKindV1::RuntimeOverride && !entry.bun_generated
        }) {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::IncompatibleProvenance,
                "runtime provenance must be Bun-generated",
            ));
        }
        let digest = hash_provenance_entries(&entries);
        Ok(Self { entries, digest })
    }

    #[must_use]
    pub fn entries(&self) -> &[PackagePathProvenanceV1] {
        &self.entries
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256 {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedLeanPackageV1 {
    key: PackageKeyV1,
    requested: RequestedPackageSourceV1,
    resolved: ResolvedPackageSourceV1,
    download_integrity: Option<Sha256>,
    source_tree_sha256: Sha256,
    config_sha256: Sha256,
    manifest_sha256: Option<Sha256>,
    dependencies: Vec<PackageDependencyV1>,
    provenance_digests: Vec<Sha256>,
    selected_source_identity: Sha256,
}

impl LockedLeanPackageV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: PackageKeyV1,
        requested: RequestedPackageSourceV1,
        resolved: ResolvedPackageSourceV1,
        download_integrity: Option<Sha256>,
        source_tree_sha256: Sha256,
        config_sha256: Sha256,
        manifest_sha256: Option<Sha256>,
        mut dependencies: Vec<PackageDependencyV1>,
        mut provenance_digests: Vec<Sha256>,
        selected_source_identity: Sha256,
    ) -> Result<Self, LeanBunLockV1Error> {
        if dependencies.len() > MAX_PACKAGE_DEPENDENCIES_V1
            || provenance_digests.len() > MAX_PACKAGE_DEPENDENCIES_V1
        {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::LimitExceeded,
                "package dependency or provenance count exceeds limit",
            ));
        }
        if matches!(resolved, ResolvedPackageSourceV1::Git { .. }) && download_integrity.is_none() {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::InvalidField,
                "resolved Git source requires download integrity",
            ));
        }
        match (&requested, &resolved) {
            (
                RequestedPackageSourceV1::Git { url: requested, .. },
                ResolvedPackageSourceV1::Git { url: resolved, .. },
            ) if requested == resolved => {}
            (
                RequestedPackageSourceV1::PathSnapshot {
                    portable_path_token: requested,
                },
                ResolvedPackageSourceV1::PathSnapshot {
                    portable_path_token: resolved,
                },
            ) if requested == resolved => {}
            _ => {
                return Err(LeanBunLockV1Error::new(
                    LeanBunLockV1ErrorKind::IncompatibleProvenance,
                    "requested and resolved package sources are incompatible",
                ));
            }
        }
        dependencies.sort();
        if dependencies.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::DuplicateDependency,
                "duplicate dependency edge",
            ));
        }
        if dependencies
            .iter()
            .any(|dependency| dependency.package() == &key)
        {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::DependencyCycle,
                "self dependency is forbidden",
            ));
        }
        provenance_digests.sort();
        if provenance_digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::DuplicateProvenance,
                "duplicate package provenance digest",
            ));
        }
        if provenance_digests.is_empty() {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::InvalidField,
                "package requires provenance evidence",
            ));
        }
        Ok(Self {
            key,
            requested,
            resolved,
            download_integrity,
            source_tree_sha256,
            config_sha256,
            manifest_sha256,
            dependencies,
            provenance_digests,
            selected_source_identity,
        })
    }

    #[must_use]
    pub fn key(&self) -> &PackageKeyV1 {
        &self.key
    }
    #[must_use]
    pub fn dependencies(&self) -> &[PackageDependencyV1] {
        &self.dependencies
    }
    #[must_use]
    pub const fn requested_source(&self) -> &RequestedPackageSourceV1 {
        &self.requested
    }
    #[must_use]
    pub const fn resolved_source(&self) -> &ResolvedPackageSourceV1 {
        &self.resolved
    }
    #[must_use]
    pub const fn download_integrity(&self) -> Option<Sha256> {
        self.download_integrity
    }
    #[must_use]
    pub const fn source_tree_sha256(&self) -> Sha256 {
        self.source_tree_sha256
    }
    #[must_use]
    pub const fn config_sha256(&self) -> Sha256 {
        self.config_sha256
    }
    #[must_use]
    pub const fn manifest_sha256(&self) -> Option<Sha256> {
        self.manifest_sha256
    }
    #[must_use]
    pub fn provenance_digests(&self) -> &[Sha256] {
        &self.provenance_digests
    }
    #[must_use]
    pub const fn selected_source_identity(&self) -> Sha256 {
        self.selected_source_identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanBunLockV1 {
    lean_toolchain: String,
    lean_compiler_githash: String,
    lake_version: String,
    root_config_sha256: Sha256,
    root_declaration_sha256: Sha256,
    packages: Vec<LockedLeanPackageV1>,
    graph_sha256: Sha256,
}

impl LeanBunLockV1 {
    pub fn new(
        lean_toolchain: impl Into<String>,
        lean_compiler_githash: impl Into<String>,
        lake_version: impl Into<String>,
        root_config_sha256: Sha256,
        root_declaration_sha256: Sha256,
        mut packages: Vec<LockedLeanPackageV1>,
    ) -> Result<Self, LeanBunLockV1Error> {
        let lean_toolchain = lean_toolchain.into();
        let lean_compiler_githash = lean_compiler_githash.into();
        let lake_version = lake_version.into();
        validate_atom(&lean_toolchain, MAX_TEXT_BYTES, false, "Lean toolchain")?;
        validate_git_revision(&lean_compiler_githash)?;
        validate_atom(&lake_version, MAX_NAME_BYTES, false, "Lake version")?;
        if packages.len() > MAX_LOCK_PACKAGES_V1 {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::LimitExceeded,
                "lock package count exceeds limit",
            ));
        }
        packages.sort_by(|left, right| left.key.cmp(&right.key));
        if packages.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::DuplicatePackage,
                "duplicate package key",
            ));
        }
        validate_graph(&packages)?;
        let graph_sha256 = hash_graph(&packages);
        Ok(Self {
            lean_toolchain,
            lean_compiler_githash,
            lake_version,
            root_config_sha256,
            root_declaration_sha256,
            packages,
            graph_sha256,
        })
    }

    #[must_use]
    pub fn packages(&self) -> &[LockedLeanPackageV1] {
        &self.packages
    }
    #[must_use]
    pub fn lean_toolchain(&self) -> &str {
        &self.lean_toolchain
    }
    #[must_use]
    pub fn lean_compiler_githash(&self) -> &str {
        &self.lean_compiler_githash
    }
    #[must_use]
    pub fn lake_version(&self) -> &str {
        &self.lake_version
    }
    #[must_use]
    pub const fn root_config_sha256(&self) -> Sha256 {
        self.root_config_sha256
    }
    #[must_use]
    pub const fn root_declaration_sha256(&self) -> Sha256 {
        self.root_declaration_sha256
    }
    #[must_use]
    pub const fn graph_sha256(&self) -> Sha256 {
        self.graph_sha256
    }

    #[must_use]
    pub fn identity(&self) -> Sha256 {
        hash_bytes(
            b"leanbun-lock-identity-v1\0",
            self.to_canonical_text().as_bytes(),
        )
    }

    #[must_use]
    pub fn to_canonical_text(&self) -> String {
        let mut output = String::from("leanbun-lock-v1\t1\n");
        line(
            &mut output,
            "lean-toolchain",
            &[&hex(self.lean_toolchain.as_bytes())],
        );
        line(
            &mut output,
            "lean-compiler-githash",
            &[&hex(self.lean_compiler_githash.as_bytes())],
        );
        line(
            &mut output,
            "lake-version",
            &[&hex(self.lake_version.as_bytes())],
        );
        line(
            &mut output,
            "root-config-sha256",
            &[&self.root_config_sha256.to_string()],
        );
        line(
            &mut output,
            "root-declaration-sha256",
            &[&self.root_declaration_sha256.to_string()],
        );
        output.push_str(&format!("package-count\t{}\n", self.packages.len()));
        for package in &self.packages {
            output.push_str("package\t");
            output.push_str(&hex(package.key.scope.as_bytes()));
            output.push('\t');
            output.push_str(&hex(package.key.name.as_bytes()));
            output.push('\n');
            encode_requested(&mut output, &package.requested);
            encode_resolved(&mut output, &package.resolved);
            line_optional_sha(
                &mut output,
                "download-integrity",
                package.download_integrity,
            );
            line(
                &mut output,
                "source-tree-sha256",
                &[&package.source_tree_sha256.to_string()],
            );
            line(
                &mut output,
                "config-sha256",
                &[&package.config_sha256.to_string()],
            );
            line_optional_sha(&mut output, "manifest-sha256", package.manifest_sha256);
            line(
                &mut output,
                "selected-source-identity",
                &[&package.selected_source_identity.to_string()],
            );
            output.push_str(&format!(
                "dependency-count\t{}\n",
                package.dependencies.len()
            ));
            for dependency in &package.dependencies {
                output.push_str("dependency\t");
                output.push_str(&hex(dependency.0.scope.as_bytes()));
                output.push('\t');
                output.push_str(&hex(dependency.0.name.as_bytes()));
                output.push('\n');
            }
            output.push_str(&format!(
                "provenance-count\t{}\n",
                package.provenance_digests.len()
            ));
            for digest in &package.provenance_digests {
                line(&mut output, "provenance", &[&digest.to_string()]);
            }
            output.push_str("end-package\n");
        }
        line(
            &mut output,
            "graph-sha256",
            &[&self.graph_sha256.to_string()],
        );
        output.push_str("end-lock\n");
        output
    }

    pub fn from_canonical_text(text: &str) -> Result<Self, LeanBunLockV1Error> {
        let parsed = parse_lock(text)?;
        if parsed.to_canonical_text() != text {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::NonCanonicalText,
                "lock text is valid but not canonical",
            ));
        }
        Ok(parsed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagePathDecisionV1 {
    package: PackageKeyV1,
    provenance_set_sha256: Sha256,
    selected_source_identity: Sha256,
    final_path: String,
    store_object_sha256: Sha256,
    source_tree_sha256: Sha256,
    generation: Sha256,
    decision_sha256: Sha256,
}

impl PackagePathDecisionV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package: PackageKeyV1,
        provenance: &PackagePathProvenanceSetV1,
        selected_source_identity: Sha256,
        generation_root: &str,
        final_path: impl Into<String>,
        store_object_sha256: Sha256,
        source_tree_sha256: Sha256,
        generation: Sha256,
    ) -> Result<Self, LeanBunLockV1Error> {
        let matching = provenance
            .entries
            .iter()
            .filter(|entry| {
                entry.package == package && entry.source_identity == selected_source_identity
            })
            .count();
        if matching == 0 {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::IncompatibleProvenance,
                "selected source identity has no matching provenance",
            ));
        }
        if matching > 1 {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::AmbiguousSelection,
                "selected source identity is ambiguous across provenance layers",
            ));
        }
        let final_path = final_path.into();
        validate_contained_absolute_path(generation_root, &final_path)?;
        let decision_sha256 = hash_decision(
            &package,
            provenance.digest,
            selected_source_identity,
            &final_path,
            store_object_sha256,
            source_tree_sha256,
            generation,
        );
        Ok(Self {
            package,
            provenance_set_sha256: provenance.digest,
            selected_source_identity,
            final_path,
            store_object_sha256,
            source_tree_sha256,
            generation,
            decision_sha256,
        })
    }

    #[must_use]
    pub fn package(&self) -> &PackageKeyV1 {
        &self.package
    }
    #[must_use]
    pub fn final_path(&self) -> &str {
        &self.final_path
    }
    #[must_use]
    pub const fn provenance_set_sha256(&self) -> Sha256 {
        self.provenance_set_sha256
    }
    #[must_use]
    pub const fn selected_source_identity(&self) -> Sha256 {
        self.selected_source_identity
    }
    #[must_use]
    pub const fn store_object_sha256(&self) -> Sha256 {
        self.store_object_sha256
    }
    #[must_use]
    pub const fn source_tree_sha256(&self) -> Sha256 {
        self.source_tree_sha256
    }
    #[must_use]
    pub const fn generation(&self) -> Sha256 {
        self.generation
    }
    #[must_use]
    pub const fn decision_sha256(&self) -> Sha256 {
        self.decision_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagePathDecisionSetV1 {
    decisions: Vec<PackagePathDecisionV1>,
    digest: Sha256,
}

impl PackagePathDecisionSetV1 {
    pub fn new(
        lock: &LeanBunLockV1,
        mut decisions: Vec<PackagePathDecisionV1>,
    ) -> Result<Self, LeanBunLockV1Error> {
        decisions.sort_by(|left, right| left.package.cmp(&right.package));
        if decisions
            .windows(2)
            .any(|pair| pair[0].package == pair[1].package)
        {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::DuplicateDecision,
                "package has more than one final path decision",
            ));
        }
        let locked = lock
            .packages
            .iter()
            .map(|package| &package.key)
            .collect::<BTreeSet<_>>();
        let decided = decisions
            .iter()
            .map(|decision| &decision.package)
            .collect::<BTreeSet<_>>();
        if let Some(package) = locked.difference(&decided).next() {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::MissingDecision,
                format!(
                    "missing final path decision for {}/{}",
                    package.scope, package.name
                ),
            ));
        }
        if let Some(package) = decided.difference(&locked).next() {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::ExtraPackage,
                format!(
                    "decision contains extra package {}/{}",
                    package.scope, package.name
                ),
            ));
        }
        for (package, decision) in lock.packages.iter().zip(&decisions) {
            if package.selected_source_identity != decision.selected_source_identity
                || package.source_tree_sha256 != decision.source_tree_sha256
            {
                return Err(LeanBunLockV1Error::new(
                    LeanBunLockV1ErrorKind::IncompatibleProvenance,
                    "decision does not match locked source identity or tree digest",
                ));
            }
        }
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-path-decision-set-v1\0");
        for decision in &decisions {
            hasher.update(decision.decision_sha256.as_bytes());
        }
        Ok(Self {
            decisions,
            digest: hasher.finalize(),
        })
    }

    #[must_use]
    pub fn decisions(&self) -> &[PackagePathDecisionV1] {
        &self.decisions
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256 {
        self.digest
    }
}

fn validate_atom(
    value: &str,
    maximum: usize,
    allow_empty: bool,
    label: &str,
) -> Result<(), LeanBunLockV1Error> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::InvalidField,
            format!("{label} is empty, too long, or contains control characters"),
        ));
    }
    Ok(())
}

fn validate_git_revision(value: &str) -> Result<(), LeanBunLockV1Error> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::InvalidField,
            "Git revision must be exactly 40 lowercase hexadecimal bytes",
        ));
    }
    Ok(())
}

fn validate_portable_path(value: &str) -> Result<(), LeanBunLockV1Error> {
    if value.starts_with('/') || value.starts_with('\\') || value.as_bytes().get(1) == Some(&b':') {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::AbsolutePortablePath,
            "portable lock path must not be absolute",
        ));
    }
    validate_relative_path(value, MAX_TEXT_BYTES, "portable path token")
}

fn validate_relative_path(
    value: &str,
    maximum: usize,
    label: &str,
) -> Result<(), LeanBunLockV1Error> {
    validate_atom(value, maximum, false, label)?;
    if value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::InvalidField,
            format!("{label} must be a normalized relative slash path"),
        ));
    }
    Ok(())
}

fn validate_contained_absolute_path(root: &str, candidate: &str) -> Result<(), LeanBunLockV1Error> {
    if !valid_normalized_absolute_path(root) || !valid_normalized_absolute_path(candidate) {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::InvalidField,
            "generation root and final path must be normalized absolute paths",
        ));
    }
    let prefix = format!("{root}/");
    if candidate == root || !candidate.starts_with(&prefix) {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::PathOutsideGenerationRoot,
            "final path is outside generation root",
        ));
    }
    Ok(())
}

fn valid_normalized_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && value[1..]
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

fn validate_graph(packages: &[LockedLeanPackageV1]) -> Result<(), LeanBunLockV1Error> {
    let indices = packages
        .iter()
        .enumerate()
        .map(|(index, package)| (&package.key, index))
        .collect::<BTreeMap<_, _>>();
    for package in packages {
        for dependency in &package.dependencies {
            if !indices.contains_key(dependency.package()) {
                return Err(LeanBunLockV1Error::new(
                    LeanBunLockV1ErrorKind::MissingPackage,
                    "dependency edge references a package absent from the lock",
                ));
            }
        }
    }
    let mut states = vec![0_u8; packages.len()];
    let mut depths = vec![0_usize; packages.len()];
    for index in 0..packages.len() {
        let _ = visit_graph(index, packages, &indices, &mut states, &mut depths)?;
    }
    Ok(())
}

fn visit_graph(
    index: usize,
    packages: &[LockedLeanPackageV1],
    indices: &BTreeMap<&PackageKeyV1, usize>,
    states: &mut [u8],
    depths: &mut [usize],
) -> Result<usize, LeanBunLockV1Error> {
    if states[index] == 1 {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::DependencyCycle,
            "dependency graph contains a cycle",
        ));
    }
    if states[index] == 2 {
        return Ok(depths[index]);
    }
    states[index] = 1;
    let mut depth = 1_usize;
    for dependency in &packages[index].dependencies {
        let next = indices.get(dependency.package()).copied().ok_or_else(|| {
            LeanBunLockV1Error::new(LeanBunLockV1ErrorKind::MissingPackage, "dependency missing")
        })?;
        depth = depth.max(1 + visit_graph(next, packages, indices, states, depths)?);
    }
    if depth > MAX_GRAPH_DEPTH_V1 {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::GraphTooDeep,
            "dependency graph exceeds maximum depth",
        ));
    }
    states[index] = 2;
    depths[index] = depth;
    Ok(depth)
}

fn hash_graph(packages: &[LockedLeanPackageV1]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-package-graph-v1\0");
    for package in packages {
        hash_string(&mut hasher, &package.key.scope);
        hash_string(&mut hasher, &package.key.name);
        hash_requested_source(&mut hasher, &package.requested);
        hash_resolved_source(&mut hasher, &package.resolved);
        hash_optional_sha(&mut hasher, package.download_integrity);
        hasher.update(package.source_tree_sha256.as_bytes());
        hasher.update(package.config_sha256.as_bytes());
        hash_optional_sha(&mut hasher, package.manifest_sha256);
        hasher.update(package.selected_source_identity.as_bytes());
        for dependency in &package.dependencies {
            hash_string(&mut hasher, &dependency.0.scope);
            hash_string(&mut hasher, &dependency.0.name);
        }
        for digest in &package.provenance_digests {
            hasher.update(digest.as_bytes());
        }
    }
    hasher.finalize()
}

fn hash_requested_source(hasher: &mut Sha256Hasher, source: &RequestedPackageSourceV1) {
    match source {
        RequestedPackageSourceV1::Git {
            url,
            requested_revision,
        } => {
            hasher.update(&[0]);
            hash_string(hasher, url.as_str());
            hash_optional_string(hasher, requested_revision.as_deref());
        }
        RequestedPackageSourceV1::PathSnapshot {
            portable_path_token,
        } => {
            hasher.update(&[1]);
            hash_string(hasher, portable_path_token);
        }
    }
}

fn hash_resolved_source(hasher: &mut Sha256Hasher, source: &ResolvedPackageSourceV1) {
    match source {
        ResolvedPackageSourceV1::Git {
            url,
            exact_revision,
            subdir,
        } => {
            hasher.update(&[0]);
            hash_string(hasher, url.as_str());
            hash_string(hasher, exact_revision);
            hash_optional_string(hasher, subdir.as_deref());
        }
        ResolvedPackageSourceV1::PathSnapshot {
            portable_path_token,
        } => {
            hasher.update(&[1]);
            hash_string(hasher, portable_path_token);
        }
    }
}

fn hash_optional_string(hasher: &mut Sha256Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hash_string(hasher, value);
        }
        None => hasher.update(&[0]),
    }
}

fn hash_optional_sha(hasher: &mut Sha256Hasher, value: Option<Sha256>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(value.as_bytes());
        }
        None => hasher.update(&[0]),
    }
}

fn hash_provenance_entries(entries: &[PackagePathProvenanceV1]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-path-provenance-set-v1\0");
    for entry in entries {
        hash_string(&mut hasher, &entry.package.scope);
        hash_string(&mut hasher, &entry.package.name);
        hasher.update(&[match entry.kind {
            PackagePathProvenanceKindV1::Manifest => 0,
            PackagePathProvenanceKindV1::WorkspaceOverride => 1,
            PackagePathProvenanceKindV1::RuntimeOverride => 2,
        }]);
        hasher.update(entry.source_identity.as_bytes());
        hasher.update(&[u8::from(entry.bun_generated)]);
    }
    hasher.finalize()
}

#[allow(clippy::too_many_arguments)]
fn hash_decision(
    package: &PackageKeyV1,
    provenance: Sha256,
    selected: Sha256,
    path: &str,
    object: Sha256,
    tree: Sha256,
    generation: Sha256,
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-path-decision-v1\0");
    hash_string(&mut hasher, &package.scope);
    hash_string(&mut hasher, &package.name);
    hasher.update(provenance.as_bytes());
    hasher.update(selected.as_bytes());
    hash_string(&mut hasher, path);
    hasher.update(object.as_bytes());
    hasher.update(tree.as_bytes());
    hasher.update(generation.as_bytes());
    hasher.finalize()
}

fn hash_bytes(domain: &[u8], bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize()
}
fn hash_string(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(H[usize::from(byte >> 4)]));
        text.push(char::from(H[usize::from(byte & 15)]));
    }
    text
}
fn unhex(value: &str) -> Result<String, LeanBunLockV1Error> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::NonCanonicalText,
            "invalid lowercase hex text token",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let nibble = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes.push((nibble(pair[0]) << 4) | nibble(pair[1]));
    }
    String::from_utf8(bytes).map_err(|_| {
        LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::NonCanonicalText,
            "text token is not UTF-8",
        )
    })
}
fn line(output: &mut String, label: &str, values: &[&str]) {
    output.push_str(label);
    for value in values {
        output.push('\t');
        output.push_str(value);
    }
    output.push('\n');
}
fn line_optional_sha(output: &mut String, label: &str, value: Option<Sha256>) {
    line(
        output,
        label,
        &[&value.map_or_else(|| "-".to_owned(), |digest| digest.to_string())],
    );
}
fn encode_optional_text(value: Option<&str>) -> String {
    value.map_or_else(|| "-".to_owned(), |text| hex(text.as_bytes()))
}
fn encode_requested(output: &mut String, value: &RequestedPackageSourceV1) {
    match value {
        RequestedPackageSourceV1::Git {
            url,
            requested_revision,
        } => line(
            output,
            "requested",
            &[
                "git",
                &hex(url.as_str().as_bytes()),
                &encode_optional_text(requested_revision.as_deref()),
            ],
        ),
        RequestedPackageSourceV1::PathSnapshot {
            portable_path_token,
        } => line(
            output,
            "requested",
            &["path-snapshot", &hex(portable_path_token.as_bytes()), "-"],
        ),
    }
}
fn encode_resolved(output: &mut String, value: &ResolvedPackageSourceV1) {
    match value {
        ResolvedPackageSourceV1::Git {
            url,
            exact_revision,
            subdir,
        } => line(
            output,
            "resolved",
            &[
                "git",
                &hex(url.as_str().as_bytes()),
                exact_revision,
                &encode_optional_text(subdir.as_deref()),
            ],
        ),
        ResolvedPackageSourceV1::PathSnapshot {
            portable_path_token,
        } => line(
            output,
            "resolved",
            &[
                "path-snapshot",
                &hex(portable_path_token.as_bytes()),
                "-",
                "-",
            ],
        ),
    }
}

struct Lines<'a> {
    lines: std::str::Lines<'a>,
}
impl<'a> Lines<'a> {
    fn expect(&mut self, label: &str, fields: usize) -> Result<Vec<&'a str>, LeanBunLockV1Error> {
        let line = self.lines.next().ok_or_else(|| {
            LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::NonCanonicalText,
                format!("missing {label} line"),
            )
        })?;
        let parts = line.split('\t').collect::<Vec<_>>();
        if parts.len() != fields + 1 || parts[0] != label {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::NonCanonicalText,
                format!("expected canonical {label} line"),
            ));
        }
        Ok(parts[1..].to_vec())
    }
}
fn parse_usize(value: &str) -> Result<usize, LeanBunLockV1Error> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::NonCanonicalText,
            "invalid canonical count",
        ));
    }
    value.parse().map_err(|_| {
        LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::LimitExceeded,
            "count exceeds platform limit",
        )
    })
}
fn parse_sha(value: &str) -> Result<Sha256, LeanBunLockV1Error> {
    Sha256::parse(value).map_err(|_| {
        LeanBunLockV1Error::new(LeanBunLockV1ErrorKind::NonCanonicalText, "invalid SHA-256")
    })
}
fn parse_optional_sha(value: &str) -> Result<Option<Sha256>, LeanBunLockV1Error> {
    if value == "-" {
        Ok(None)
    } else {
        parse_sha(value).map(Some)
    }
}
fn parse_optional_text(value: &str) -> Result<Option<String>, LeanBunLockV1Error> {
    if value == "-" {
        Ok(None)
    } else {
        unhex(value).map(Some)
    }
}

fn parse_lock(text: &str) -> Result<LeanBunLockV1, LeanBunLockV1Error> {
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::NonCanonicalText,
            "lock must use one trailing LF and no CR",
        ));
    }
    let mut lines = Lines {
        lines: text.lines(),
    };
    let header = lines.expect("leanbun-lock-v1", 1)?;
    if header[0] != "1" {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::NonCanonicalText,
            "unsupported schema version",
        ));
    }
    let toolchain = unhex(lines.expect("lean-toolchain", 1)?[0])?;
    let compiler = unhex(lines.expect("lean-compiler-githash", 1)?[0])?;
    let lake = unhex(lines.expect("lake-version", 1)?[0])?;
    let root_config = parse_sha(lines.expect("root-config-sha256", 1)?[0])?;
    let root_declaration = parse_sha(lines.expect("root-declaration-sha256", 1)?[0])?;
    let count = parse_usize(lines.expect("package-count", 1)?[0])?;
    if count > MAX_LOCK_PACKAGES_V1 {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::LimitExceeded,
            "package count exceeds limit",
        ));
    }
    let mut packages = Vec::with_capacity(count);
    for _ in 0..count {
        let key_line = lines.expect("package", 2)?;
        let key = PackageKeyV1::new(unhex(key_line[0])?, unhex(key_line[1])?)?;
        let requested_line = lines.expect("requested", 3)?;
        let requested = match requested_line[0] {
            "git" => RequestedPackageSourceV1::git(
                CanonicalSourceUrlV1::parse(unhex(requested_line[1])?)?,
                parse_optional_text(requested_line[2])?,
            )?,
            "path-snapshot" if requested_line[2] == "-" => {
                RequestedPackageSourceV1::path_snapshot(unhex(requested_line[1])?)?
            }
            _ => {
                return Err(LeanBunLockV1Error::new(
                    LeanBunLockV1ErrorKind::NonCanonicalText,
                    "invalid requested source",
                ));
            }
        };
        let resolved_line = lines.expect("resolved", 4)?;
        let resolved = match resolved_line[0] {
            "git" => ResolvedPackageSourceV1::git(
                CanonicalSourceUrlV1::parse(unhex(resolved_line[1])?)?,
                resolved_line[2],
                parse_optional_text(resolved_line[3])?,
            )?,
            "path-snapshot" if resolved_line[2] == "-" && resolved_line[3] == "-" => {
                ResolvedPackageSourceV1::path_snapshot(unhex(resolved_line[1])?)?
            }
            _ => {
                return Err(LeanBunLockV1Error::new(
                    LeanBunLockV1ErrorKind::NonCanonicalText,
                    "invalid resolved source",
                ));
            }
        };
        let integrity = parse_optional_sha(lines.expect("download-integrity", 1)?[0])?;
        let tree = parse_sha(lines.expect("source-tree-sha256", 1)?[0])?;
        let config = parse_sha(lines.expect("config-sha256", 1)?[0])?;
        let manifest = parse_optional_sha(lines.expect("manifest-sha256", 1)?[0])?;
        let selected = parse_sha(lines.expect("selected-source-identity", 1)?[0])?;
        let dep_count = parse_usize(lines.expect("dependency-count", 1)?[0])?;
        if dep_count > MAX_PACKAGE_DEPENDENCIES_V1 {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::LimitExceeded,
                "dependency count exceeds limit",
            ));
        }
        let mut dependencies = Vec::with_capacity(dep_count);
        for _ in 0..dep_count {
            let item = lines.expect("dependency", 2)?;
            dependencies.push(PackageDependencyV1::new(PackageKeyV1::new(
                unhex(item[0])?,
                unhex(item[1])?,
            )?));
        }
        let provenance_count = parse_usize(lines.expect("provenance-count", 1)?[0])?;
        if provenance_count > MAX_PACKAGE_DEPENDENCIES_V1 {
            return Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::LimitExceeded,
                "provenance count exceeds limit",
            ));
        }
        let mut provenance = Vec::with_capacity(provenance_count);
        for _ in 0..provenance_count {
            provenance.push(parse_sha(lines.expect("provenance", 1)?[0])?);
        }
        lines.expect("end-package", 0)?;
        packages.push(LockedLeanPackageV1::new(
            key,
            requested,
            resolved,
            integrity,
            tree,
            config,
            manifest,
            dependencies,
            provenance,
            selected,
        )?);
    }
    let claimed_graph = parse_sha(lines.expect("graph-sha256", 1)?[0])?;
    lines.expect("end-lock", 0)?;
    if lines.lines.next().is_some() {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::NonCanonicalText,
            "trailing lock records",
        ));
    }
    let lock = LeanBunLockV1::new(
        toolchain,
        compiler,
        lake,
        root_config,
        root_declaration,
        packages,
    )?;
    if lock.graph_sha256 != claimed_graph {
        return Err(LeanBunLockV1Error::new(
            LeanBunLockV1ErrorKind::DigestMismatch,
            "graph digest does not match canonical graph",
        ));
    }
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(byte: u8) -> Sha256 {
        Sha256::from_bytes([byte; 32])
    }

    fn git_package(
        key: PackageKeyV1,
        dependencies: Vec<PackageDependencyV1>,
        selected: Sha256,
    ) -> LockedLeanPackageV1 {
        let url = CanonicalSourceUrlV1::parse("https://github.com/example/package")
            .unwrap_or_else(|error| panic!("fixture URL failed: {error}"));
        LockedLeanPackageV1::new(
            key,
            RequestedPackageSourceV1::git(url.clone(), Some("main".to_owned()))
                .unwrap_or_else(|error| panic!("requested source failed: {error}")),
            ResolvedPackageSourceV1::git(
                url,
                "1111111111111111111111111111111111111111",
                Some("src".to_owned()),
            )
            .unwrap_or_else(|error| panic!("resolved source failed: {error}")),
            Some(sha(1)),
            sha(2),
            sha(3),
            Some(sha(4)),
            dependencies,
            vec![sha(5)],
            selected,
        )
        .unwrap_or_else(|error| panic!("package failed: {error}"))
    }

    fn two_package_lock(reverse: bool) -> LeanBunLockV1 {
        let alpha =
            PackageKeyV1::new("", "alpha").unwrap_or_else(|error| panic!("key failed: {error}"));
        let beta = PackageKeyV1::new("scope", "beta")
            .unwrap_or_else(|error| panic!("key failed: {error}"));
        let first = git_package(
            alpha.clone(),
            vec![PackageDependencyV1::new(beta.clone())],
            sha(6),
        );
        let second = git_package(beta, Vec::new(), sha(7));
        let packages = if reverse {
            vec![second, first]
        } else {
            vec![first, second]
        };
        LeanBunLockV1::new(
            "leanprover/lean4:v4.32.0",
            "1111111111111111111111111111111111111111",
            "5.0.0-src+8c9756b",
            sha(8),
            sha(9),
            packages,
        )
        .unwrap_or_else(|error| panic!("lock failed: {error}"))
    }

    #[test]
    fn canonical_codec_round_trips_and_input_order_does_not_change_identity() {
        let first = two_package_lock(false);
        let reordered = two_package_lock(true);
        assert_eq!(first.graph_sha256(), reordered.graph_sha256());
        assert_eq!(first.identity(), reordered.identity());
        assert_eq!(first.to_canonical_text(), reordered.to_canonical_text());
        assert_eq!(
            LeanBunLockV1::from_canonical_text(&first.to_canonical_text()),
            Ok(first)
        );
        let expected = include_str!("../../../../test/fixtures/m31-lock/canonical-golden.tsv")
            .lines()
            .map(|line| {
                line.split_once('\t')
                    .unwrap_or_else(|| panic!("invalid golden fixture"))
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(reordered.graph_sha256().to_string(), expected["graph"]);
        assert_eq!(reordered.identity().to_string(), expected["identity"]);
        assert_eq!(
            hash_bytes(b"", reordered.to_canonical_text().as_bytes()).to_string(),
            expected["text-sha256"]
        );
    }

    #[test]
    fn every_package_semantic_field_is_bound_into_the_graph_digest() {
        let lock = two_package_lock(false);
        let baseline = lock.graph_sha256();
        let mut packages = lock.packages.clone();
        packages[0].source_tree_sha256 = sha(10);
        assert_ne!(hash_graph(&packages), baseline);
        packages = lock.packages.clone();
        if let ResolvedPackageSourceV1::Git { exact_revision, .. } = &mut packages[0].resolved {
            *exact_revision = "2222222222222222222222222222222222222222".to_owned();
        }
        assert_ne!(hash_graph(&packages), baseline);
        packages = lock.packages.clone();
        packages[0].provenance_digests = vec![sha(13)];
        assert_ne!(hash_graph(&packages), baseline);
    }

    #[test]
    fn noncanonical_and_digest_drift_are_rejected() {
        let text = two_package_lock(false).to_canonical_text();
        let noncanonical = text.replacen("package-count\t2", "package-count\t02", 1);
        assert_eq!(
            LeanBunLockV1::from_canonical_text(&noncanonical).map(|_| ()),
            Err(LeanBunLockV1Error::new(
                LeanBunLockV1ErrorKind::NonCanonicalText,
                "invalid canonical count"
            ))
        );
        let drifted = text.replacen(&sha(6).to_string(), &sha(10).to_string(), 1);
        assert!(matches!(
            LeanBunLockV1::from_canonical_text(&drifted),
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::DigestMismatch,
                ..
            })
        ));
    }

    #[test]
    fn graph_rejects_missing_packages_cycles_and_excessive_depth() {
        let a = PackageKeyV1::new("", "a").unwrap_or_else(|error| panic!("key failed: {error}"));
        let missing =
            PackageKeyV1::new("", "missing").unwrap_or_else(|error| panic!("key failed: {error}"));
        let package = git_package(a, vec![PackageDependencyV1::new(missing)], sha(6));
        assert!(matches!(
            LeanBunLockV1::new(
                "toolchain",
                "1111111111111111111111111111111111111111",
                "lake",
                sha(1),
                sha(2),
                vec![package]
            ),
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::MissingPackage,
                ..
            })
        ));

        let left =
            PackageKeyV1::new("", "left").unwrap_or_else(|error| panic!("key failed: {error}"));
        let right =
            PackageKeyV1::new("", "right").unwrap_or_else(|error| panic!("key failed: {error}"));
        let cycle = vec![
            git_package(
                left.clone(),
                vec![PackageDependencyV1::new(right.clone())],
                sha(6),
            ),
            git_package(right, vec![PackageDependencyV1::new(left)], sha(7)),
        ];
        assert!(matches!(
            LeanBunLockV1::new(
                "toolchain",
                "1111111111111111111111111111111111111111",
                "lake",
                sha(1),
                sha(2),
                cycle
            ),
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::DependencyCycle,
                ..
            })
        ));

        let keys = (0..=MAX_GRAPH_DEPTH_V1)
            .map(|index| {
                PackageKeyV1::new("", format!("p{index:03}"))
                    .unwrap_or_else(|error| panic!("key failed: {error}"))
            })
            .collect::<Vec<_>>();
        let deep = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                git_package(
                    key.clone(),
                    keys.get(index + 1)
                        .cloned()
                        .map(PackageDependencyV1::new)
                        .into_iter()
                        .collect(),
                    sha(6),
                )
            })
            .collect();
        assert!(matches!(
            LeanBunLockV1::new(
                "toolchain",
                "1111111111111111111111111111111111111111",
                "lake",
                sha(1),
                sha(2),
                deep
            ),
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::GraphTooDeep,
                ..
            })
        ));
    }

    #[test]
    fn provenance_and_decisions_admit_exactly_one_contained_final_path_per_locked_package() {
        let lock = two_package_lock(false);
        let mut provenances = Vec::new();
        let mut decisions = Vec::new();
        for package in lock.packages() {
            provenances.push(PackagePathProvenanceV1::manifest(
                package.key().clone(),
                package.selected_source_identity(),
            ));
        }
        let set = PackagePathProvenanceSetV1::new(provenances)
            .unwrap_or_else(|error| panic!("provenance failed: {error}"));
        let duplicate = PackagePathProvenanceSetV1::new(vec![
            PackagePathProvenanceV1::manifest(
                lock.packages()[0].key().clone(),
                lock.packages()[0].selected_source_identity(),
            ),
            PackagePathProvenanceV1::manifest(lock.packages()[0].key().clone(), sha(14)),
        ]);
        assert!(matches!(
            duplicate,
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::DuplicateProvenance,
                ..
            })
        ));
        let ambiguous = PackagePathProvenanceSetV1::new(vec![
            PackagePathProvenanceV1::manifest(
                lock.packages()[0].key().clone(),
                lock.packages()[0].selected_source_identity(),
            ),
            PackagePathProvenanceV1::workspace_override(
                lock.packages()[0].key().clone(),
                lock.packages()[0].selected_source_identity(),
            ),
        ])
        .unwrap_or_else(|error| panic!("ambiguous fixture set failed: {error}"));
        assert!(matches!(
            PackagePathDecisionV1::new(
                lock.packages()[0].key().clone(),
                &ambiguous,
                lock.packages()[0].selected_source_identity(),
                "/isolated/generation",
                "/isolated/generation/alpha",
                sha(11),
                lock.packages()[0].source_tree_sha256,
                sha(12)
            ),
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::AmbiguousSelection,
                ..
            })
        ));
        for package in lock.packages() {
            let final_path = if package.key().scope().is_empty() {
                format!("/isolated/generation/{}", package.key().name())
            } else {
                format!(
                    "/isolated/generation/{}/{}",
                    package.key().scope(),
                    package.key().name()
                )
            };
            decisions.push(
                PackagePathDecisionV1::new(
                    package.key().clone(),
                    &set,
                    package.selected_source_identity(),
                    "/isolated/generation",
                    final_path,
                    sha(11),
                    package.source_tree_sha256,
                    sha(12),
                )
                .unwrap_or_else(|error| panic!("decision failed: {error}")),
            );
        }
        assert!(PackagePathDecisionSetV1::new(&lock, decisions.clone()).is_ok());
        assert!(matches!(
            PackagePathDecisionSetV1::new(&lock, vec![decisions[0].clone()]),
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::MissingDecision,
                ..
            })
        ));
        assert!(matches!(
            PackagePathDecisionSetV1::new(
                &lock,
                vec![
                    decisions[0].clone(),
                    decisions[0].clone(),
                    decisions[1].clone()
                ]
            ),
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::DuplicateDecision,
                ..
            })
        ));
        assert!(matches!(
            PackagePathDecisionV1::new(
                lock.packages()[0].key().clone(),
                &set,
                lock.packages()[0].selected_source_identity(),
                "/isolated/generation",
                "/other/path",
                sha(11),
                lock.packages()[0].source_tree_sha256,
                sha(12)
            ),
            Err(LeanBunLockV1Error {
                kind: LeanBunLockV1ErrorKind::PathOutsideGenerationRoot,
                ..
            })
        ));
    }

    #[test]
    fn shared_model_fixture_matches_bounded_constructor_contract() {
        let fixture = include_str!("../../../../test/fixtures/m31-lock/model-cases.tsv");
        for (index, line) in fixture.lines().enumerate() {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 8, "fixture line {}", index + 1);
            let expected = fields[0] == "true";
            let decode = |value: &str| {
                if value == "-" {
                    Ok(String::new())
                } else {
                    unhex(value)
                }
            };
            let result = (|| {
                let key = PackageKeyV1::new(decode(fields[2])?, decode(fields[3])?)?;
                match fields[4] {
                    "git" => {
                        let url = CanonicalSourceUrlV1::parse(decode(fields[5])?)?;
                        let subdir = if fields[7] == "-" {
                            None
                        } else {
                            Some(unhex(fields[7])?)
                        };
                        let _ = ResolvedPackageSourceV1::git(url, fields[6], subdir)?;
                    }
                    "path" => {
                        let _ = ResolvedPackageSourceV1::path_snapshot(decode(fields[5])?)?;
                    }
                    _ => {
                        return Err(LeanBunLockV1Error::new(
                            LeanBunLockV1ErrorKind::InvalidField,
                            "unknown fixture source",
                        ));
                    }
                }
                let _ = key;
                Ok(())
            })();
            assert_eq!(result.is_ok(), expected, "{}", fields[1]);
        }
    }
}

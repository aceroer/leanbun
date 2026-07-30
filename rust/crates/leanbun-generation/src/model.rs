use leanbun_core::{ExecutionId, ProjectId, Sha256, Sha256Hasher, project_id};
use leanbun_lake_bridge::{LakeManifestProjectionV1, LakeRuntimePackagesProjectionV1};
use leanbun_lock::{LeanBunLockV1, PackagePathDecisionSetV1, ReservoirBindingDocumentV1};
use leanbun_resolver::{LeanExactSourceV1, LeanResolutionGraphV1, LeanSourceRequestV1};
use leanbun_store::VerifiedPackageObjectV1;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};

pub const MAX_GENERATION_PACKAGES_V1: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeanGenerationErrorKind {
    InvalidField,
    BoundaryViolation,
    IncompatibleInput,
    DuplicatePackage,
    MissingPackage,
    LockBusy,
    OwnershipMismatch,
    InvalidTransition,
    RecordMalformed,
    RecordDrift,
    GenerationDrift,
    MixedProjection,
    Io,
    SyncFailed,
    RenameFailed,
    FaultInjected,
    IndeterminatePublication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanGenerationError {
    pub kind: LeanGenerationErrorKind,
    pub message: String,
}

impl LeanGenerationError {
    pub(crate) fn new(kind: LeanGenerationErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for LeanGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LeanGenerationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeanGenerationStateV1 {
    Preparing,
    Materialized,
    Verified,
    Published,
    Failed,
}

impl LeanGenerationStateV1 {
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Materialized => "materialized",
            Self::Verified => "verified",
            Self::Published => "published",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, LeanGenerationError> {
        match value {
            "preparing" => Ok(Self::Preparing),
            "materialized" => Ok(Self::Materialized),
            "verified" => Ok(Self::Verified),
            "published" => Ok(Self::Published),
            "failed" => Ok(Self::Failed),
            _ => Err(LeanGenerationError::new(
                LeanGenerationErrorKind::RecordMalformed,
                "unknown generation transaction state",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LeanGenerationFaultV1 {
    #[default]
    None,
    AfterLock,
    AfterPreparing,
    AfterLockFile,
    AfterManifestProjection,
    AfterRuntimeProjection,
    AfterPackages,
    AfterGenerationMetadata,
    AfterFileSync,
    AfterDirectorySync,
    AfterMaterialized,
    AfterVerified,
    BeforeActiveRename,
    AfterActiveRename,
    AfterPublishedRecord,
    AfterRetainedRecord,
    BeforeLockRelease,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanGenerationOutcomeV1 {
    pub(crate) transaction_id: ExecutionId,
    pub(crate) generation_identity: Sha256,
    pub(crate) generation_root: PathBuf,
    pub(crate) state: LeanGenerationStateV1,
}

impl LeanGenerationOutcomeV1 {
    #[must_use]
    pub const fn transaction_id(&self) -> ExecutionId {
        self.transaction_id
    }
    #[must_use]
    pub const fn generation_identity(&self) -> Sha256 {
        self.generation_identity
    }
    #[must_use]
    pub fn generation_root(&self) -> &Path {
        &self.generation_root
    }
    #[must_use]
    pub const fn state(&self) -> LeanGenerationStateV1 {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeanGenerationRecoveryV1 {
    pub(crate) state: LeanGenerationStateV1,
    pub(crate) active: bool,
    pub(crate) lock_released: bool,
}

impl LeanGenerationRecoveryV1 {
    #[must_use]
    pub const fn state(&self) -> LeanGenerationStateV1 {
        self.state
    }
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }
    #[must_use]
    pub const fn lock_released(&self) -> bool {
        self.lock_released
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GenerationPackageV1 {
    pub key_scope: String,
    pub key_name: String,
    pub final_path: PathBuf,
    pub store_object_sha256: Sha256,
    pub source_tree_sha256: Sha256,
    pub object_tree_path: PathBuf,
    pub entries: Vec<leanbun_store::NormalizedTreeEntryV1>,
}

#[derive(Clone, Debug)]
pub struct LeanBunGenerationV1 {
    transaction_id: ExecutionId,
    project_id: ProjectId,
    project_root: PathBuf,
    generation_root: PathBuf,
    lock_sha256: Sha256,
    graph_sha256: Sha256,
    decision_set_sha256: Sha256,
    manifest_projection_sha256: Sha256,
    runtime_projection_sha256: Sha256,
    reservoir_bindings_sha256: Option<Sha256>,
    lean_toolchain: String,
    compiler_githash: String,
    lake_version: String,
    identity: Sha256,
    pub(crate) lock_text: String,
    pub(crate) manifest_text: String,
    pub(crate) runtime_text: String,
    pub(crate) packages: Vec<GenerationPackageV1>,
}

impl LeanBunGenerationV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: ExecutionId,
        project_root: impl Into<PathBuf>,
        generation_root: impl Into<PathBuf>,
        lock: &LeanBunLockV1,
        graph: &LeanResolutionGraphV1,
        decisions: &PackagePathDecisionSetV1,
        manifest: &LakeManifestProjectionV1,
        runtime: &LakeRuntimePackagesProjectionV1,
        objects: Vec<VerifiedPackageObjectV1>,
    ) -> Result<Self, LeanGenerationError> {
        Self::new_with_reservoir_bindings(
            transaction_id,
            project_root,
            generation_root,
            lock,
            graph,
            decisions,
            manifest,
            runtime,
            objects,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_reservoir_bindings(
        transaction_id: ExecutionId,
        project_root: impl Into<PathBuf>,
        generation_root: impl Into<PathBuf>,
        lock: &LeanBunLockV1,
        graph: &LeanResolutionGraphV1,
        decisions: &PackagePathDecisionSetV1,
        manifest: &LakeManifestProjectionV1,
        runtime: &LakeRuntimePackagesProjectionV1,
        objects: Vec<VerifiedPackageObjectV1>,
        reservoir_bindings: Option<&ReservoirBindingDocumentV1>,
    ) -> Result<Self, LeanGenerationError> {
        let project_root = project_root.into();
        let generation_root = generation_root.into();
        validate_absolute_path(&project_root, "project root")?;
        validate_absolute_path(&generation_root, "generation root")?;
        if objects.len() > MAX_GENERATION_PACKAGES_V1 {
            return Err(invalid("generation package count exceeds limit"));
        }
        if lock.root_declaration_sha256() != graph.root_declaration_identity()
            || lock.lean_toolchain() != graph.toolchain().lean_toolchain()
            || lock.lean_compiler_githash() != graph.toolchain().compiler_githash()
            || lock.lake_version() != graph.toolchain().lake_version()
        {
            return Err(incompatible("lock and M33 graph identity differ"));
        }
        if lock.packages().len() != graph.packages().len()
            || lock.packages().len() != decisions.decisions().len()
            || lock.packages().len() != objects.len()
            || runtime.package_count() != objects.len()
        {
            return Err(incompatible(
                "generation inputs do not describe one complete closure",
            ));
        }

        let mut object_map = BTreeMap::new();
        for object in objects {
            if object_map
                .insert(object.package().clone(), object)
                .is_some()
            {
                return Err(LeanGenerationError::new(
                    LeanGenerationErrorKind::DuplicatePackage,
                    "generation contains duplicate verified package objects",
                ));
            }
        }
        let graph_keys = graph
            .packages()
            .iter()
            .map(|package| package.key())
            .collect::<BTreeSet<_>>();
        let lock_keys = lock
            .packages()
            .iter()
            .map(|package| package.key())
            .collect::<BTreeSet<_>>();
        if graph_keys != lock_keys {
            return Err(incompatible("lock package set differs from the M33 graph"));
        }
        validate_reservoir_bindings(lock, graph, reservoir_bindings)?;

        let mut packages = Vec::with_capacity(lock.packages().len());
        for (locked, decision) in lock.packages().iter().zip(decisions.decisions()) {
            if locked.key() != decision.package() {
                return Err(incompatible(
                    "decision ordering differs from canonical lock ordering",
                ));
            }
            let object = object_map.remove(locked.key()).ok_or_else(|| {
                LeanGenerationError::new(
                    LeanGenerationErrorKind::MissingPackage,
                    "verified package object is missing",
                )
            })?;
            let resolved = graph
                .packages()
                .iter()
                .find(|package| package.key() == locked.key())
                .ok_or_else(|| incompatible("locked package is absent from the M33 graph"))?;
            let graph_candidate = resolved.candidate();
            let locked_dependencies = locked
                .dependencies()
                .iter()
                .map(leanbun_lock::PackageDependencyV1::package)
                .collect::<BTreeSet<_>>();
            let graph_dependencies = resolved.dependencies().iter().collect::<BTreeSet<_>>();
            if graph_candidate.source_tree_sha256() != locked.source_tree_sha256()
                || graph_candidate.download_integrity() != locked.download_integrity()
                || graph_candidate.config_sha256() != locked.config_sha256()
                || graph_candidate.manifest_sha256() != locked.manifest_sha256()
                || graph_candidate.selected_source_identity() != locked.selected_source_identity()
                || locked_dependencies != graph_dependencies
                || object.candidate_identity() != resolved.candidate_identity()
                || object.package_source_key()
                    != leanbun_lock::PackageSourceKeyV1::from_locked_package(locked)
            {
                return Err(incompatible(
                    "M31 lock, M33 graph and M34 object package facts differ",
                ));
            }
            if object.source_tree_sha256() != locked.source_tree_sha256()
                || object.source_tree_sha256() != decision.source_tree_sha256()
                || object.store_object_sha256() != decision.store_object_sha256()
                || decision.generation() != graph.identity()
            {
                return Err(incompatible(
                    "verified object differs from lock or path decision",
                ));
            }
            let expected =
                package_path(&generation_root, locked.key().scope(), locked.key().name());
            if Path::new(decision.final_path()) != expected {
                return Err(incompatible(
                    "path decision is not the canonical generation package path",
                ));
            }
            packages.push(GenerationPackageV1 {
                key_scope: locked.key().scope().to_owned(),
                key_name: locked.key().name().to_owned(),
                final_path: expected,
                store_object_sha256: object.store_object_sha256(),
                source_tree_sha256: object.source_tree_sha256(),
                object_tree_path: object.tree_path().to_path_buf(),
                entries: object.entries().to_vec(),
            });
        }
        if !object_map.is_empty() {
            return Err(incompatible("verified object contains an extra package"));
        }
        let lock_text = lock.to_canonical_text();
        let lock_sha256 = hash_domain(b"leanbun-lock-bytes-v1\0", lock_text.as_bytes());
        let graph_sha256 = graph.identity();
        let decision_set_sha256 = decisions.digest();
        let manifest_projection_sha256 = manifest.sha256();
        let runtime_projection_sha256 = runtime.sha256();
        let reservoir_bindings_sha256 =
            reservoir_bindings.map(ReservoirBindingDocumentV1::identity);
        let identity = generation_identity(
            transaction_id,
            project_id(path_text(&project_root)?),
            &generation_root,
            lock_sha256,
            graph_sha256,
            decision_set_sha256,
            manifest_projection_sha256,
            runtime_projection_sha256,
            reservoir_bindings_sha256,
            &packages,
        )?;
        Ok(Self {
            transaction_id,
            project_id: project_id(path_text(&project_root)?),
            project_root,
            generation_root,
            lock_sha256,
            graph_sha256,
            decision_set_sha256,
            manifest_projection_sha256,
            runtime_projection_sha256,
            reservoir_bindings_sha256,
            lean_toolchain: lock.lean_toolchain().to_owned(),
            compiler_githash: lock.lean_compiler_githash().to_owned(),
            lake_version: lock.lake_version().to_owned(),
            identity,
            lock_text,
            manifest_text: manifest.as_str().to_owned(),
            runtime_text: runtime.as_str().to_owned(),
            packages,
        })
    }

    #[must_use]
    pub const fn transaction_id(&self) -> ExecutionId {
        self.transaction_id
    }
    #[must_use]
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }
    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }
    #[must_use]
    pub fn generation_root(&self) -> &Path {
        &self.generation_root
    }
    #[must_use]
    pub const fn lock_sha256(&self) -> Sha256 {
        self.lock_sha256
    }
    #[must_use]
    pub const fn graph_sha256(&self) -> Sha256 {
        self.graph_sha256
    }
    #[must_use]
    pub const fn decision_set_sha256(&self) -> Sha256 {
        self.decision_set_sha256
    }
    #[must_use]
    pub const fn manifest_projection_sha256(&self) -> Sha256 {
        self.manifest_projection_sha256
    }
    #[must_use]
    pub const fn runtime_projection_sha256(&self) -> Sha256 {
        self.runtime_projection_sha256
    }
    #[must_use]
    pub const fn reservoir_bindings_sha256(&self) -> Option<Sha256> {
        self.reservoir_bindings_sha256
    }
    #[must_use]
    pub fn lean_toolchain(&self) -> &str {
        &self.lean_toolchain
    }
    #[must_use]
    pub fn compiler_githash(&self) -> &str {
        &self.compiler_githash
    }
    #[must_use]
    pub fn lake_version(&self) -> &str {
        &self.lake_version
    }
    #[must_use]
    pub const fn identity(&self) -> Sha256 {
        self.identity
    }
    #[must_use]
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }
    #[must_use]
    pub fn package_paths(&self) -> Vec<PathBuf> {
        self.packages
            .iter()
            .map(|package| package.final_path.clone())
            .collect()
    }

    pub(crate) fn canonical_metadata(&self) -> Result<Vec<u8>, LeanGenerationError> {
        let mut output = if self.reservoir_bindings_sha256.is_some() {
            String::from("leanbun-generation-v2\t2\n")
        } else {
            String::from("leanbun-generation-v1\t1\n")
        };
        field(&mut output, "transaction", self.transaction_id.as_str());
        field(&mut output, "project-id", &self.project_id.to_string());
        field(&mut output, "project-root", path_text(&self.project_root)?);
        field(
            &mut output,
            "generation-root",
            path_text(&self.generation_root)?,
        );
        field(&mut output, "lock-sha256", &self.lock_sha256.to_string());
        field(&mut output, "graph-sha256", &self.graph_sha256.to_string());
        field(
            &mut output,
            "decision-set-sha256",
            &self.decision_set_sha256.to_string(),
        );
        field(
            &mut output,
            "manifest-projection-sha256",
            &self.manifest_projection_sha256.to_string(),
        );
        field(
            &mut output,
            "runtime-projection-sha256",
            &self.runtime_projection_sha256.to_string(),
        );
        if let Some(identity) = self.reservoir_bindings_sha256 {
            field(
                &mut output,
                "reservoir-bindings-sha256",
                &identity.to_string(),
            );
        }
        field(
            &mut output,
            "lean-toolchain",
            &hex(self.lean_toolchain.as_bytes()),
        );
        field(&mut output, "compiler-githash", &self.compiler_githash);
        field(
            &mut output,
            "lake-version",
            &hex(self.lake_version.as_bytes()),
        );
        field(
            &mut output,
            "package-count",
            &self.packages.len().to_string(),
        );
        for package in &self.packages {
            output.push_str("package\t");
            output.push_str(&hex(package.key_scope.as_bytes()));
            output.push('\t');
            output.push_str(&hex(package.key_name.as_bytes()));
            output.push('\t');
            output.push_str(path_text(&package.final_path)?);
            output.push('\t');
            output.push_str(&package.store_object_sha256.to_string());
            output.push('\t');
            output.push_str(&package.source_tree_sha256.to_string());
            output.push('\n');
        }
        field(&mut output, "generation-sha256", &self.identity.to_string());
        output.push_str("end-generation\n");
        Ok(output.into_bytes())
    }
}

pub(crate) fn package_path(root: &Path, scope: &str, name: &str) -> PathBuf {
    if scope.is_empty() {
        root.join("packages").join(name)
    } else {
        root.join("packages").join(scope).join(name)
    }
}

#[allow(clippy::too_many_arguments)]
fn generation_identity(
    transaction: ExecutionId,
    project: ProjectId,
    root: &Path,
    lock: Sha256,
    graph: Sha256,
    decisions: Sha256,
    manifest: Sha256,
    runtime: Sha256,
    reservoir_bindings: Option<Sha256>,
    packages: &[GenerationPackageV1],
) -> Result<Sha256, LeanGenerationError> {
    let mut hasher = Sha256Hasher::new();
    if reservoir_bindings.is_some() {
        hasher.update(b"leanbun-generation-identity-v2\0");
    } else {
        hasher.update(b"leanbun-generation-identity-v1\0");
    }
    hasher.update(transaction.as_str().as_bytes());
    hasher.update(project.digest().as_bytes());
    hash_text(&mut hasher, path_text(root)?);
    for digest in [lock, graph, decisions, manifest, runtime] {
        hasher.update(digest.as_bytes());
    }
    if let Some(identity) = reservoir_bindings {
        hasher.update(identity.as_bytes());
    }
    hasher.update(&(packages.len() as u64).to_be_bytes());
    for package in packages {
        hash_text(&mut hasher, &package.key_scope);
        hash_text(&mut hasher, &package.key_name);
        hash_text(&mut hasher, path_text(&package.final_path)?);
        hasher.update(package.store_object_sha256.as_bytes());
        hasher.update(package.source_tree_sha256.as_bytes());
    }
    Ok(hasher.finalize())
}

fn validate_reservoir_bindings(
    lock: &LeanBunLockV1,
    graph: &LeanResolutionGraphV1,
    document: Option<&ReservoirBindingDocumentV1>,
) -> Result<(), LeanGenerationError> {
    let reservoir_packages = graph
        .packages()
        .iter()
        .filter(|package| {
            matches!(
                package.candidate().requested_source(),
                LeanSourceRequestV1::Reservoir { .. }
            )
        })
        .collect::<Vec<_>>();
    if reservoir_packages.is_empty() {
        if document.is_some() {
            return Err(incompatible(
                "non-Reservoir generation must not carry Reservoir binding authority",
            ));
        }
        return Ok(());
    }
    let document = document
        .ok_or_else(|| incompatible("Reservoir-backed generation requires a binding companion"))?;
    if document.lock_v1_identity() != lock.identity() {
        return Err(incompatible(
            "Reservoir binding companion names another V1 lock",
        ));
    }
    if document.bindings().len() != reservoir_packages.len() {
        return Err(incompatible(
            "Reservoir binding set differs from the resolution graph",
        ));
    }
    let binding_map = document
        .bindings()
        .iter()
        .map(|binding| (binding.package(), binding))
        .collect::<BTreeMap<_, _>>();
    for package in reservoir_packages {
        let binding = binding_map
            .get(package.key())
            .ok_or_else(|| incompatible("Reservoir graph package lacks a binding"))?;
        let LeanSourceRequestV1::Reservoir { version } = package.candidate().requested_source()
        else {
            return Err(incompatible("Reservoir request classification changed"));
        };
        if version.as_deref() != Some(binding.requested_version()) {
            return Err(incompatible(
                "Reservoir graph requires an explicit version matching the binding",
            ));
        }
        let LeanExactSourceV1::Git {
            url,
            exact_revision,
            ..
        } = package.candidate().resolved_source()
        else {
            return Err(incompatible(
                "Reservoir graph package requires an exact Git source",
            ));
        };
        if url != binding.resolved_url()
            || exact_revision != binding.exact_commit()
            || package.candidate().download_integrity() != Some(binding.download_integrity())
            || package.candidate().source_tree_sha256() != binding.source_tree_sha256()
            || package.candidate().selected_source_identity() != binding.selected_source_identity()
        {
            return Err(incompatible(
                "Reservoir graph facts differ from the binding companion",
            ));
        }
    }
    Ok(())
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<(), LeanGenerationError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || path_text(path)?.len() > 4_096
    {
        return Err(invalid(format!("{label} must be normalized and absolute")));
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<&str, LeanGenerationError> {
    path.to_str()
        .ok_or_else(|| invalid("generation path is not UTF-8"))
}

fn field(output: &mut String, name: &str, value: &str) {
    output.push_str(name);
    output.push('\t');
    output.push_str(value);
    output.push('\n');
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(TABLE[usize::from(byte >> 4)]));
        output.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    output
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize()
}

fn hash_text(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn invalid(message: impl Into<String>) -> LeanGenerationError {
    LeanGenerationError::new(LeanGenerationErrorKind::InvalidField, message)
}

fn incompatible(message: impl Into<String>) -> LeanGenerationError {
    LeanGenerationError::new(LeanGenerationErrorKind::IncompatibleInput, message)
}

#[cfg(test)]
mod reservoir_tests {
    use super::*;
    use leanbun_lake_bridge::{
        LakeDependencySourceV1, LakeRootDeclarationV1, LakeRootDependencyV1,
    };
    use leanbun_lock::{
        CanonicalSourceUrlV1, LockedLeanPackageV1, PackageKeyV1, PackagePathProvenanceSetV1,
        PackagePathProvenanceV1, RequestedPackageSourceV1, ReservoirBindingV1,
        ReservoirRegistryIdentityV1, ResolvedPackageSourceV1,
    };
    use leanbun_resolver::{
        LeanPackageCandidateV1, LeanResolutionModeV1, LeanResolutionRequestV1,
        LeanToolchainIdentityV1, resolve_lean_dependencies_v1,
    };

    const TOOLCHAIN: &str = "leanprover/lean4:v4.32.0";
    const COMPILER: &str = "8c9756b28d64dab099da31a4c09229a9e6a2ef35";
    const LAKE: &str = "5.0.0-src+8c9756b";

    fn sha(label: &[u8]) -> Sha256 {
        let mut hasher = Sha256Hasher::new();
        hasher.update(label);
        hasher.finalize()
    }

    fn fixture(
        reservoir: bool,
        requested_version: Option<&str>,
    ) -> (
        LeanBunLockV1,
        LeanResolutionGraphV1,
        ReservoirBindingDocumentV1,
    ) {
        let key =
            PackageKeyV1::new("", "fixture").unwrap_or_else(|error| panic!("key failed: {error}"));
        let url = CanonicalSourceUrlV1::parse("https://github.com/leanbun/fixture")
            .unwrap_or_else(|error| panic!("URL failed: {error}"));
        let revision = "1111111111111111111111111111111111111111";
        let root_source = if reservoir {
            LakeDependencySourceV1::Reservoir
        } else {
            LakeDependencySourceV1::Git {
                url: url.as_str().to_owned(),
                revision: Some(revision.to_owned()),
                subdir: None,
            }
        };
        let declaration = LakeRootDeclarationV1::new(
            "root",
            "lakefile.toml",
            vec![
                LakeRootDependencyV1::new(
                    key.clone(),
                    requested_version.map(str::to_owned),
                    root_source,
                )
                .unwrap_or_else(|error| panic!("dependency failed: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("declaration failed: {error}"));
        let provenance = PackagePathProvenanceSetV1::new(vec![PackagePathProvenanceV1::manifest(
            key.clone(),
            sha(b"selected"),
        )])
        .unwrap_or_else(|error| panic!("provenance failed: {error}"));
        let locked = LockedLeanPackageV1::new(
            key.clone(),
            RequestedPackageSourceV1::git(url.clone(), requested_version.map(str::to_owned))
                .unwrap_or_else(|error| panic!("lock request failed: {error}")),
            ResolvedPackageSourceV1::git(url.clone(), revision, None)
                .unwrap_or_else(|error| panic!("lock source failed: {error}")),
            Some(sha(b"download")),
            sha(b"tree"),
            sha(b"config"),
            None,
            Vec::new(),
            vec![provenance.digest()],
            sha(b"selected"),
        )
        .unwrap_or_else(|error| panic!("locked package failed: {error}"));
        let lock = LeanBunLockV1::new(
            TOOLCHAIN,
            COMPILER,
            LAKE,
            sha(b"root-config"),
            declaration.identity(),
            vec![locked],
        )
        .unwrap_or_else(|error| panic!("lock failed: {error}"));
        let requested = if reservoir {
            LeanSourceRequestV1::reservoir(requested_version.map(str::to_owned))
                .unwrap_or_else(|error| panic!("Reservoir request failed: {error}"))
        } else {
            LeanSourceRequestV1::git(url.clone(), Some(revision.to_owned()), None)
                .unwrap_or_else(|error| panic!("Git request failed: {error}"))
        };
        let candidate = LeanPackageCandidateV1::new(
            key.clone(),
            requested,
            LeanExactSourceV1::git(url.clone(), revision, None)
                .unwrap_or_else(|error| panic!("exact source failed: {error}")),
            Vec::new(),
            None,
            Some(sha(b"download")),
            sha(b"tree"),
            sha(b"config"),
            None,
            sha(b"selected"),
        )
        .unwrap_or_else(|error| panic!("candidate failed: {error}"));
        let request = LeanResolutionRequestV1::new(
            declaration,
            None,
            LeanResolutionModeV1::update(Vec::new())
                .unwrap_or_else(|error| panic!("mode failed: {error}")),
            LeanToolchainIdentityV1::new(TOOLCHAIN, COMPILER, LAKE)
                .unwrap_or_else(|error| panic!("toolchain failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("request failed: {error}"));
        let graph = resolve_lean_dependencies_v1(&request, vec![candidate])
            .unwrap_or_else(|error| panic!("resolution failed: {error}"));
        let binding = ReservoirBindingV1::new(
            ReservoirRegistryIdentityV1::new(sha(b"registry")),
            key,
            requested_version.unwrap_or("v1"),
            sha(b"metadata"),
            url,
            revision,
            sha(b"download"),
            sha(b"tree"),
            sha(b"selected"),
        )
        .unwrap_or_else(|error| panic!("binding failed: {error}"));
        let document = ReservoirBindingDocumentV1::new(&lock, vec![binding])
            .unwrap_or_else(|error| panic!("document failed: {error}"));
        (lock, graph, document)
    }

    #[test]
    fn reservoir_graph_requires_exact_companion_and_explicit_version() {
        let (lock, graph, document) = fixture(true, Some("v1"));
        assert_eq!(
            validate_reservoir_bindings(&lock, &graph, None).map_err(|error| error.kind),
            Err(LeanGenerationErrorKind::IncompatibleInput)
        );
        validate_reservoir_bindings(&lock, &graph, Some(&document))
            .unwrap_or_else(|error| panic!("binding validation failed: {error}"));

        let (lock, graph, document) = fixture(true, None);
        assert_eq!(
            validate_reservoir_bindings(&lock, &graph, Some(&document)).map_err(|error| error.kind),
            Err(LeanGenerationErrorKind::IncompatibleInput)
        );
    }

    #[test]
    fn non_reservoir_graph_rejects_extraneous_companion_authority() {
        let (lock, graph, document) = fixture(false, Some("git-main"));
        assert_eq!(
            validate_reservoir_bindings(&lock, &graph, Some(&document)).map_err(|error| error.kind),
            Err(LeanGenerationErrorKind::IncompatibleInput)
        );
        validate_reservoir_bindings(&lock, &graph, None)
            .unwrap_or_else(|error| panic!("ordinary graph failed: {error}"));
    }

    #[test]
    fn generation_v2_identity_and_metadata_bind_companion_without_changing_v1() {
        let transaction = ExecutionId::parse("90000000-0000-4000-8000-000000000009")
            .unwrap_or_else(|error| panic!("transaction failed: {error}"));
        let project_root = PathBuf::from("/tmp/leanbun-m46b-project");
        let generation_root = PathBuf::from("/tmp/leanbun-m46b-generation");
        let project = project_id("/tmp/leanbun-m46b-project");
        let digests = [
            sha(b"lock"),
            sha(b"graph"),
            sha(b"decisions"),
            sha(b"manifest"),
            sha(b"runtime"),
        ];
        let v1_identity = generation_identity(
            transaction,
            project,
            &generation_root,
            digests[0],
            digests[1],
            digests[2],
            digests[3],
            digests[4],
            None,
            &[],
        )
        .unwrap_or_else(|error| panic!("V1 identity failed: {error}"));
        let companion = sha(b"companion");
        let v2_identity = generation_identity(
            transaction,
            project,
            &generation_root,
            digests[0],
            digests[1],
            digests[2],
            digests[3],
            digests[4],
            Some(companion),
            &[],
        )
        .unwrap_or_else(|error| panic!("V2 identity failed: {error}"));
        assert_ne!(v1_identity, v2_identity);

        let generation = LeanBunGenerationV1 {
            transaction_id: transaction,
            project_id: project,
            project_root,
            generation_root,
            lock_sha256: digests[0],
            graph_sha256: digests[1],
            decision_set_sha256: digests[2],
            manifest_projection_sha256: digests[3],
            runtime_projection_sha256: digests[4],
            reservoir_bindings_sha256: Some(companion),
            lean_toolchain: TOOLCHAIN.to_owned(),
            compiler_githash: COMPILER.to_owned(),
            lake_version: LAKE.to_owned(),
            identity: v2_identity,
            lock_text: String::new(),
            manifest_text: String::new(),
            runtime_text: String::new(),
            packages: Vec::new(),
        };
        let metadata = String::from_utf8(
            generation
                .canonical_metadata()
                .unwrap_or_else(|error| panic!("metadata failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("metadata UTF-8 failed: {error}"));
        assert!(metadata.starts_with("leanbun-generation-v2\t2\n"));
        assert!(metadata.contains(&format!("reservoir-bindings-sha256\t{companion}\n")));
    }
}

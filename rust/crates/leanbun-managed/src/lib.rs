#![forbid(unsafe_code)]

mod dry_run;
mod external_acceptance;
mod fixture_regression;
mod history_regression;
mod negative_regression;
mod registered;
mod reservoir_regression;

pub use dry_run::{ExternalAdoptionDryRunV1, dry_run_external_adoption_v1};
pub use external_acceptance::{ExternalFixtureAcceptanceV1, run_external_fixture_acceptance_v1};
pub use fixture_regression::{
    ManagedDependencyRegressionV1, run_managed_dependency_regression_v1, run_mathlib_regression_v1,
};
pub use history_regression::{ConcurrentHistoryRegressionV1, run_concurrent_history_regression_v1};
pub use negative_regression::{NegativeFixtureRegressionV1, run_negative_fixture_regression_v1};
pub use reservoir_regression::{
    ReservoirLoopbackRegressionV1, run_reservoir_loopback_regression_v1,
};

use leanbun_build::{
    BuildErrorKind, SupervisedLakeBuildV1, project_artifact_sha256_v1,
    run_supervised_lake_build_v1, verify_active_generation_build_gate_v1,
    verify_lake_workspace_paths_v1,
};
use leanbun_core::{ExecutionId, ProjectId, Sha256, Sha256Hasher, project_id};
use leanbun_generation::{LeanBunGenerationV1, LeanGenerationFaultV1, LeanGenerationManagerV1};
use leanbun_lake_bridge::{
    LakeDependencySourceV1, LakeManifestProjectionV1, LakePackageProjectionMetadataV1,
    LakeRootDeclarationV1, LakeRootProbeRequestV1, LakeRuntimePackagesProjectionV1,
    run_lake_root_probe_v1,
};
use leanbun_lock::{
    LeanBunLockV1, LockedLeanPackageV1, PackageDependencyV1, PackageKeyV1,
    PackagePathDecisionSetV1, PackagePathDecisionV1, PackagePathProvenanceSetV1,
    PackagePathProvenanceV1, RequestedPackageSourceV1, ResolvedPackageSourceV1,
};
use leanbun_resolver::{
    LeanDependencyRequirementV1, LeanExactSourceV1, LeanPackageCandidateV1, LeanResolutionModeV1,
    LeanResolutionRequestV1, LeanSourceRequestV1, LeanToolchainIdentityV1,
    resolve_lean_dependencies_v1,
};
use leanbun_store::{
    LeanFetchCancellationV1, LeanFetchFaultV1, LeanFetchRequestV1, LeanFetchSourceV1,
    LeanImmutableStoreV1, LeanStoreLimitsV1, VerifiedPackageObjectV1,
    normalized_directory_tree_sha256_v1,
};
use registered::{RegisteredGitInputV1, load_registered_git_closure};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TOOLCHAIN: &str = "leanprover/lean4:v4.32.0";
const COMPILER: &str = "8c9756b28d64dab099da31a4c09229a9e6a2ef35";
const LAKE_VERSION: &str = "5.0.0-src+8c9756b";
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_INPUT_FILE_BYTES: u64 = 256 * 1024 * 1024;
static PROBE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedProjectErrorKind {
    BoundaryViolation,
    AlreadyAdopted,
    NotAdopted,
    UnsupportedDependencyGraph,
    InputDrift,
    PendingTransaction,
    NoPreviousGeneration,
    Store,
    Generation,
    Build,
    Io,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedProjectError {
    pub kind: ManagedProjectErrorKind,
    pub message: String,
}

impl fmt::Display for ManagedProjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ManagedProjectError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedProjectStatusV1 {
    pub project_id: ProjectId,
    pub project_root: PathBuf,
    pub target: String,
    pub active_transaction: ExecutionId,
    pub previous_transaction: Option<ExecutionId>,
    pub pending_transaction: Option<ExecutionId>,
    pub generation_sha256: Sha256,
    pub package_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedBuildResultV1 {
    pub generation_sha256: Sha256,
    pub project_artifact_sha256: Sha256,
}

#[derive(Clone, Debug)]
pub struct ManagedProjectControllerV1 {
    repository: PathBuf,
    project: PathBuf,
    development: PathBuf,
    authority: PathBuf,
    state: PathBuf,
    registry: PathBuf,
    supervisor: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedRecordV1 {
    project_id: ProjectId,
    project_root: PathBuf,
    target: String,
    management_input_sha256: Sha256,
    baseline_transaction: ExecutionId,
    active_transaction: ExecutionId,
    previous_transaction: Option<ExecutionId>,
    pending_transaction: Option<ExecutionId>,
}

impl ManagedProjectControllerV1 {
    pub fn open(
        repository: impl AsRef<Path>,
        project: impl AsRef<Path>,
        supervisor: impl AsRef<Path>,
    ) -> Result<Self, ManagedProjectError> {
        let repository = canonical_directory(repository.as_ref(), "repository")?;
        if !repository.join("TEST_PROJECT_BOUNDARY.adoc").is_file()
            || !repository.join("config/upstream-bun.lock.json").is_file()
        {
            return Err(boundary("repository is not a LeanBun source root"));
        }
        let project = canonical_directory(project.as_ref(), "managed project")?;
        let supervisor = canonical_file(supervisor.as_ref(), "LeanBun supervisor")?;
        let development =
            canonical_directory(&repository.join(".leanbun-dev"), "development root")?;
        let authority = repository.join(".leanbun-dev-rust/managed-projects");
        ensure_private_directory(&repository.join(".leanbun-dev-rust"), &authority)?;
        let authority = canonical_directory(&authority, "managed authority root")?;
        if project.starts_with(&authority) {
            return Err(boundary(
                "managed project cannot live inside its state authority root",
            ));
        }
        let state = authority.join("generation-state");
        let registry = authority.join("registry");
        ensure_private_directory(&authority, &state)?;
        ensure_private_directory(&authority, &registry)?;
        Ok(Self {
            repository,
            project,
            development,
            authority,
            state,
            registry,
            supervisor,
        })
    }

    pub fn adopt(&self, target: &str) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        self.adopt_with_fault(target, LeanGenerationFaultV1::None)
    }

    pub fn adopt_with_fault(
        &self,
        target: &str,
        fault: LeanGenerationFaultV1,
    ) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        validate_target(target)?;
        let record_path = self.record_path()?;
        if record_path.exists() {
            return Err(error(
                ManagedProjectErrorKind::AlreadyAdopted,
                "project already has a managed adoption record",
            ));
        }
        let model = self.model()?;
        let transaction = new_transaction(&self.project, b"adopt")?;
        let generation = model.generation(transaction)?;
        let preparing = ManagedRecordV1 {
            project_id: project_id(path_text(&self.project)?),
            project_root: self.project.clone(),
            target: target.to_owned(),
            management_input_sha256: model.management_input_sha256,
            baseline_transaction: transaction,
            active_transaction: transaction,
            previous_transaction: None,
            pending_transaction: Some(transaction),
        };
        create_record(&record_path, &preparing)?;
        model
            .manager
            .publish(&generation.generation, fault)
            .map_err(generation_error)?;
        let active = ManagedRecordV1 {
            pending_transaction: None,
            ..preparing
        };
        replace_record(&record_path, &active)?;
        self.status_from(&active, &generation.generation)
    }

    pub fn update(&self) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        self.update_with_fault(LeanGenerationFaultV1::None)
    }

    pub fn update_packages(
        &self,
        packages: &[String],
    ) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        let model = self.model()?;
        let available = model
            .lock
            .packages()
            .iter()
            .map(|package| package.key().name())
            .collect::<BTreeSet<_>>();
        let requested = packages.iter().map(String::as_str).collect::<BTreeSet<_>>();
        if requested.len() != packages.len() {
            return Err(boundary("managed update set contains a duplicate package"));
        }
        if !available.is_empty() && requested.is_empty() {
            return Err(boundary(
                "dependency-bearing managed update requires an explicit package set",
            ));
        }
        if let Some(package) = requested.difference(&available).next() {
            return Err(boundary(format!(
                "managed update names an unknown package: {package}"
            )));
        }
        self.update_with_fault(LeanGenerationFaultV1::None)
    }

    pub fn update_with_fault(
        &self,
        fault: LeanGenerationFaultV1,
    ) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        let mut record = self.read_record()?;
        if record.pending_transaction.is_some() {
            return Err(error(
                ManagedProjectErrorKind::PendingTransaction,
                "managed project has a pending transaction; recover first",
            ));
        }
        let model = self.model()?;
        require_model_identity(&record, &model)?;
        let current = model.generation(record.active_transaction)?;
        model
            .manager
            .verify_active_generation(&current.generation)
            .map_err(generation_error)?;
        let transaction = new_transaction(&self.project, b"update")?;
        let candidate = model.generation(transaction)?;
        record.pending_transaction = Some(transaction);
        replace_record(&self.record_path()?, &record)?;
        model
            .manager
            .publish(&candidate.generation, fault)
            .map_err(generation_error)?;
        record.previous_transaction = Some(record.active_transaction);
        record.active_transaction = transaction;
        record.pending_transaction = None;
        replace_record(&self.record_path()?, &record)?;
        self.status_from(&record, &candidate.generation)
    }

    pub fn recover(&self) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        let mut record = self.read_record()?;
        let Some(pending_transaction) = record.pending_transaction else {
            return Err(error(
                ManagedProjectErrorKind::PendingTransaction,
                "managed project has no pending transaction",
            ));
        };
        let model = self.model()?;
        require_model_identity(&record, &model)?;
        let pending = model.generation(pending_transaction)?;
        let active = model
            .manager
            .active_generation_reference()
            .map_err(generation_error)?;
        if active.is_none()
            && pending_transaction == record.baseline_transaction
            && pending_transaction == record.active_transaction
            && record.previous_transaction.is_none()
        {
            model
                .manager
                .recover(&pending.generation)
                .map_err(generation_error)?;
            fs::remove_file(self.record_path()?).map_err(io_error)?;
            sync_directory(&self.registry)?;
            return Err(error(
                ManagedProjectErrorKind::NotAdopted,
                "failed initial adoption was recovered and removed; adopt again explicitly",
            ));
        }
        if active
            .as_ref()
            .is_some_and(|active| active.generation_sha256 == pending.generation.identity())
        {
            model
                .manager
                .recover(&pending.generation)
                .map_err(generation_error)?;
            record.previous_transaction = Some(record.active_transaction);
            record.active_transaction = pending_transaction;
        } else {
            model
                .manager
                .recover(&pending.generation)
                .map_err(generation_error)?;
        }
        record.pending_transaction = None;
        replace_record(&self.record_path()?, &record)?;
        let current = model.generation(record.active_transaction)?;
        model
            .manager
            .verify_active_generation(&current.generation)
            .map_err(generation_error)?;
        self.status_from(&record, &current.generation)
    }

    pub fn rollback(&self) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        let mut record = self.read_record()?;
        if record.pending_transaction.is_some() {
            return Err(error(
                ManagedProjectErrorKind::PendingTransaction,
                "cannot roll back a managed project with a pending transaction",
            ));
        }
        let previous = record.previous_transaction.ok_or_else(|| {
            error(
                ManagedProjectErrorKind::NoPreviousGeneration,
                "managed project has no previous generation",
            )
        })?;
        let model = self.model()?;
        require_model_identity(&record, &model)?;
        let current = model.generation(record.active_transaction)?;
        let retained = model.generation(previous)?;
        model
            .manager
            .rollback_active_generation(&current.generation, &retained.generation)
            .map_err(generation_error)?;
        record.previous_transaction = Some(record.active_transaction);
        record.active_transaction = previous;
        replace_record(&self.record_path()?, &record)?;
        self.status_from(&record, &retained.generation)
    }

    pub fn build(&self) -> Result<ManagedBuildResultV1, ManagedProjectError> {
        let record = self.read_record()?;
        if record.pending_transaction.is_some() {
            return Err(error(
                ManagedProjectErrorKind::PendingTransaction,
                "cannot build while a managed transaction is pending",
            ));
        }
        let model = self.model()?;
        require_model_identity(&record, &model)?;
        let generation = model.generation(record.active_transaction)?;
        let paths = verify_active_generation_build_gate_v1(
            &model.manager,
            &generation.generation,
            &generation.decisions,
            &generation.runtime,
        )
        .map_err(build_error)?;
        model
            .manager
            .prepare_active_build_caches(&generation.generation)
            .map_err(generation_error)?;
        self.seed_registered_caches(&model, &generation)?;
        let request = self.build_request(&record, &generation.generation)?;
        verify_lake_workspace_paths_v1(&request, &paths).map_err(build_error)?;
        run_supervised_lake_build_v1(&request).map_err(build_error)?;
        let artifact =
            project_artifact_sha256_v1(&self.project.join(".lake/build")).map_err(build_error)?;
        Ok(ManagedBuildResultV1 {
            generation_sha256: generation.generation.identity(),
            project_artifact_sha256: artifact,
        })
    }

    pub fn status(&self) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        let record = self.read_record()?;
        let model = self.model()?;
        require_model_identity(&record, &model)?;
        let generation = model.generation(record.active_transaction)?;
        model
            .manager
            .verify_active_generation(&generation.generation)
            .map_err(generation_error)?;
        self.status_from(&record, &generation.generation)
    }

    fn model(&self) -> Result<ManagedModelV1, ManagedProjectError> {
        let declaration = self.probe_declaration()?;
        let config = self.project.join(declaration.config_file());
        let config_sha256 = hash_file(&config, MAX_INPUT_FILE_BYTES)?;
        let management_input_sha256 = management_input_sha256(
            &self.project,
            declaration.config_file(),
            declaration.identity(),
        )?;
        let mut candidates = Vec::new();
        let mut locked = Vec::new();
        let mut metadata = Vec::new();
        let mut sources = BTreeMap::<PackageKeyV1, (LeanFetchSourceV1, PathBuf)>::new();
        let mut registered_caches = BTreeMap::new();
        let has_git = declaration
            .dependencies()
            .iter()
            .any(|dependency| matches!(dependency.source(), LakeDependencySourceV1::Git { .. }));
        if has_git {
            if declaration.dependencies().iter().any(|dependency| {
                !matches!(dependency.source(), LakeDependencySourceV1::Git { .. })
            }) {
                return Err(error(
                    ManagedProjectErrorKind::UnsupportedDependencyGraph,
                    "managed root cannot mix registered Git and local path dependencies",
                ));
            }
            let inputs = load_registered_git_closure(
                &self.development,
                &self.project.join("lake-manifest.json"),
            )
            .map_err(input_error)?;
            let registered_requests = inputs
                .iter()
                .map(|input| Ok((input.key.clone(), input.request()?)))
                .collect::<Result<BTreeMap<_, _>, String>>()
                .map_err(input_error)?;
            for input in inputs {
                let dependencies = input
                    .dependencies
                    .iter()
                    .map(|key| {
                        registered_requests
                            .get(key)
                            .cloned()
                            .map(|request| LeanDependencyRequirementV1::new(key.clone(), request))
                            .ok_or_else(|| "registered dependency request is missing".to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(input_error)?;
                let package = registered_git_package(input.clone(), dependencies)?;
                sources.insert(
                    package.key.clone(),
                    (
                        LeanFetchSourceV1::LocalGit {
                            repository: input.directory.clone(),
                        },
                        self.development.join("lean/package-set/packages"),
                    ),
                );
                registered_caches.insert(package.key.clone(), input.directory);
                candidates.push(package.candidate);
                locked.push(package.locked);
                metadata.push(package.metadata);
            }
        } else {
            for dependency in declaration.dependencies() {
                let LakeDependencySourceV1::Path { directory } = dependency.source() else {
                    return Err(error(
                        ManagedProjectErrorKind::UnsupportedDependencyGraph,
                        "unsupported managed dependency source",
                    ));
                };
                let package =
                    local_path_package(&self.project, dependency.key().clone(), directory)?;
                sources.insert(
                    package.key.clone(),
                    (
                        LeanFetchSourceV1::LocalDirectory {
                            path: package.source,
                        },
                        self.project.clone(),
                    ),
                );
                candidates.push(package.candidate);
                locked.push(package.locked);
                metadata.push(package.metadata);
            }
        }
        let lock = LeanBunLockV1::new(
            TOOLCHAIN,
            COMPILER,
            LAKE_VERSION,
            config_sha256,
            declaration.identity(),
            locked,
        )
        .map_err(|error| input_error(error.to_string()))?;
        let request = LeanResolutionRequestV1::new(
            declaration.clone(),
            None,
            LeanResolutionModeV1::update(Vec::new())
                .map_err(|error| input_error(error.to_string()))?,
            LeanToolchainIdentityV1::new(TOOLCHAIN, COMPILER, LAKE_VERSION)
                .map_err(|error| input_error(error.to_string()))?,
        )
        .map_err(|error| input_error(error.to_string()))?;
        let graph = resolve_lean_dependencies_v1(&request, candidates)
            .map_err(|error| input_error(error.to_string()))?;
        let manifest = LakeManifestProjectionV1::new(&declaration, &lock, metadata.clone())
            .map_err(|error| input_error(error.to_string()))?;
        let store = LeanImmutableStoreV1::open(
            &self.development,
            self.development
                .join("store-fixture/m40-managed")
                .join(project_id(path_text(&self.project)?).to_string()),
        )
        .map_err(store_error)?;
        let mut fetches = Vec::with_capacity(sources.len());
        for (package, (source, allowed_root)) in sources {
            let limits = if matches!(source, LeanFetchSourceV1::LocalGit { .. }) {
                LeanStoreLimitsV1::registered_provider()
            } else {
                LeanStoreLimitsV1::default()
            };
            let fetch =
                LeanFetchRequestV1::from_graph(&graph, &package, source, allowed_root, limits)
                    .map_err(store_error)?;
            fetches.push(fetch);
        }
        let objects = thread::scope(|scope| {
            let handles = fetches
                .into_iter()
                .map(|fetch| {
                    let store = store.clone();
                    scope.spawn(move || {
                        store.fetch_and_publish(
                            &fetch,
                            &LeanFetchCancellationV1::default(),
                            LeanFetchFaultV1::None,
                        )
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| input_error("managed package fetch worker panicked"))?
                        .map_err(store_error)
                })
                .collect::<Result<Vec<_>, ManagedProjectError>>()
        })?;
        let manager =
            LeanGenerationManagerV1::open_managed(&self.authority, &self.state, &self.project)
                .map_err(generation_error)?;
        Ok(ManagedModelV1 {
            project: self.project.clone(),
            manager,
            lock,
            graph,
            manifest,
            metadata,
            objects,
            registered_caches,
            management_input_sha256,
        })
    }

    fn probe_declaration(&self) -> Result<LakeRootDeclarationV1, ManagedProjectError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| input_error(format!("system clock precedes epoch: {error}")))?
            .as_nanos();
        let counter = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let staging = self.development.join(format!(
            "tmp/m39-managed-probe-{}-{nonce}-{counter}",
            std::process::id()
        ));
        let cleanup = Cleanup(staging.clone());
        let toolchain = self
            .development
            .join("lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
        let source_root = self
            .project
            .parent()
            .ok_or_else(|| boundary("managed project has no source parent"))?;
        let request = LakeRootProbeRequestV1 {
            source_fixture_root: source_root.to_path_buf(),
            source_project: self.project.clone(),
            development_root: self.development.clone(),
            staging_directory: staging,
            lean_executable: toolchain.join("bin/lean"),
            elan_home: self.development.join("lean/elan-home"),
            sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
            sandbox_profile: self.repository.join("config/leanbun-dev.sb"),
            probe_source: self.repository.join("lean/probes/M32RootDeclarations.lean"),
            lake_source_root: toolchain.join("src/lean/lake"),
        };
        let declaration = run_lake_root_probe_v1(&request)
            .map_err(|error| input_error(format!("Lake declaration probe failed: {error}")))?;
        drop(cleanup);
        Ok(declaration)
    }

    fn build_request(
        &self,
        record: &ManagedRecordV1,
        generation: &LeanBunGenerationV1,
    ) -> Result<SupervisedLakeBuildV1, ManagedProjectError> {
        let toolchain = self
            .development
            .join("lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
        let lake = canonical_file(&toolchain.join("bin/lake"), "Lake executable")?;
        let profile = self
            .project_state_root()?
            .join(format!("build-{}.sb", generation.identity()));
        let mut writable = vec![self.project.clone()];
        writable.extend(
            generation
                .package_paths()
                .into_iter()
                .map(|package| package.join(".lake")),
        );
        let mut profile_text = String::from(
            "(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n(allow file-write*",
        );
        for path in writable {
            profile_text.push_str(&format!(" (subpath {:?})", path.to_string_lossy()));
        }
        profile_text.push_str(
            " (literal \"/dev/null\") (literal \"/dev/stdout\") (literal \"/dev/stderr\"))\n",
        );
        if profile.exists() {
            if fs::read_to_string(&profile).map_err(io_error)? != profile_text {
                return Err(input_error("managed build sandbox profile drifted"));
            }
        } else {
            create_bytes(&profile, profile_text.as_bytes())?;
        }
        Ok(SupervisedLakeBuildV1 {
            supervisor_executable: self.supervisor.clone(),
            sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
            sandbox_profile_sha256: hash_file(&profile, 1024 * 1024)?,
            sandbox_profile: profile,
            lake_executable_sha256: hash_file(&lake, 128 * 1024 * 1024)?,
            lake_executable: lake,
            cwd: self.project.clone(),
            runtime_packages: generation.generation_root().join("runtime-packages.json"),
            target: record.target.clone(),
            allowed_targets: BTreeSet::from([record.target.clone()]),
            environment: build_environment(&toolchain, &self.project),
            deadline: Duration::from_secs(120),
            termination_grace: Duration::from_secs(1),
            maximum_output_bytes: 16 * 1024 * 1024,
        })
    }

    fn status_from(
        &self,
        record: &ManagedRecordV1,
        generation: &LeanBunGenerationV1,
    ) -> Result<ManagedProjectStatusV1, ManagedProjectError> {
        Ok(ManagedProjectStatusV1 {
            project_id: record.project_id,
            project_root: record.project_root.clone(),
            target: record.target.clone(),
            active_transaction: record.active_transaction,
            previous_transaction: record.previous_transaction,
            pending_transaction: record.pending_transaction,
            generation_sha256: generation.identity(),
            package_count: generation.package_count(),
        })
    }

    fn read_record(&self) -> Result<ManagedRecordV1, ManagedProjectError> {
        let path = self.record_path()?;
        if !path.exists() {
            return Err(error(
                ManagedProjectErrorKind::NotAdopted,
                "project has not been explicitly adopted",
            ));
        }
        parse_record(&stable_read(&path, MAX_RECORD_BYTES)?)
    }

    fn record_path(&self) -> Result<PathBuf, ManagedProjectError> {
        Ok(self
            .registry
            .join(format!("{}.record", project_id(path_text(&self.project)?))))
    }

    fn project_state_root(&self) -> Result<PathBuf, ManagedProjectError> {
        let root = self
            .authority
            .join("project-control")
            .join(project_id(path_text(&self.project)?).to_string());
        ensure_private_directory(&self.authority, &root)?;
        Ok(root)
    }

    fn seed_registered_caches(
        &self,
        model: &ManagedModelV1,
        generation: &ManagedGenerationV1,
    ) -> Result<(), ManagedProjectError> {
        for (package, source) in &model.registered_caches {
            let decision = generation
                .decisions
                .decisions()
                .iter()
                .find(|decision| decision.package() == package)
                .ok_or_else(|| input_error("registered cache lacks a Bun path decision"))?;
            let final_path = PathBuf::from(decision.final_path());
            if package.scope() == "leanprover-community" && package.name() == "proofwidgets" {
                seed_registered_derived_file(
                    &source.join("widget/package-lock.json.hash"),
                    &final_path.join("widget/package-lock.json.hash"),
                )?;
            }
            let source = source.join(".lake/build");
            if !source.is_dir() {
                // A registered source is authoritative independently of whether
                // Lake has already published a derived cache for it. Missing
                // caches are built inside the active generation.
                continue;
            }
            let destination = final_path.join(".lake/build");
            if destination.exists() {
                if !destination.is_dir() {
                    return Err(input_error(
                        "generation dependency cache is not a directory",
                    ));
                }
                continue;
            }
            let status = Command::new("/bin/cp")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .args(["-c", "-R"])
                .arg(&source)
                .arg(&destination)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(io_error)?;
            if !status.success() || !destination.is_dir() {
                return Err(error(
                    ManagedProjectErrorKind::Build,
                    format!(
                        "cannot clone registered dependency cache for {}/{}",
                        package.scope(),
                        package.name()
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn seed_registered_derived_file(
    source: &Path,
    destination: &Path,
) -> Result<(), ManagedProjectError> {
    let source_metadata = fs::symlink_metadata(source).map_err(io_error)?;
    if !source_metadata.file_type().is_file() || source_metadata.len() > 64 * 1024 {
        return Err(input_error(
            "registered derived cache is not a bounded regular file",
        ));
    }
    let expected = hash_file(source, 64 * 1024)?;
    if destination.exists() {
        if hash_file(destination, 64 * 1024)? != expected {
            return Err(input_error("registered derived cache digest differs"));
        }
        return Ok(());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| input_error("registered derived cache has no parent"))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).map_err(io_error)?;
    let copy = Command::new("/bin/cp")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["-c", "-p"])
        .arg(source)
        .arg(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(io_error);
    fs::set_permissions(parent, fs::Permissions::from_mode(0o555)).map_err(io_error)?;
    let copy = copy?;
    if !copy.success() || hash_file(destination, 64 * 1024)? != expected {
        return Err(error(
            ManagedProjectErrorKind::Build,
            "cannot clone registered derived cache",
        ));
    }
    fs::set_permissions(destination, fs::Permissions::from_mode(0o444)).map_err(io_error)
}

struct ManagedModelV1 {
    project: PathBuf,
    manager: LeanGenerationManagerV1,
    lock: LeanBunLockV1,
    graph: leanbun_resolver::LeanResolutionGraphV1,
    manifest: LakeManifestProjectionV1,
    metadata: Vec<LakePackageProjectionMetadataV1>,
    objects: Vec<VerifiedPackageObjectV1>,
    registered_caches: BTreeMap<PackageKeyV1, PathBuf>,
    management_input_sha256: Sha256,
}

struct ManagedGenerationV1 {
    generation: LeanBunGenerationV1,
    decisions: PackagePathDecisionSetV1,
    runtime: LakeRuntimePackagesProjectionV1,
}

impl ManagedModelV1 {
    fn generation(
        &self,
        transaction: ExecutionId,
    ) -> Result<ManagedGenerationV1, ManagedProjectError> {
        let generation_root = self.manager.generation_root(transaction);
        let generation_root_text = path_text(&generation_root)?;
        let mut decisions = Vec::with_capacity(self.lock.packages().len());
        for object in &self.objects {
            let locked = self
                .lock
                .packages()
                .iter()
                .find(|locked| locked.key() == object.package())
                .ok_or_else(|| input_error("store object is absent from managed lock"))?;
            let provenance = PackagePathProvenanceSetV1::new(vec![
                PackagePathProvenanceV1::bun_generated_runtime(
                    object.package().clone(),
                    locked.selected_source_identity(),
                ),
            ])
            .map_err(|error| input_error(error.to_string()))?;
            let final_path = generation_package_path(&generation_root, object.package());
            decisions.push(
                PackagePathDecisionV1::new(
                    object.package().clone(),
                    &provenance,
                    locked.selected_source_identity(),
                    generation_root_text,
                    path_text(&final_path)?,
                    object.store_object_sha256(),
                    object.source_tree_sha256(),
                    self.graph.identity(),
                )
                .map_err(|error| input_error(error.to_string()))?,
            );
        }
        let decisions = PackagePathDecisionSetV1::new(&self.lock, decisions)
            .map_err(|error| input_error(error.to_string()))?;
        let runtime = LakeRuntimePackagesProjectionV1::from_bun_decisions(
            &self.lock,
            &decisions,
            self.metadata.clone(),
        )
        .map_err(|error| input_error(error.to_string()))?;
        let generation = LeanBunGenerationV1::new(
            transaction,
            &self.project,
            generation_root,
            &self.lock,
            &self.graph,
            &decisions,
            &self.manifest,
            &runtime,
            self.objects.clone(),
        )
        .map_err(generation_error)?;
        Ok(ManagedGenerationV1 {
            generation,
            decisions,
            runtime,
        })
    }
}

struct LocalPathPackageV1 {
    key: PackageKeyV1,
    source: PathBuf,
    candidate: LeanPackageCandidateV1,
    locked: LockedLeanPackageV1,
    metadata: LakePackageProjectionMetadataV1,
}

fn registered_git_package(
    input: RegisteredGitInputV1,
    dependencies: Vec<LeanDependencyRequirementV1>,
) -> Result<LocalPathPackageV1, ManagedProjectError> {
    let candidate = LeanPackageCandidateV1::new(
        input.key.clone(),
        input.request().map_err(input_error)?,
        LeanExactSourceV1::git(
            input.url.clone(),
            input.revision.clone(),
            input.subdir.clone(),
        )
        .map_err(|error| input_error(error.to_string()))?,
        dependencies.clone(),
        None,
        Some(input.download_sha256),
        input.tree_sha256,
        input.config_sha256,
        input.manifest_sha256,
        input.selected_source_identity,
    )
    .map_err(|error| input_error(error.to_string()))?;
    let provenance =
        PackagePathProvenanceSetV1::new(vec![PackagePathProvenanceV1::workspace_override(
            input.key.clone(),
            input.selected_source_identity,
        )])
        .map_err(|error| input_error(error.to_string()))?;
    let locked_dependencies = dependencies
        .iter()
        .map(|dependency| PackageDependencyV1::new(dependency.key().clone()))
        .collect();
    let locked = LockedLeanPackageV1::new(
        input.key.clone(),
        RequestedPackageSourceV1::git(input.url.clone(), input.input_revision.clone())
            .map_err(|error| input_error(error.to_string()))?,
        ResolvedPackageSourceV1::git(input.url, input.revision, input.subdir)
            .map_err(|error| input_error(error.to_string()))?,
        Some(input.download_sha256),
        input.tree_sha256,
        input.config_sha256,
        input.manifest_sha256,
        locked_dependencies,
        vec![provenance.digest()],
        input.selected_source_identity,
    )
    .map_err(|error| input_error(error.to_string()))?;
    let metadata = LakePackageProjectionMetadataV1::new(
        input.key.clone(),
        input.inherited,
        input.config_file,
        input.manifest_file,
        input.input_revision,
    )
    .map_err(|error| input_error(error.to_string()))?;
    Ok(LocalPathPackageV1 {
        key: input.key,
        source: input.directory,
        candidate,
        locked,
        metadata,
    })
}

fn local_path_package(
    project: &Path,
    key: PackageKeyV1,
    portable_path: &str,
) -> Result<LocalPathPackageV1, ManagedProjectError> {
    let source = canonical_directory(&project.join(portable_path), "local dependency source")?;
    if !source.starts_with(project) {
        return Err(boundary(
            "local dependency source escaped the managed project",
        ));
    }
    let config_file = match (
        source.join("lakefile.toml").is_file(),
        source.join("lakefile.lean").is_file(),
    ) {
        (true, false) => "lakefile.toml",
        (false, true) => "lakefile.lean",
        _ => {
            return Err(input_error(
                "local dependency must contain exactly one Lake config file",
            ));
        }
    };
    if source.join("lake-manifest.json").exists() {
        return Err(error(
            ManagedProjectErrorKind::UnsupportedDependencyGraph,
            "M40 local snapshot dependency must have no transitive manifest",
        ));
    }
    let tree = normalized_directory_tree_sha256_v1(&source, LeanStoreLimitsV1::default())
        .map_err(store_error)?;
    let config = hash_file(&source.join(config_file), MAX_INPUT_FILE_BYTES)?;
    let mut identity = Sha256Hasher::new();
    identity.update(b"leanbun-managed-local-source-v1\0");
    identity.update(&(portable_path.len() as u64).to_be_bytes());
    identity.update(portable_path.as_bytes());
    identity.update(tree.as_bytes());
    let selected = identity.finalize();
    let candidate = LeanPackageCandidateV1::new(
        key.clone(),
        LeanSourceRequestV1::path(portable_path).map_err(|error| input_error(error.to_string()))?,
        LeanExactSourceV1::path(portable_path, selected)
            .map_err(|error| input_error(error.to_string()))?,
        Vec::new(),
        None,
        None,
        tree,
        config,
        None,
        selected,
    )
    .map_err(|error| input_error(error.to_string()))?;
    let provenance = PackagePathProvenanceSetV1::new(vec![PackagePathProvenanceV1::manifest(
        key.clone(),
        selected,
    )])
    .map_err(|error| input_error(error.to_string()))?;
    let locked = LockedLeanPackageV1::new(
        key.clone(),
        RequestedPackageSourceV1::path_snapshot(portable_path)
            .map_err(|error| input_error(error.to_string()))?,
        ResolvedPackageSourceV1::path_snapshot(portable_path)
            .map_err(|error| input_error(error.to_string()))?,
        None,
        tree,
        config,
        None,
        Vec::new(),
        vec![provenance.digest()],
        selected,
    )
    .map_err(|error| input_error(error.to_string()))?;
    let metadata =
        LakePackageProjectionMetadataV1::new(key.clone(), false, config_file, None, None)
            .map_err(|error| input_error(error.to_string()))?;
    Ok(LocalPathPackageV1 {
        key,
        source,
        candidate,
        locked,
        metadata,
    })
}

fn generation_package_path(root: &Path, key: &PackageKeyV1) -> PathBuf {
    let mut path = root.join("packages");
    if !key.scope().is_empty() {
        path.push(key.scope());
    }
    path.push(key.name());
    path
}

fn require_model_identity(
    record: &ManagedRecordV1,
    model: &ManagedModelV1,
) -> Result<(), ManagedProjectError> {
    if record.management_input_sha256 != model.management_input_sha256 {
        return Err(input_error(
            "managed configuration/toolchain changed; explicit migration is required",
        ));
    }
    Ok(())
}

fn management_input_sha256(
    project: &Path,
    config_name: &str,
    declaration: Sha256,
) -> Result<Sha256, ManagedProjectError> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-managed-input-v1\0");
    hasher.update(declaration.as_bytes());
    for relative in [config_name, "lean-toolchain", "lake-manifest.json"] {
        if relative == "lake-manifest.json" && !project.join(relative).exists() {
            continue;
        }
        let digest = hash_file(&project.join(relative), MAX_INPUT_FILE_BYTES)?;
        hasher.update(&(relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(digest.as_bytes());
    }
    Ok(hasher.finalize())
}

fn build_environment(toolchain: &Path, project: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "PATH".to_owned(),
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                toolchain.join("bin").display()
            ),
        ),
        ("HOME".to_owned(), project.to_string_lossy().into_owned()),
        ("TMPDIR".to_owned(), project.to_string_lossy().into_owned()),
        (
            "LEAN_SYSROOT".to_owned(),
            toolchain.to_string_lossy().into_owned(),
        ),
        (
            "DYLD_LIBRARY_PATH".to_owned(),
            toolchain.join("lib/lean").to_string_lossy().into_owned(),
        ),
        ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("DO_NOT_TRACK".to_owned(), "1".to_owned()),
        ("LAKE_NO_CACHE".to_owned(), "1".to_owned()),
        ("LAKE_ARTIFACT_CACHE".to_owned(), "0".to_owned()),
    ])
}

fn record_bytes(record: &ManagedRecordV1) -> Result<Vec<u8>, ManagedProjectError> {
    Ok(format!(
        "leanbun-managed-project-v1\t1\nproject-id\t{}\nproject-root\t{}\ntarget\t{}\nmanagement-input-sha256\t{}\nbaseline-transaction\t{}\nactive-transaction\t{}\nprevious-transaction\t{}\npending-transaction\t{}\nend-managed-project\n",
        record.project_id,
        path_text(&record.project_root)?,
        record.target,
        record.management_input_sha256,
        record.baseline_transaction,
        record.active_transaction,
        record.previous_transaction.map_or("-".to_owned(), |value| value.to_string()),
        record.pending_transaction.map_or("-".to_owned(), |value| value.to_string()),
    )
    .into_bytes())
}

fn parse_record(bytes: &[u8]) -> Result<ManagedRecordV1, ManagedProjectError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| input_error("managed record is not UTF-8"))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 10
        || lines[0] != "leanbun-managed-project-v1\t1"
        || lines[9] != "end-managed-project"
    {
        return Err(input_error("managed record shape is invalid"));
    }
    let record = ManagedRecordV1 {
        project_id: ProjectId::parse(field(lines[1], "project-id")?)
            .map_err(|error| input_error(error.to_string()))?,
        project_root: PathBuf::from(field(lines[2], "project-root")?),
        target: field(lines[3], "target")?.to_owned(),
        management_input_sha256: Sha256::parse(field(lines[4], "management-input-sha256")?)
            .map_err(|error| input_error(error.to_string()))?,
        baseline_transaction: parse_transaction(field(lines[5], "baseline-transaction")?)?,
        active_transaction: parse_transaction(field(lines[6], "active-transaction")?)?,
        previous_transaction: parse_optional_transaction(field(lines[7], "previous-transaction")?)?,
        pending_transaction: parse_optional_transaction(field(lines[8], "pending-transaction")?)?,
    };
    validate_target(&record.target)?;
    if record_bytes(&record)? != bytes {
        return Err(input_error("managed record is not canonical"));
    }
    Ok(record)
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str, ManagedProjectError> {
    line.strip_prefix(name)
        .and_then(|value| value.strip_prefix('\t'))
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| input_error(format!("managed record field is invalid: {name}")))
}

fn parse_transaction(value: &str) -> Result<ExecutionId, ManagedProjectError> {
    ExecutionId::parse(value).map_err(|error| input_error(error.to_string()))
}

fn parse_optional_transaction(value: &str) -> Result<Option<ExecutionId>, ManagedProjectError> {
    if value == "-" {
        Ok(None)
    } else {
        parse_transaction(value).map(Some)
    }
}

fn create_record(path: &Path, record: &ManagedRecordV1) -> Result<(), ManagedProjectError> {
    if path.exists() {
        return Err(error(
            ManagedProjectErrorKind::AlreadyAdopted,
            "managed adoption record already exists",
        ));
    }
    create_bytes(path, &record_bytes(record)?)
}

fn replace_record(path: &Path, record: &ManagedRecordV1) -> Result<(), ManagedProjectError> {
    let parent = path
        .parent()
        .ok_or_else(|| boundary("record has no parent"))?;
    let next = parent.join(format!(
        ".managed-{}-{}.next",
        std::process::id(),
        now_nanos()?
    ));
    create_bytes(&next, &record_bytes(record)?)?;
    fs::rename(&next, path).map_err(io_error)?;
    sync_directory(parent)?;
    if stable_read(path, MAX_RECORD_BYTES)? != record_bytes(record)? {
        return Err(input_error("managed record changed after publication"));
    }
    Ok(())
}

fn create_bytes(path: &Path, bytes: &[u8]) -> Result<(), ManagedProjectError> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| boundary("file has no parent"))?,
    )
}

fn stable_read(path: &Path, maximum: u64) -> Result<Vec<u8>, ManagedProjectError> {
    let before = fs::symlink_metadata(path).map_err(io_error)?;
    if !before.file_type().is_file() || before.len() > maximum {
        return Err(input_error("managed record is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(io_error)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let after = fs::symlink_metadata(path).map_err(io_error)?;
    use std::os::unix::fs::MetadataExt;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(input_error("managed record changed while reading"));
    }
    Ok(bytes)
}

fn new_transaction(project: &Path, domain: &[u8]) -> Result<ExecutionId, ManagedProjectError> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-managed-transaction-v1\0");
    hasher.update(domain);
    hasher.update(path_text(project)?.as_bytes());
    hasher.update(&now_nanos()?.to_be_bytes());
    hasher.update(&std::process::id().to_be_bytes());
    let mut bytes = *hasher.finalize().as_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let value = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    );
    ExecutionId::parse(&value).map_err(|error| input_error(error.to_string()))
}

fn now_nanos() -> Result<u128, ManagedProjectError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|error| input_error(format!("system clock precedes epoch: {error}")))
}

fn hash_file(path: &Path, maximum: u64) -> Result<Sha256, ManagedProjectError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(boundary(format!(
            "input is not a bounded regular file: {}",
            path.display()
        )));
    }
    let bytes = fs::read(path).map_err(io_error)?;
    let mut hasher = Sha256Hasher::new();
    hasher.update(&bytes);
    Ok(hasher.finalize())
}

fn ensure_private_directory(base: &Path, target: &Path) -> Result<(), ManagedProjectError> {
    let relative = target
        .strip_prefix(base)
        .map_err(|_| boundary("private directory escaped its base"))?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(boundary("private directory is not normalized"));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(boundary("private directory contains a symlink or file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(io_error)?;
            }
            Err(error) => return Err(io_error(error)),
        }
        fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, ManagedProjectError> {
    let canonical = path
        .canonicalize()
        .map_err(|error| boundary(format!("cannot canonicalize {label}: {error}")))?;
    if !canonical.is_dir() {
        return Err(boundary(format!("{label} is not a directory")));
    }
    Ok(canonical)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, ManagedProjectError> {
    let canonical = path
        .canonicalize()
        .map_err(|error| boundary(format!("cannot canonicalize {label}: {error}")))?;
    if !canonical.is_file() {
        return Err(boundary(format!("{label} is not a file")));
    }
    Ok(canonical)
}

fn validate_target(value: &str) -> Result<(), ManagedProjectError> {
    leanbun_core::BuildTarget::parse(value)
        .map(|_| ())
        .map_err(|error| boundary(error.to_string()))
}

fn path_text(path: &Path) -> Result<&str, ManagedProjectError> {
    path.to_str().ok_or_else(|| boundary("path is not UTF-8"))
}

fn sync_directory(path: &Path) -> Result<(), ManagedProjectError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

fn generation_error(error: leanbun_generation::LeanGenerationError) -> ManagedProjectError {
    error_with(
        ManagedProjectErrorKind::Generation,
        format!("generation rejected: {error}"),
    )
}

fn store_error(error: leanbun_store::LeanStoreError) -> ManagedProjectError {
    error_with(
        ManagedProjectErrorKind::Store,
        format!("immutable store rejected: {error}"),
    )
}

fn build_error(error: leanbun_build::BuildError) -> ManagedProjectError {
    let kind = if error.kind == BuildErrorKind::InputDrift {
        ManagedProjectErrorKind::InputDrift
    } else {
        ManagedProjectErrorKind::Build
    };
    error_with(kind, format!("managed build rejected: {error}"))
}

fn input_error(message: impl Into<String>) -> ManagedProjectError {
    error(ManagedProjectErrorKind::InputDrift, message)
}

fn boundary(message: impl Into<String>) -> ManagedProjectError {
    error(ManagedProjectErrorKind::BoundaryViolation, message)
}

fn io_error(error: std::io::Error) -> ManagedProjectError {
    error_with(
        ManagedProjectErrorKind::Io,
        format!("managed project I/O failed: {error}"),
    )
}

fn error(kind: ManagedProjectErrorKind, message: impl Into<String>) -> ManagedProjectError {
    error_with(kind, message)
}

fn error_with(kind: ManagedProjectErrorKind, message: impl Into<String>) -> ManagedProjectError {
    ManagedProjectError {
        kind,
        message: message.into(),
    }
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

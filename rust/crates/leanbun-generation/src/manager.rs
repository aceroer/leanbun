use crate::model::{
    GenerationPackageV1, LeanBunGenerationV1, LeanGenerationError, LeanGenerationErrorKind,
    LeanGenerationFaultV1, LeanGenerationOutcomeV1, LeanGenerationRecoveryV1,
    LeanGenerationStateV1,
};
use leanbun_core::{ExecutionId, ProjectId, Sha256, Sha256Hasher};
use leanbun_store::{
    LeanStoreLimitsV1, NormalizedTreeEntryKindV1, normalized_directory_tree_sha256_v1,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_RECORD_BYTES: u64 = 2 * 1_024 * 1_024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct LeanGenerationManagerV1 {
    development_root: PathBuf,
    state_root: PathBuf,
    project_root: PathBuf,
    project_id: ProjectId,
    project_state: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveGenerationRefV1 {
    pub transaction_id: ExecutionId,
    pub generation_sha256: Sha256,
    pub generation_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransactionRecord {
    transaction: ExecutionId,
    project: ProjectId,
    generation: Sha256,
    state: LeanGenerationStateV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveRecord {
    transaction: ExecutionId,
    generation: Sha256,
    path: PathBuf,
}

impl LeanGenerationManagerV1 {
    pub fn open(
        development_root: impl AsRef<Path>,
        state_root: impl AsRef<Path>,
        project_root: impl AsRef<Path>,
    ) -> Result<Self, LeanGenerationError> {
        let development_root = development_root
            .as_ref()
            .canonicalize()
            .map_err(boundary_error)?;
        let fixture_root = development_root.join("generation-fixture");
        ensure_private_descendant(&development_root, &fixture_root)?;
        let fixture_root = fixture_root.canonicalize().map_err(boundary_error)?;
        let requested_state = normalized_absolute(state_root.as_ref())?;
        let requested_project = normalized_absolute(project_root.as_ref())?;
        if !requested_state.starts_with(&fixture_root)
            || !requested_project.starts_with(&fixture_root)
        {
            return Err(boundary(
                "M35 state and project roots must stay in generation-fixture",
            ));
        }
        ensure_private_descendant(&fixture_root, &requested_state)?;
        ensure_private_descendant(&fixture_root, &requested_project)?;
        let state_root = requested_state.canonicalize().map_err(boundary_error)?;
        let project_root = requested_project.canonicalize().map_err(boundary_error)?;
        if !state_root.starts_with(&fixture_root) || !project_root.starts_with(&fixture_root) {
            return Err(boundary("canonical M35 root escaped generation-fixture"));
        }
        Self::finish_open(development_root, state_root, project_root)
    }

    /// Opens the generation engine for an explicitly managed project whose
    /// source may live outside LeanBun state. All writer paths remain below
    /// `management_root`; `project_root` is canonicalized but never created or
    /// modified by this constructor.
    pub fn open_managed(
        management_root: impl AsRef<Path>,
        state_root: impl AsRef<Path>,
        project_root: impl AsRef<Path>,
    ) -> Result<Self, LeanGenerationError> {
        let management_root = management_root
            .as_ref()
            .canonicalize()
            .map_err(boundary_error)?;
        let requested_state = normalized_absolute(state_root.as_ref())?;
        if !requested_state.starts_with(&management_root) || requested_state == management_root {
            return Err(boundary(
                "managed generation state must be a child of its private authority root",
            ));
        }
        ensure_private_descendant(&management_root, &requested_state)?;
        let state_root = requested_state.canonicalize().map_err(boundary_error)?;
        if !state_root.starts_with(&management_root) || state_root == management_root {
            return Err(boundary(
                "canonical managed generation state escaped its authority root",
            ));
        }
        let project_root = normalized_absolute(project_root.as_ref())?
            .canonicalize()
            .map_err(boundary_error)?;
        if !project_root.is_dir() || project_root.starts_with(&state_root) {
            return Err(boundary(
                "managed project must be a canonical directory outside generation state",
            ));
        }
        Self::finish_open(management_root, state_root, project_root)
    }

    fn finish_open(
        development_root: PathBuf,
        state_root: PathBuf,
        project_root: PathBuf,
    ) -> Result<Self, LeanGenerationError> {
        let project_text = path_text(&project_root)?;
        let project_id = leanbun_core::project_id(project_text);
        let project_state = state_root.join("projects").join(project_id.to_string());
        ensure_private_descendant(&state_root, &project_state)?;
        for child in ["generations", "transactions"] {
            ensure_private_descendant(&project_state, &project_state.join(child))?;
        }
        Ok(Self {
            development_root,
            state_root,
            project_root,
            project_id,
            project_state,
        })
    }

    #[must_use]
    pub fn development_root(&self) -> &Path {
        &self.development_root
    }
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
    #[must_use]
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }
    #[must_use]
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Re-verifies that `generation` is the exact active, published generation.
    ///
    /// M36 uses this read-only gate immediately before it projects any build
    /// inputs.  It deliberately performs no recovery and never changes the
    /// active record.
    pub fn verify_active_generation(
        &self,
        generation: &LeanBunGenerationV1,
    ) -> Result<(), LeanGenerationError> {
        self.validate_generation_location(generation)?;
        let active = self
            .read_active_optional()?
            .ok_or_else(|| drift("active generation record is missing"))?;
        if active.transaction != generation.transaction_id()
            || active.generation != generation.identity()
            || active.path != generation.generation_root()
        {
            return Err(drift(
                "active generation record does not match requested generation",
            ));
        }
        let transaction = self
            .read_transaction_optional(generation.transaction_id())?
            .ok_or_else(|| drift("active generation transaction record is missing"))?;
        if transaction.project != generation.project_id()
            || transaction.generation != generation.identity()
            || transaction.state != LeanGenerationStateV1::Published
        {
            return Err(drift("active generation transaction is not published"));
        }
        self.verify_generation(generation)
    }

    /// Creates the only writable portion of each active package: its derived
    /// Lake cache. Source entries remain read-only and are reverified while
    /// `.lake` is treated as non-authoritative build output.
    pub fn prepare_active_build_caches(
        &self,
        generation: &LeanBunGenerationV1,
    ) -> Result<Vec<PathBuf>, LeanGenerationError> {
        self.verify_active_generation(generation)?;
        let mut caches = Vec::with_capacity(generation.packages.len());
        for package in &generation.packages {
            let cache = package.final_path.join(".lake");
            if cache.exists() {
                let metadata = fs::symlink_metadata(&cache).map_err(io_error)?;
                if !metadata.file_type().is_dir() {
                    return Err(drift("package build cache is not a directory"));
                }
            } else {
                set_mode(&package.final_path, 0o755)?;
                let created = fs::create_dir(&cache).map_err(io_error);
                let resealed = set_mode(&package.final_path, 0o555);
                created?;
                resealed?;
            }
            set_mode(&cache, 0o700)?;
            caches.push(cache);
        }
        Ok(caches)
    }
    #[must_use]
    pub fn generation_root(&self, transaction: ExecutionId) -> PathBuf {
        self.project_state
            .join("generations")
            .join(transaction.as_str())
    }

    pub fn publish(
        &self,
        generation: &LeanBunGenerationV1,
        fault: LeanGenerationFaultV1,
    ) -> Result<LeanGenerationOutcomeV1, LeanGenerationError> {
        self.validate_generation_location(generation)?;
        self.acquire_lock(generation)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterLock,
            "after project lock",
        )?;
        self.create_transaction_record(generation, LeanGenerationStateV1::Preparing)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterPreparing,
            "after preparing record",
        )?;
        self.materialize_generation(generation, fault)?;
        self.transition(generation, LeanGenerationStateV1::Materialized)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterMaterialized,
            "after materialized record",
        )?;
        self.verify_generation(generation)?;
        self.transition(generation, LeanGenerationStateV1::Verified)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterVerified,
            "after verified record",
        )?;
        self.publish_active(generation, fault)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterActiveRename,
            "after active rename",
        )?;
        self.transition(generation, LeanGenerationStateV1::Published)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterPublishedRecord,
            "after published record",
        )?;
        self.update_retained(generation)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterRetainedRecord,
            "after retained record",
        )?;
        inject(
            fault,
            LeanGenerationFaultV1::BeforeLockRelease,
            "before project lock release",
        )?;
        self.release_lock(generation)?;
        Ok(outcome(generation, LeanGenerationStateV1::Published))
    }

    pub fn recover(
        &self,
        generation: &LeanBunGenerationV1,
    ) -> Result<LeanGenerationRecoveryV1, LeanGenerationError> {
        self.validate_generation_location(generation)?;
        let transaction = self.read_transaction_optional(generation.transaction_id())?;
        let active = self.read_active_optional()?;
        let is_active = active.as_ref().is_some_and(|record| {
            record.transaction == generation.transaction_id()
                && record.generation == generation.identity()
                && record.path == generation.generation_root()
        });
        if active
            .as_ref()
            .is_some_and(|record| record.transaction == generation.transaction_id() && !is_active)
        {
            return Err(LeanGenerationError::new(
                LeanGenerationErrorKind::IndeterminatePublication,
                "active record names the transaction but carries different generation evidence",
            ));
        }
        if is_active {
            self.verify_generation(generation)?;
            match transaction.as_ref().map(|record| record.state) {
                Some(LeanGenerationStateV1::Published) => {}
                Some(LeanGenerationStateV1::Verified) => {
                    self.transition(generation, LeanGenerationStateV1::Published)?;
                }
                _ => {
                    return Err(LeanGenerationError::new(
                        LeanGenerationErrorKind::InvalidTransition,
                        "active generation lacks a verified or published transaction record",
                    ));
                }
            }
            self.update_retained(generation)?;
            let released = self.release_lock_if_owned(generation)?;
            return Ok(LeanGenerationRecoveryV1 {
                state: LeanGenerationStateV1::Published,
                active: true,
                lock_released: released,
            });
        }

        match transaction.as_ref().map(|record| record.state) {
            Some(LeanGenerationStateV1::Published) => {
                return Err(LeanGenerationError::new(
                    LeanGenerationErrorKind::IndeterminatePublication,
                    "published transaction is not the active generation",
                ));
            }
            Some(LeanGenerationStateV1::Failed) => {}
            Some(_) => self.transition(generation, LeanGenerationStateV1::Failed)?,
            None => self.create_transaction_record(generation, LeanGenerationStateV1::Failed)?,
        }
        self.remove_abandoned_active_temp(generation)?;
        let released = self.release_lock_if_owned(generation)?;
        Ok(LeanGenerationRecoveryV1 {
            state: LeanGenerationStateV1::Failed,
            active: false,
            lock_released: released,
        })
    }

    pub fn active_generation_identity(&self) -> Result<Option<Sha256>, LeanGenerationError> {
        Ok(self.read_active_optional()?.map(|record| record.generation))
    }

    pub fn active_generation_reference(
        &self,
    ) -> Result<Option<ActiveGenerationRefV1>, LeanGenerationError> {
        Ok(self
            .read_active_optional()?
            .map(|record| ActiveGenerationRefV1 {
                transaction_id: record.transaction,
                generation_sha256: record.generation,
                generation_root: record.path,
            }))
    }

    /// Atomically restores a previously published generation as active.
    ///
    /// Both generations are fully reverified before the project lock is
    /// acquired.  The active record is then re-read under exact ownership so
    /// a concurrent publication cannot be mistaken for the requested current
    /// generation.  Retained generation bytes are never rewritten.
    pub fn rollback_active_generation(
        &self,
        current: &LeanBunGenerationV1,
        retained: &LeanBunGenerationV1,
    ) -> Result<(), LeanGenerationError> {
        self.validate_generation_location(current)?;
        self.validate_generation_location(retained)?;
        if current.identity() == retained.identity()
            || current.transaction_id() == retained.transaction_id()
        {
            return Err(LeanGenerationError::new(
                LeanGenerationErrorKind::InvalidField,
                "rollback current and retained generations must be distinct",
            ));
        }
        self.verify_active_generation(current)?;
        self.verify_published_generation(retained)?;
        self.acquire_lock(current)?;
        let result = (|| {
            self.verify_active_generation(current)?;
            self.verify_published_generation(retained)?;
            self.publish_active(retained, LeanGenerationFaultV1::None)?;
            self.verify_active_generation(retained)
        })();
        match result {
            Ok(()) => self.release_lock(current),
            Err(error) => {
                let _ = self.release_lock_if_owned(current);
                Err(error)
            }
        }
    }

    fn validate_generation_location(
        &self,
        generation: &LeanBunGenerationV1,
    ) -> Result<(), LeanGenerationError> {
        if generation.project_id() != self.project_id
            || generation.project_root() != self.project_root
            || generation.generation_root() != self.generation_root(generation.transaction_id())
        {
            return Err(boundary(
                "generation is not bound to this fixture project/state root",
            ));
        }
        Ok(())
    }

    fn verify_published_generation(
        &self,
        generation: &LeanBunGenerationV1,
    ) -> Result<(), LeanGenerationError> {
        let transaction = self
            .read_transaction_optional(generation.transaction_id())?
            .ok_or_else(|| drift("retained generation transaction record is missing"))?;
        if transaction.project != generation.project_id()
            || transaction.generation != generation.identity()
            || transaction.state != LeanGenerationStateV1::Published
        {
            return Err(drift("retained generation transaction is not published"));
        }
        self.verify_generation(generation)
    }

    fn acquire_lock(&self, generation: &LeanBunGenerationV1) -> Result<(), LeanGenerationError> {
        let path = self.lock_path();
        let bytes = lock_bytes(generation);
        match create_synced_new(&path, &bytes) {
            Ok(()) => sync_directory(&self.project_state),
            Err(error) if error.kind == LeanGenerationErrorKind::LockBusy => Err(error),
            Err(error) => Err(error),
        }
    }

    fn release_lock(&self, generation: &LeanBunGenerationV1) -> Result<(), LeanGenerationError> {
        if !self.release_lock_if_owned(generation)? {
            return Err(LeanGenerationError::new(
                LeanGenerationErrorKind::OwnershipMismatch,
                "project lock is absent before required release",
            ));
        }
        Ok(())
    }

    fn release_lock_if_owned(
        &self,
        generation: &LeanBunGenerationV1,
    ) -> Result<bool, LeanGenerationError> {
        let path = self.lock_path();
        if !path.exists() {
            return Ok(false);
        }
        let observed = stable_read(&path, MAX_RECORD_BYTES)?;
        if observed != lock_bytes(generation) {
            return Err(LeanGenerationError::new(
                LeanGenerationErrorKind::OwnershipMismatch,
                "project lock belongs to another transaction",
            ));
        }
        fs::remove_file(&path).map_err(io_error)?;
        sync_directory(&self.project_state)?;
        Ok(true)
    }

    fn materialize_generation(
        &self,
        generation: &LeanBunGenerationV1,
        fault: LeanGenerationFaultV1,
    ) -> Result<(), LeanGenerationError> {
        let root = generation.generation_root();
        match fs::create_dir(root) {
            Ok(()) => set_mode(root, 0o700)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(LeanGenerationError::new(
                    LeanGenerationErrorKind::RecordDrift,
                    "generation directory already exists before materialization",
                ));
            }
            Err(error) => return Err(io_error(error)),
        }
        write_generation_file(root, "leanbun.lock", generation.lock_text.as_bytes())?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterLockFile,
            "after generation lock file",
        )?;
        write_generation_file(
            root,
            "lake-manifest.json",
            generation.manifest_text.as_bytes(),
        )?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterManifestProjection,
            "after manifest projection",
        )?;
        write_generation_file(
            root,
            "runtime-packages.json",
            generation.runtime_text.as_bytes(),
        )?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterRuntimeProjection,
            "after runtime projection",
        )?;
        ensure_private_descendant(root, &root.join("packages"))?;
        for package in &generation.packages {
            ensure_private_descendant(&root.join("packages"), &package.final_path)?;
            materialize_package(package)?;
        }
        inject(
            fault,
            LeanGenerationFaultV1::AfterPackages,
            "after package materialization",
        )?;
        write_generation_file(root, "generation.meta", &generation.canonical_metadata()?)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterGenerationMetadata,
            "after generation metadata",
        )?;
        sync_files(root)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterFileSync,
            "after generation file sync",
        )?;
        sync_directories_tree(root)?;
        inject(
            fault,
            LeanGenerationFaultV1::AfterDirectorySync,
            "after generation directory sync",
        )?;
        make_generation_read_only(root)?;
        sync_files(root)?;
        sync_directories_tree(root)?;
        sync_directory(
            root.parent()
                .ok_or_else(|| boundary("generation root has no parent"))?,
        )
    }

    fn verify_generation(
        &self,
        generation: &LeanBunGenerationV1,
    ) -> Result<(), LeanGenerationError> {
        let root = generation.generation_root();
        let expected_root = BTreeSet::from([
            "generation.meta".to_owned(),
            "lake-manifest.json".to_owned(),
            "leanbun.lock".to_owned(),
            "packages".to_owned(),
            "runtime-packages.json".to_owned(),
        ]);
        let actual_root = directory_names(root)?;
        if actual_root != expected_root {
            return Err(drift(
                "generation root contains an unknown or missing entry",
            ));
        }
        require_exact(
            &root.join("generation.meta"),
            &generation.canonical_metadata()?,
            LeanGenerationErrorKind::GenerationDrift,
        )?;
        require_exact(
            &root.join("leanbun.lock"),
            generation.lock_text.as_bytes(),
            LeanGenerationErrorKind::GenerationDrift,
        )?;
        require_exact(
            &root.join("lake-manifest.json"),
            generation.manifest_text.as_bytes(),
            LeanGenerationErrorKind::MixedProjection,
        )?;
        require_exact(
            &root.join("runtime-packages.json"),
            generation.runtime_text.as_bytes(),
            LeanGenerationErrorKind::MixedProjection,
        )?;
        validate_package_namespace(&root.join("packages"), &generation.packages)?;
        for package in &generation.packages {
            verify_package_source_ignoring_lake_cache(package)?;
        }
        Ok(())
    }

    fn create_transaction_record(
        &self,
        generation: &LeanBunGenerationV1,
        state: LeanGenerationStateV1,
    ) -> Result<(), LeanGenerationError> {
        let record = TransactionRecord {
            transaction: generation.transaction_id(),
            project: generation.project_id(),
            generation: generation.identity(),
            state,
        };
        let path = self.transaction_path(generation.transaction_id());
        if path.exists() {
            return Err(LeanGenerationError::new(
                LeanGenerationErrorKind::RecordDrift,
                "transaction record already exists",
            ));
        }
        create_synced_new(&path, &transaction_bytes(&record))?;
        sync_directory(&self.project_state.join("transactions"))
    }

    fn transition(
        &self,
        generation: &LeanBunGenerationV1,
        next: LeanGenerationStateV1,
    ) -> Result<(), LeanGenerationError> {
        let current = self
            .read_transaction_optional(generation.transaction_id())?
            .ok_or_else(|| drift("transaction record is missing"))?;
        if current.project != generation.project_id() || current.generation != generation.identity()
        {
            return Err(drift("transaction record identity changed"));
        }
        if !valid_transition(current.state, next) {
            return Err(LeanGenerationError::new(
                LeanGenerationErrorKind::InvalidTransition,
                format!(
                    "invalid generation transition {:?} -> {next:?}",
                    current.state
                ),
            ));
        }
        let updated = TransactionRecord {
            state: next,
            ..current
        };
        atomic_replace(
            &self.transaction_path(generation.transaction_id()),
            &transaction_bytes(&updated),
        )
    }

    fn publish_active(
        &self,
        generation: &LeanBunGenerationV1,
        fault: LeanGenerationFaultV1,
    ) -> Result<(), LeanGenerationError> {
        let active = ActiveRecord {
            transaction: generation.transaction_id(),
            generation: generation.identity(),
            path: generation.generation_root().to_path_buf(),
        };
        let bytes = active_bytes(&active)?;
        let temp = create_temp(&self.project_state, "active", &bytes)?;
        inject(
            fault,
            LeanGenerationFaultV1::BeforeActiveRename,
            "before active rename",
        )?;
        fs::rename(&temp, self.active_path()).map_err(|error| {
            LeanGenerationError::new(
                LeanGenerationErrorKind::RenameFailed,
                format!("cannot publish active generation: {error}"),
            )
        })?;
        sync_directory(&self.project_state)?;
        let observed = self
            .read_active_optional()?
            .ok_or_else(|| drift("active record disappeared after publication"))?;
        if observed != active {
            return Err(drift("active record differs after publication"));
        }
        Ok(())
    }

    fn remove_abandoned_active_temp(
        &self,
        generation: &LeanBunGenerationV1,
    ) -> Result<(), LeanGenerationError> {
        let expected = active_bytes(&ActiveRecord {
            transaction: generation.transaction_id(),
            generation: generation.identity(),
            path: generation.generation_root().to_path_buf(),
        })?;
        let mut removed = false;
        for entry in fs::read_dir(&self.project_state).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(".active-") || !name.ends_with(".tmp") {
                continue;
            }
            let candidate = entry.path();
            let metadata = fs::symlink_metadata(&candidate).map_err(io_error)?;
            if !metadata.file_type().is_file() {
                return Err(drift(
                    "abandoned active temporary record is not a regular file",
                ));
            }
            if stable_read(&candidate, MAX_RECORD_BYTES)? == expected {
                fs::remove_file(&candidate).map_err(io_error)?;
                removed = true;
            }
        }
        if removed {
            sync_directory(&self.project_state)?;
        }
        Ok(())
    }

    fn update_retained(&self, generation: &LeanBunGenerationV1) -> Result<(), LeanGenerationError> {
        let path = self.project_state.join("retained.record");
        let mut pairs = if path.exists() {
            parse_retained(&stable_read(&path, MAX_RECORD_BYTES)?)?
        } else {
            BTreeSet::new()
        };
        for package in &generation.packages {
            pairs.insert((generation.identity(), package.store_object_sha256));
        }
        atomic_replace(&path, &retained_bytes(&pairs))
    }

    fn read_transaction_optional(
        &self,
        transaction: ExecutionId,
    ) -> Result<Option<TransactionRecord>, LeanGenerationError> {
        let path = self.transaction_path(transaction);
        if !path.exists() {
            return Ok(None);
        }
        parse_transaction(&stable_read(&path, MAX_RECORD_BYTES)?).map(Some)
    }

    fn read_active_optional(&self) -> Result<Option<ActiveRecord>, LeanGenerationError> {
        let path = self.active_path();
        if !path.exists() {
            return Ok(None);
        }
        parse_active(&stable_read(&path, MAX_RECORD_BYTES)?).map(Some)
    }

    fn lock_path(&self) -> PathBuf {
        self.project_state.join("project.lock")
    }
    fn active_path(&self) -> PathBuf {
        self.project_state.join("active.record")
    }
    fn transaction_path(&self, transaction: ExecutionId) -> PathBuf {
        self.project_state
            .join("transactions")
            .join(format!("{}.record", transaction.as_str()))
    }
}

fn outcome(
    generation: &LeanBunGenerationV1,
    state: LeanGenerationStateV1,
) -> LeanGenerationOutcomeV1 {
    LeanGenerationOutcomeV1 {
        transaction_id: generation.transaction_id(),
        generation_identity: generation.identity(),
        generation_root: generation.generation_root().to_path_buf(),
        state,
    }
}

fn verify_package_source_ignoring_lake_cache(
    package: &GenerationPackageV1,
) -> Result<(), LeanGenerationError> {
    let expected = package
        .entries
        .iter()
        .map(|entry| (entry.path().to_owned(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeSet::new();
    let mut pending = vec![package.final_path.clone()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let path = entry.path();
            if directory == package.final_path && entry.file_name() == ".lake" {
                if !entry.file_type().map_err(io_error)?.is_dir() {
                    return Err(drift("package .lake cache is not a directory"));
                }
                continue;
            }
            let relative = path
                .strip_prefix(&package.final_path)
                .map_err(|_| drift("generation package entry escaped its root"))?;
            let relative = relative
                .to_str()
                .ok_or_else(|| drift("generation package entry is not UTF-8"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if package.key_scope == "leanprover-community"
                && package.key_name == "proofwidgets"
                && relative == "widget/package-lock.json.hash"
            {
                let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
                if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
                    return Err(drift("registered derived cache is invalid"));
                }
                continue;
            }
            let expected_entry = expected
                .get(&relative)
                .ok_or_else(|| drift("generation package source contains an extra path"))?;
            let file_type = entry.file_type().map_err(io_error)?;
            match expected_entry.kind() {
                NormalizedTreeEntryKindV1::Directory if file_type.is_dir() => pending.push(path),
                NormalizedTreeEntryKindV1::File if file_type.is_file() => {
                    let bytes = fs::read(&path).map_err(io_error)?;
                    if bytes.len() as u64 != expected_entry.size() {
                        return Err(drift("generation package source file size changed"));
                    }
                    let mut hasher = Sha256Hasher::new();
                    hasher.update(&bytes);
                    if Some(hasher.finalize()) != expected_entry.sha256() {
                        return Err(drift("generation package source file digest changed"));
                    }
                }
                _ => return Err(drift("generation package source entry kind changed")),
            }
            observed.insert(relative);
        }
    }
    if observed != expected.keys().cloned().collect() {
        return Err(drift("generation package source contains a missing path"));
    }
    Ok(())
}

fn materialize_package(package: &GenerationPackageV1) -> Result<(), LeanGenerationError> {
    let source_digest = normalized_directory_tree_sha256_v1(
        &package.object_tree_path,
        // Store admission has already enforced the source-specific profile.
        // Reverification must accommodate a registered provider object while
        // retaining the same finite global maxima.
        LeanStoreLimitsV1::registered_provider(),
    )
    .map_err(|error| drift(format!("M34 object cannot be reverified: {error}")))?;
    if source_digest != package.source_tree_sha256 {
        return Err(drift(
            "M34 object tree changed before generation materialization",
        ));
    }
    for entry in &package.entries {
        let source = safe_join(&package.object_tree_path, entry.path())?;
        let destination = safe_join(&package.final_path, entry.path())?;
        match entry.kind() {
            NormalizedTreeEntryKindV1::Directory => {
                ensure_private_descendant(&package.final_path, &destination)?;
            }
            NormalizedTreeEntryKindV1::File => {
                if let Some(parent) = destination.parent() {
                    ensure_private_descendant(&package.final_path, parent)?;
                }
                let metadata = fs::symlink_metadata(&source).map_err(io_error)?;
                if !metadata.file_type().is_file() {
                    return Err(drift("M34 object entry is not a regular file"));
                }
                let source_file = fs::File::open(&source).map_err(io_error)?;
                let mut destination_file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&destination)
                    .map_err(io_error)?;
                let copied = std::io::copy(
                    &mut source_file.take(entry.size().saturating_add(1)),
                    &mut destination_file,
                )
                .map_err(io_error)?;
                if copied != entry.size() {
                    return Err(drift("M34 object file changed while copying"));
                }
            }
        }
    }
    Ok(())
}

fn validate_package_namespace(
    packages_root: &Path,
    packages: &[GenerationPackageV1],
) -> Result<(), LeanGenerationError> {
    let roots = packages
        .iter()
        .map(|package| package.final_path.clone())
        .collect::<BTreeSet<_>>();
    let mut pending = vec![packages_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if roots
                .iter()
                .any(|root| path == *root || path.starts_with(root))
            {
                continue;
            }
            if roots.iter().any(|root| root.starts_with(&path)) && path.is_dir() {
                pending.push(path);
            } else {
                return Err(drift("generation package namespace contains an extra path"));
            }
        }
    }
    Ok(())
}

fn write_generation_file(root: &Path, name: &str, bytes: &[u8]) -> Result<(), LeanGenerationError> {
    let path = root.join(name);
    create_synced_new(&path, bytes)?;
    set_mode(&path, 0o444)
}

fn create_synced_new(path: &Path, bytes: &[u8]) -> Result<(), LeanGenerationError> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                LeanGenerationError::new(
                    LeanGenerationErrorKind::LockBusy,
                    "exclusive state file exists",
                )
            } else {
                io_error(error)
            }
        })?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(sync_error)?;
    set_mode(path, 0o444)?;
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(sync_error)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), LeanGenerationError> {
    let parent = path
        .parent()
        .ok_or_else(|| boundary("state file has no parent"))?;
    let temp = create_temp(parent, "replace", bytes)?;
    fs::rename(&temp, path).map_err(|error| {
        LeanGenerationError::new(
            LeanGenerationErrorKind::RenameFailed,
            format!("cannot atomically replace state record: {error}"),
        )
    })?;
    sync_directory(parent)?;
    require_exact(path, bytes, LeanGenerationErrorKind::RecordDrift)
}

fn create_temp(parent: &Path, label: &str, bytes: &[u8]) -> Result<PathBuf, LeanGenerationError> {
    for _ in 0..32 {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".{label}-{}-{nonce}.tmp", std::process::id()));
        match create_synced_new(&path, bytes) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind == LeanGenerationErrorKind::LockBusy => {}
            Err(error) => return Err(error),
        }
    }
    Err(LeanGenerationError::new(
        LeanGenerationErrorKind::Io,
        "cannot allocate unique durable temporary record",
    ))
}

fn stable_read(path: &Path, maximum: u64) -> Result<Vec<u8>, LeanGenerationError> {
    let before = fs::symlink_metadata(path).map_err(io_error)?;
    if !before.file_type().is_file() || before.len() > maximum {
        return Err(drift("state record is not a bounded regular file"));
    }
    let file = fs::File::open(path).map_err(io_error)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let after = fs::symlink_metadata(path).map_err(io_error)?;
    if !stable_metadata_equal(&before, &after) || bytes.len() as u64 != before.len() {
        return Err(drift("state record changed while reading"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn stable_metadata_equal(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

#[cfg(not(unix))]
fn stable_metadata_equal(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.permissions().readonly() == after.permissions().readonly()
}

fn require_exact(
    path: &Path,
    expected: &[u8],
    kind: LeanGenerationErrorKind,
) -> Result<(), LeanGenerationError> {
    let actual = stable_read(path, MAX_RECORD_BYTES)?;
    if actual != expected {
        return Err(LeanGenerationError::new(
            kind,
            "durable generation bytes differ from identity",
        ));
    }
    Ok(())
}

fn lock_bytes(generation: &LeanBunGenerationV1) -> Vec<u8> {
    format!(
        "leanbun-generation-lock-v1\t1\ntransaction\t{}\ngeneration\t{}\nend-lock\n",
        generation.transaction_id(),
        generation.identity()
    )
    .into_bytes()
}

fn transaction_bytes(record: &TransactionRecord) -> Vec<u8> {
    format!(
        "leanbun-generation-transaction-v1\t1\ntransaction\t{}\nproject-id\t{}\ngeneration\t{}\nstate\t{}\nend-transaction\n",
        record.transaction,
        record.project,
        record.generation,
        record.state.token()
    )
    .into_bytes()
}

fn parse_transaction(bytes: &[u8]) -> Result<TransactionRecord, LeanGenerationError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| malformed("transaction record is not UTF-8"))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 6
        || lines[0] != "leanbun-generation-transaction-v1\t1"
        || lines[5] != "end-transaction"
    {
        return Err(malformed("transaction record shape is invalid"));
    }
    let record = TransactionRecord {
        transaction: ExecutionId::parse(field_value(lines[1], "transaction")?)
            .map_err(|_| malformed("transaction id is invalid"))?,
        project: ProjectId::parse(field_value(lines[2], "project-id")?)
            .map_err(|_| malformed("project id is invalid"))?,
        generation: Sha256::parse(field_value(lines[3], "generation")?)
            .map_err(|_| malformed("generation digest is invalid"))?,
        state: LeanGenerationStateV1::parse(field_value(lines[4], "state")?)?,
    };
    if transaction_bytes(&record) != bytes {
        return Err(malformed("transaction record is not canonical"));
    }
    Ok(record)
}

fn active_bytes(record: &ActiveRecord) -> Result<Vec<u8>, LeanGenerationError> {
    Ok(format!(
        "leanbun-active-generation-v1\t1\ntransaction\t{}\ngeneration\t{}\npath\t{}\nend-active\n",
        record.transaction,
        record.generation,
        path_text(&record.path)?
    )
    .into_bytes())
}

fn parse_active(bytes: &[u8]) -> Result<ActiveRecord, LeanGenerationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| malformed("active record is not UTF-8"))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 5 || lines[0] != "leanbun-active-generation-v1\t1" || lines[4] != "end-active"
    {
        return Err(malformed("active record shape is invalid"));
    }
    let record = ActiveRecord {
        transaction: ExecutionId::parse(field_value(lines[1], "transaction")?)
            .map_err(|_| malformed("active transaction id is invalid"))?,
        generation: Sha256::parse(field_value(lines[2], "generation")?)
            .map_err(|_| malformed("active generation digest is invalid"))?,
        path: PathBuf::from(field_value(lines[3], "path")?),
    };
    if active_bytes(&record)? != bytes {
        return Err(malformed("active record is not canonical"));
    }
    Ok(record)
}

fn retained_bytes(pairs: &BTreeSet<(Sha256, Sha256)>) -> Vec<u8> {
    let mut output = format!(
        "leanbun-retained-generation-v1\t1\nreference-count\t{}\n",
        pairs.len()
    );
    for (generation, object) in pairs {
        output.push_str(&format!("reference\t{generation}\t{object}\n"));
    }
    output.push_str("end-retained\n");
    output.into_bytes()
}

fn parse_retained(bytes: &[u8]) -> Result<BTreeSet<(Sha256, Sha256)>, LeanGenerationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| malformed("retained record is not UTF-8"))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() < 3 || lines[0] != "leanbun-retained-generation-v1\t1" {
        return Err(malformed("retained record shape is invalid"));
    }
    let count = field_value(lines[1], "reference-count")?
        .parse::<usize>()
        .map_err(|_| malformed("retained reference count is invalid"))?;
    if lines.len() != count + 3 || lines.last().copied() != Some("end-retained") {
        return Err(malformed("retained reference count differs from body"));
    }
    let mut pairs = BTreeSet::new();
    for line in &lines[2..2 + count] {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 3 || fields[0] != "reference" {
            return Err(malformed("retained reference is invalid"));
        }
        let generation =
            Sha256::parse(fields[1]).map_err(|_| malformed("retained generation is invalid"))?;
        let object =
            Sha256::parse(fields[2]).map_err(|_| malformed("retained object is invalid"))?;
        if !pairs.insert((generation, object)) {
            return Err(malformed("retained reference is duplicated"));
        }
    }
    if retained_bytes(&pairs) != bytes {
        return Err(malformed("retained record is not canonical"));
    }
    Ok(pairs)
}

fn field_value<'a>(line: &'a str, name: &str) -> Result<&'a str, LeanGenerationError> {
    line.strip_prefix(name)
        .and_then(|value| value.strip_prefix('\t'))
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| malformed(format!("record field {name} is invalid")))
}

fn valid_transition(current: LeanGenerationStateV1, next: LeanGenerationStateV1) -> bool {
    matches!(
        (current, next),
        (
            LeanGenerationStateV1::Preparing,
            LeanGenerationStateV1::Materialized
        ) | (
            LeanGenerationStateV1::Materialized,
            LeanGenerationStateV1::Verified
        ) | (
            LeanGenerationStateV1::Verified,
            LeanGenerationStateV1::Published
        ) | (
            LeanGenerationStateV1::Preparing,
            LeanGenerationStateV1::Failed
        ) | (
            LeanGenerationStateV1::Materialized,
            LeanGenerationStateV1::Failed
        ) | (
            LeanGenerationStateV1::Verified,
            LeanGenerationStateV1::Failed
        )
    )
}

fn inject(
    actual: LeanGenerationFaultV1,
    expected: LeanGenerationFaultV1,
    stage: &str,
) -> Result<(), LeanGenerationError> {
    if actual == expected {
        return Err(LeanGenerationError::new(
            LeanGenerationErrorKind::FaultInjected,
            format!("crash fault injected {stage}"),
        ));
    }
    Ok(())
}

fn sync_files(root: &Path) -> Result<(), LeanGenerationError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
            if metadata.file_type().is_symlink() {
                return Err(drift("symlink appeared in generation tree"));
            }
            if metadata.file_type().is_dir() {
                pending.push(path);
            } else if metadata.file_type().is_file() {
                fs::File::open(&path)
                    .and_then(|file| file.sync_all())
                    .map_err(sync_error)?;
            } else {
                return Err(drift("special file appeared in generation tree"));
            }
        }
    }
    Ok(())
}

fn sync_directories_tree(root: &Path) -> Result<(), LeanGenerationError> {
    let mut directories = vec![root.to_path_buf()];
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path.is_dir() {
                directories.push(path.clone());
                pending.push(path);
            }
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn make_generation_read_only(root: &Path) -> Result<(), LeanGenerationError> {
    let mut directories = vec![root.to_path_buf()];
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path.is_dir() {
                directories.push(path.clone());
                pending.push(path);
            } else {
                set_mode(&path, 0o444)?;
            }
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        set_mode(&directory, 0o555)?;
    }
    Ok(())
}

fn directory_names(root: &Path) -> Result<BTreeSet<String>, LeanGenerationError> {
    fs::read_dir(root)
        .map_err(io_error)?
        .map(|entry| {
            entry
                .map_err(io_error)?
                .file_name()
                .into_string()
                .map_err(|_| drift("generation filename is not UTF-8"))
        })
        .collect()
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, LeanGenerationError> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(boundary("package entry is not safely relative"));
    }
    Ok(root.join(relative))
}

fn ensure_private_descendant(base: &Path, target: &Path) -> Result<(), LeanGenerationError> {
    let relative = target
        .strip_prefix(base)
        .map_err(|_| boundary("directory target is outside its established base"))?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(boundary("directory target is not normalized"));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(boundary(
                    "directory boundary contains symlink or nondirectory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(io_error)?;
            }
            Err(error) => return Err(io_error(error)),
        }
        set_mode(&current, 0o700)?;
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, LeanGenerationError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(boundary("M35 path must be normalized and absolute"));
    }
    Ok(path.to_path_buf())
}

fn sync_directory(path: &Path) -> Result<(), LeanGenerationError> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(sync_error)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), LeanGenerationError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_error)
}

#[cfg(not(unix))]
fn set_mode(path: &Path, _mode: u32) -> Result<(), LeanGenerationError> {
    let mut permissions = fs::metadata(path).map_err(io_error)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(io_error)
}

fn path_text(path: &Path) -> Result<&str, LeanGenerationError> {
    path.to_str()
        .ok_or_else(|| boundary("M35 path is not UTF-8"))
}

fn malformed(message: impl Into<String>) -> LeanGenerationError {
    LeanGenerationError::new(LeanGenerationErrorKind::RecordMalformed, message)
}

fn boundary(message: impl Into<String>) -> LeanGenerationError {
    LeanGenerationError::new(LeanGenerationErrorKind::BoundaryViolation, message)
}

fn boundary_error(error: std::io::Error) -> LeanGenerationError {
    boundary(format!("cannot establish M35 boundary: {error}"))
}

fn io_error(error: std::io::Error) -> LeanGenerationError {
    LeanGenerationError::new(
        LeanGenerationErrorKind::Io,
        format!("M35 I/O failed: {error}"),
    )
}

fn sync_error(error: std::io::Error) -> LeanGenerationError {
    LeanGenerationError::new(
        LeanGenerationErrorKind::SyncFailed,
        format!("M35 durable sync failed: {error}"),
    )
}

fn drift(message: impl Into<String>) -> LeanGenerationError {
    LeanGenerationError::new(LeanGenerationErrorKind::GenerationDrift, message)
}

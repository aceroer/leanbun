use crate::archive::{TreePlan, plan_directory};
use crate::fetch::fetch_and_plan;
use crate::model::{
    LeanFetchCancellationV1, LeanFetchFaultV1, LeanFetchRequestV1, LeanStoreError,
    LeanStoreErrorKind, LeanStorePublicationV1, NormalizedTreeEntryKindV1, NormalizedTreeEntryV1,
    VerifiedDownloadBlobV1, VerifiedPackageObjectV1, sha256,
};
use leanbun_core::Sha256;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const MAX_RETAINED_TASKS: usize = 4_096;
static SLOT_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct LeanImmutableStoreV1 {
    development_root: PathBuf,
    store_root: PathBuf,
    shared: Arc<Shared>,
}

struct Shared {
    tasks: Mutex<HashMap<Sha256, Arc<TaskCell>>>,
}

struct TaskCell {
    state: Mutex<TaskState>,
    ready: Condvar,
}

enum TaskState {
    Running,
    Terminal(Box<Result<VerifiedPackageObjectV1, LeanStoreError>>),
}

impl LeanImmutableStoreV1 {
    pub fn open(
        development_root: impl AsRef<Path>,
        store_root: impl AsRef<Path>,
    ) -> Result<Self, LeanStoreError> {
        let development_root = development_root
            .as_ref()
            .canonicalize()
            .map_err(boundary_error)?;
        let requested = normalized_absolute(store_root.as_ref())?;
        let fixture_base = development_root.join("store-fixture");
        if requested != fixture_base && !requested.starts_with(&fixture_base) {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::BoundaryViolation,
                "store root must be inside development_root/store-fixture",
            ));
        }
        ensure_private_descendant(&development_root, &fixture_base)?;
        ensure_private_descendant(&fixture_base, &requested)?;
        let fixture_base = fixture_base.canonicalize().map_err(boundary_error)?;
        let store_root = requested.canonicalize().map_err(boundary_error)?;
        if store_root != fixture_base && !store_root.starts_with(&fixture_base) {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::BoundaryViolation,
                "canonical store root escaped store-fixture",
            ));
        }
        create_private_directory(&store_root.join("objects"))?;
        create_private_directory(&store_root.join("slots"))?;
        Ok(Self {
            development_root,
            store_root,
            shared: Arc::new(Shared {
                tasks: Mutex::new(HashMap::new()),
            }),
        })
    }

    #[must_use]
    pub fn development_root(&self) -> &Path {
        &self.development_root
    }

    #[must_use]
    pub fn store_root(&self) -> &Path {
        &self.store_root
    }

    pub fn fetch_and_publish(
        &self,
        request: &LeanFetchRequestV1,
        cancellation: &LeanFetchCancellationV1,
        fault: LeanFetchFaultV1,
    ) -> Result<VerifiedPackageObjectV1, LeanStoreError> {
        let (task, runner) = {
            let mut tasks = self.shared.tasks.lock().map_err(lock_error)?;
            if let Some(task) = tasks.get(&request.identity()) {
                (Arc::clone(task), false)
            } else {
                if tasks.len() >= MAX_RETAINED_TASKS {
                    return Err(LeanStoreError::new(
                        LeanStoreErrorKind::LimitExceeded,
                        "retained fetch task count exceeds limit",
                    ));
                }
                let task = Arc::new(TaskCell {
                    state: Mutex::new(TaskState::Running),
                    ready: Condvar::new(),
                });
                tasks.insert(request.identity(), Arc::clone(&task));
                (task, true)
            }
        };
        if runner {
            let result = self.execute(request, cancellation, fault);
            let mut state = task.state.lock().map_err(lock_error)?;
            *state = TaskState::Terminal(Box::new(result.clone()));
            task.ready.notify_all();
            result
        } else {
            wait_for_terminal(&task, cancellation)
                .map(|object| object.with_publication(LeanStorePublicationV1::Deduplicated))
        }
    }

    pub fn verify_object_for_request(
        &self,
        request: &LeanFetchRequestV1,
    ) -> Result<VerifiedPackageObjectV1, LeanStoreError> {
        self.verify_existing(request, LeanStorePublicationV1::Reused)
    }

    fn execute(
        &self,
        request: &LeanFetchRequestV1,
        cancellation: &LeanFetchCancellationV1,
        fault: LeanFetchFaultV1,
    ) -> Result<VerifiedPackageObjectV1, LeanStoreError> {
        let destination = self.object_path(request.candidate().source_tree_sha256());
        if destination.exists() {
            return self.verify_existing(request, LeanStorePublicationV1::Reused);
        }
        let slot = self.create_slot()?;
        let result = self.execute_in_slot(request, cancellation, fault, &slot, &destination);
        cleanup_slot(&slot);
        result
    }

    fn execute_in_slot(
        &self,
        request: &LeanFetchRequestV1,
        cancellation: &LeanFetchCancellationV1,
        fault: LeanFetchFaultV1,
        slot: &Path,
        destination: &Path,
    ) -> Result<VerifiedPackageObjectV1, LeanStoreError> {
        let fetched = fetch_and_plan(request, slot, cancellation, fault)?;
        let object = slot.join("object");
        let tree = object.join("tree");
        create_private_directory(&tree)?;
        materialize_tree(&tree, &fetched.plan)?;
        let metadata = encode_metadata(&fetched.plan.entries);
        let object_digest = sha256(&metadata);
        let metadata_path = object.join("object.meta");
        let mut metadata_file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&metadata_path)
            .map_err(store_error)?;
        metadata_file.write_all(&metadata).map_err(store_error)?;
        drop(metadata_file);

        if fault == LeanFetchFaultV1::FileSync {
            return Err(injected("file sync"));
        }
        sync_regular_files(&object)?;
        if fault == LeanFetchFaultV1::DirectorySync {
            return Err(injected("directory sync"));
        }
        sync_directories(&object)?;
        sync_directory(slot)?;
        if fault == LeanFetchFaultV1::Rename {
            return Err(injected("rename"));
        }

        match fs::rename(&object, destination) {
            Ok(()) => {
                let sealed = make_tree_read_only(&destination.join("tree"), &fetched.plan)
                    .and_then(|()| set_mode(&destination.join("object.meta"), 0o444))
                    .and_then(|()| set_mode(destination, 0o555))
                    .and_then(|()| sync_directory(destination))
                    .and_then(|()| sync_directory(&self.store_root.join("objects")));
                if let Err(error) = sealed {
                    let rollback = fs::rename(destination, &object);
                    if rollback.is_err() {
                        return Err(LeanStoreError::new(
                            LeanStoreErrorKind::IndeterminatePublication,
                            format!(
                                "object published but parent sync and rollback failed: {error}"
                            ),
                        ));
                    }
                    return Err(error);
                }
                Ok(build_verified(
                    request,
                    destination.to_path_buf(),
                    fetched.plan,
                    object_digest,
                    fetched.download,
                    LeanStorePublicationV1::Published,
                ))
            }
            Err(rename_error) if destination.exists() => {
                let existing = self.verify_existing(request, LeanStorePublicationV1::Reused)?;
                if existing.store_object_sha256() != object_digest {
                    return Err(LeanStoreError::new(
                        LeanStoreErrorKind::StoreObjectConflict,
                        "concurrent store object has different normalized metadata",
                    ));
                }
                let _ = rename_error;
                Ok(existing)
            }
            Err(error) => Err(LeanStoreError::new(
                LeanStoreErrorKind::RenameFailed,
                format!("cannot atomically publish store object: {error}"),
            )),
        }
    }

    fn verify_existing(
        &self,
        request: &LeanFetchRequestV1,
        publication: LeanStorePublicationV1,
    ) -> Result<VerifiedPackageObjectV1, LeanStoreError> {
        let object = self.object_path(request.candidate().source_tree_sha256());
        let object_metadata = fs::symlink_metadata(&object).map_err(|error| {
            LeanStoreError::new(
                LeanStoreErrorKind::TreeDrift,
                format!("store object is unavailable: {error}"),
            )
        })?;
        if !object_metadata.file_type().is_dir() {
            return Err(tree_drift("store object is not a directory"));
        }
        let metadata_path = object.join("object.meta");
        let metadata = fs::read(&metadata_path)
            .map_err(|error| tree_drift(format!("cannot read store object metadata: {error}")))?;
        let tree = object.join("tree");
        let plan = plan_directory(&tree, request.limits())
            .map_err(|error| tree_drift(format!("cannot reverify store tree: {error}")))?;
        if plan.digest != request.candidate().source_tree_sha256() {
            return Err(tree_drift("published store tree digest changed"));
        }
        let expected_metadata = encode_metadata(&plan.entries);
        if metadata != expected_metadata {
            return Err(tree_drift("published store metadata changed"));
        }
        Ok(build_verified(
            request,
            object,
            plan,
            sha256(&metadata),
            None,
            publication,
        ))
    }

    fn object_path(&self, digest: Sha256) -> PathBuf {
        self.store_root.join("objects").join(digest.to_string())
    }

    fn create_slot(&self) -> Result<PathBuf, LeanStoreError> {
        for _ in 0..32 {
            let value = SLOT_COUNTER.fetch_add(1, Ordering::Relaxed);
            let slot = self
                .store_root
                .join("slots")
                .join(format!("{}-{value}", std::process::id()));
            match fs::create_dir(&slot) {
                Ok(()) => {
                    set_mode(&slot, 0o700)?;
                    return Ok(slot);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(store_error(error)),
            }
        }
        Err(LeanStoreError::new(
            LeanStoreErrorKind::LimitExceeded,
            "cannot allocate a unique store slot",
        ))
    }
}

fn wait_for_terminal(
    task: &TaskCell,
    cancellation: &LeanFetchCancellationV1,
) -> Result<VerifiedPackageObjectV1, LeanStoreError> {
    let mut state = task.state.lock().map_err(lock_error)?;
    loop {
        match &*state {
            TaskState::Terminal(result) => return result.as_ref().clone(),
            TaskState::Running if cancellation.is_cancelled() => {
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::Cancelled,
                    "deduplicated fetch wait was cancelled",
                ));
            }
            TaskState::Running => {
                let waited = task
                    .ready
                    .wait_timeout(state, std::time::Duration::from_millis(25))
                    .map_err(|_| lock_error(()))?;
                state = waited.0;
            }
        }
    }
}

fn materialize_tree(root: &Path, plan: &TreePlan) -> Result<(), LeanStoreError> {
    for entry in &plan.entries {
        let path = safe_join(root, &entry.metadata.path)?;
        match entry.metadata.kind {
            NormalizedTreeEntryKindV1::Directory => create_private_directory(&path)?,
            NormalizedTreeEntryKindV1::File => {
                let bytes = entry.bytes.as_deref().ok_or_else(|| {
                    LeanStoreError::new(
                        LeanStoreErrorKind::TreeDrift,
                        "planned file lacks materialized bytes",
                    )
                })?;
                if let Some(parent) = path.parent() {
                    create_private_directory(parent)?;
                }
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(store_error)?;
                file.write_all(bytes).map_err(store_error)?;
                set_mode(&path, entry.metadata.mode)?;
            }
        }
    }
    Ok(())
}

fn encode_metadata(entries: &[crate::archive::PlannedTreeEntry]) -> Vec<u8> {
    let public = entries
        .iter()
        .map(|entry| entry.metadata.clone())
        .collect::<Vec<_>>();
    encode_public_metadata(&public)
}

fn encode_public_metadata(entries: &[NormalizedTreeEntryV1]) -> Vec<u8> {
    let mut bytes = b"leanbun-object-v1\0".to_vec();
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        bytes.extend_from_slice(&(entry.path.len() as u64).to_be_bytes());
        bytes.extend_from_slice(entry.path.as_bytes());
        bytes.push(match entry.kind {
            NormalizedTreeEntryKindV1::Directory => 1,
            NormalizedTreeEntryKindV1::File => 2,
        });
        bytes.extend_from_slice(&entry.mode.to_be_bytes());
        bytes.extend_from_slice(&entry.size.to_be_bytes());
        if let Some(digest) = entry.sha256 {
            bytes.push(1);
            bytes.extend_from_slice(digest.as_bytes());
        } else {
            bytes.push(0);
        }
    }
    bytes
}

fn build_verified(
    request: &LeanFetchRequestV1,
    object: PathBuf,
    plan: TreePlan,
    object_digest: Sha256,
    download: Option<VerifiedDownloadBlobV1>,
    publication: LeanStorePublicationV1,
) -> VerifiedPackageObjectV1 {
    let entries = plan
        .entries
        .into_iter()
        .map(|entry| entry.metadata)
        .collect();
    VerifiedPackageObjectV1::new(
        request.package().clone(),
        request.candidate().identity(),
        plan.digest,
        object_digest,
        object.clone(),
        object.join("tree"),
        entries,
        download,
        publication,
    )
}

fn sync_regular_files(root: &Path) -> Result<(), LeanStoreError> {
    for path in walk(root)? {
        let metadata = fs::symlink_metadata(&path).map_err(store_error)?;
        if metadata.file_type().is_symlink() {
            return Err(tree_drift("symlink appeared in publication slot"));
        }
        if metadata.file_type().is_file() {
            fs::File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|error| {
                    LeanStoreError::new(
                        LeanStoreErrorKind::FileSyncFailed,
                        format!("cannot sync publication file: {error}"),
                    )
                })?;
        }
    }
    Ok(())
}

fn sync_directories(root: &Path) -> Result<(), LeanStoreError> {
    let mut directories = walk(root)?
        .into_iter()
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<(), LeanStoreError> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            LeanStoreError::new(
                LeanStoreErrorKind::DirectorySyncFailed,
                format!("cannot sync publication directory: {error}"),
            )
        })
}

fn make_tree_read_only(root: &Path, plan: &TreePlan) -> Result<(), LeanStoreError> {
    for entry in plan.entries.iter().rev() {
        let path = safe_join(root, &entry.metadata.path)?;
        let mode = match entry.metadata.kind {
            NormalizedTreeEntryKindV1::Directory => 0o555,
            NormalizedTreeEntryKindV1::File if entry.metadata.mode & 0o111 != 0 => 0o555,
            NormalizedTreeEntryKindV1::File => 0o444,
        };
        set_mode(&path, mode)?;
    }
    set_mode(root, 0o555)
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, LeanStoreError> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::PathTraversal,
            "normalized tree path is not safely relative",
        ));
    }
    Ok(root.join(relative))
}

fn walk(root: &Path) -> Result<Vec<PathBuf>, LeanStoreError> {
    let mut pending = vec![root.to_path_buf()];
    let mut paths = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut children = fs::read_dir(&directory)
            .map_err(store_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(store_error)?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let path = child.path();
            if child.file_type().map_err(store_error)?.is_dir() {
                pending.push(path.clone());
            }
            paths.push(path);
        }
    }
    Ok(paths)
}

fn create_private_directory(path: &Path) -> Result<(), LeanStoreError> {
    fs::create_dir_all(path).map_err(store_error)?;
    let metadata = fs::symlink_metadata(path).map_err(store_error)?;
    if !metadata.file_type().is_dir() {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::BoundaryViolation,
            "store path is not a directory",
        ));
    }
    set_mode(path, 0o700)
}

fn ensure_private_descendant(base: &Path, target: &Path) -> Result<(), LeanStoreError> {
    let relative = target.strip_prefix(base).map_err(|_| {
        LeanStoreError::new(
            LeanStoreErrorKind::BoundaryViolation,
            "directory target is outside its established base",
        )
    })?;
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LeanStoreError::new(
                LeanStoreErrorKind::BoundaryViolation,
                "directory target is not lexically normalized",
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(LeanStoreError::new(
                    LeanStoreErrorKind::BoundaryViolation,
                    "store boundary contains a symlink or nondirectory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&current).map_err(store_error)?;
                        if !metadata.file_type().is_dir() {
                            return Err(LeanStoreError::new(
                                LeanStoreErrorKind::BoundaryViolation,
                                "concurrently created store boundary is not a direct directory",
                            ));
                        }
                    }
                    Err(error) => return Err(store_error(error)),
                }
            }
            Err(error) => return Err(store_error(error)),
        }
        set_mode(&current, 0o700)?;
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, LeanStoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(LeanStoreError::new(
            LeanStoreErrorKind::BoundaryViolation,
            "store path must be absolute and lexically normalized",
        ));
    }
    Ok(path.to_path_buf())
}

fn cleanup_slot(slot: &Path) {
    if !slot.exists() {
        return;
    }
    if let Ok(paths) = walk(slot) {
        for path in paths.iter().rev() {
            let _ = set_mode(path, if path.is_dir() { 0o700 } else { 0o600 });
        }
    }
    let _ = set_mode(slot, 0o700);
    let _ = fs::remove_dir_all(slot);
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), LeanStoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(store_error)
}

#[cfg(not(unix))]
fn set_mode(path: &Path, _mode: u32) -> Result<(), LeanStoreError> {
    let mut permissions = fs::metadata(path).map_err(store_error)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(store_error)
}

fn injected(stage: &str) -> LeanStoreError {
    LeanStoreError::new(
        LeanStoreErrorKind::FaultInjected,
        format!("fault injected at {stage} stage"),
    )
}

fn boundary_error(error: std::io::Error) -> LeanStoreError {
    LeanStoreError::new(
        LeanStoreErrorKind::BoundaryViolation,
        format!("store boundary cannot be established: {error}"),
    )
}

fn store_error(error: std::io::Error) -> LeanStoreError {
    LeanStoreError::new(
        LeanStoreErrorKind::TreeDrift,
        format!("store operation failed: {error}"),
    )
}

fn tree_drift(message: impl Into<String>) -> LeanStoreError {
    LeanStoreError::new(LeanStoreErrorKind::TreeDrift, message)
}

fn lock_error<T>(_error: T) -> LeanStoreError {
    LeanStoreError::new(
        LeanStoreErrorKind::TerminalTaskFailure,
        "store task synchronization was poisoned",
    )
}

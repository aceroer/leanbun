use crate::{BuildError, BuildErrorKind, project_artifact_sha256_v1};
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_lock::LeanBunLockV1;
use leanbun_lock::{PackageKeyV1, PackageSourceKeyV1};
use rustix::fd::OwnedFd;
use rustix::fs::{FlockOperation, Mode, OFlags};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static SLOT_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageBuildContextV1 {
    pub lean_toolchain: String,
    pub compiler_githash: String,
    pub lake_version: String,
    pub platform: String,
    pub platform_abi_sha256: Sha256,
    pub build_policy_sha256: Sha256,
    pub facets_sha256: Sha256,
    pub environment_sha256: Sha256,
    pub lake_executable_sha256: Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageBuildDependencyV1 {
    package: PackageKeyV1,
    build: PackageBuildKeyV1,
}

impl PackageBuildDependencyV1 {
    #[must_use]
    pub fn new(package: PackageKeyV1, build: PackageBuildKeyV1) -> Self {
        Self { package, build }
    }

    #[must_use]
    pub fn package(&self) -> &PackageKeyV1 {
        &self.package
    }

    #[must_use]
    pub const fn build(&self) -> PackageBuildKeyV1 {
        self.build
    }
}

/// Recursive identity for one globally reusable compiled Lean package.
///
/// Project, environment and root-generation identities are deliberately absent.
/// Every direct dependency identity is included with its package key, so an
/// upstream change invalidates precisely the packages above that edge.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageBuildKeyV1(Sha256);

impl PackageBuildKeyV1 {
    pub fn new(
        source: PackageSourceKeyV1,
        context: &PackageBuildContextV1,
        mut dependencies: Vec<PackageBuildDependencyV1>,
    ) -> Result<Self, BuildError> {
        for (value, label, maximum) in [
            (&context.lean_toolchain, "Lean toolchain", 512),
            (&context.compiler_githash, "compiler githash", 128),
            (&context.lake_version, "Lake version", 128),
            (&context.platform, "platform", 256),
        ] {
            validate_text(value, maximum, label)?;
        }
        dependencies.sort_by(|left, right| left.package.cmp(&right.package));
        if dependencies
            .windows(2)
            .any(|pair| pair[0].package == pair[1].package)
        {
            return Err(invalid("duplicate direct package-build dependency"));
        }
        if dependencies.len() > 4_096 {
            return Err(invalid(
                "direct package-build dependency count exceeds limit",
            ));
        }
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-package-build-v1\0");
        hasher.update(source.digest().as_bytes());
        hash_text(&mut hasher, &context.lean_toolchain);
        hash_text(&mut hasher, &context.compiler_githash);
        hash_text(&mut hasher, &context.lake_version);
        hash_text(&mut hasher, &context.platform);
        for digest in [
            context.platform_abi_sha256,
            context.build_policy_sha256,
            context.facets_sha256,
            context.environment_sha256,
            context.lake_executable_sha256,
        ] {
            hasher.update(digest.as_bytes());
        }
        hasher.update(&(dependencies.len() as u64).to_be_bytes());
        for dependency in dependencies {
            hash_text(&mut hasher, dependency.package.scope());
            hash_text(&mut hasher, dependency.package.name());
            hasher.update(dependency.build.digest().as_bytes());
        }
        Ok(Self(hasher.finalize()))
    }

    #[must_use]
    pub const fn digest(self) -> Sha256 {
        self.0
    }
}

/// Derives eligible package keys in dependency order. A path package, or a Git
/// package depending on any non-global package, is intentionally absent.
pub fn package_build_keys_v1(
    lock: &LeanBunLockV1,
    context: &PackageBuildContextV1,
) -> Result<BTreeMap<PackageKeyV1, PackageBuildKeyV1>, BuildError> {
    let packages = lock
        .packages()
        .iter()
        .map(|package| (package.key().clone(), package))
        .collect::<BTreeMap<_, _>>();
    let mut resolved = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    for key in packages.keys() {
        derive_package_key(key, &packages, context, &mut resolved, &mut visiting)?;
    }
    Ok(resolved)
}

fn derive_package_key(
    key: &PackageKeyV1,
    packages: &BTreeMap<PackageKeyV1, &leanbun_lock::LockedLeanPackageV1>,
    context: &PackageBuildContextV1,
    resolved: &mut BTreeMap<PackageKeyV1, PackageBuildKeyV1>,
    visiting: &mut BTreeSet<PackageKeyV1>,
) -> Result<Option<PackageBuildKeyV1>, BuildError> {
    if let Some(value) = resolved.get(key) {
        return Ok(Some(*value));
    }
    if !visiting.insert(key.clone()) {
        return Err(invalid("package-build dependency graph contains a cycle"));
    }
    let package = packages
        .get(key)
        .ok_or_else(|| invalid("package-build dependency is absent from lock"))?;
    let Some(source) = PackageSourceKeyV1::from_locked_package(package) else {
        visiting.remove(key);
        return Ok(None);
    };
    let mut dependencies = Vec::with_capacity(package.dependencies().len());
    for dependency in package.dependencies() {
        let Some(build) =
            derive_package_key(dependency.package(), packages, context, resolved, visiting)?
        else {
            visiting.remove(key);
            return Ok(None);
        };
        dependencies.push(PackageBuildDependencyV1::new(
            dependency.package().clone(),
            build,
        ));
    }
    let build = PackageBuildKeyV1::new(source, context, dependencies)?;
    visiting.remove(key);
    resolved.insert(key.clone(), build);
    Ok(Some(build))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageArtifactOutcomeV1 {
    Published,
    Reused,
    Materialized,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PackageArtifactStoreFaultV1 {
    #[default]
    None,
    AfterTree,
    AfterRecord,
    AfterRename,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageArtifactObjectV1 {
    key: PackageBuildKeyV1,
    artifact_sha256: Sha256,
    object_path: PathBuf,
    outcome: PackageArtifactOutcomeV1,
}

impl PackageArtifactObjectV1 {
    #[must_use]
    pub const fn key(&self) -> PackageBuildKeyV1 {
        self.key
    }
    #[must_use]
    pub const fn artifact_sha256(&self) -> Sha256 {
        self.artifact_sha256
    }
    #[must_use]
    pub fn object_path(&self) -> &Path {
        &self.object_path
    }
    #[must_use]
    pub const fn outcome(&self) -> PackageArtifactOutcomeV1 {
        self.outcome
    }
}

#[derive(Clone, Debug)]
pub struct PackageArtifactStoreV1 {
    root: PathBuf,
}

struct Lease {
    _descriptor: OwnedFd,
}

impl PackageArtifactStoreV1 {
    pub fn open_global(development_root: impl AsRef<Path>) -> Result<Self, BuildError> {
        let development = development_root.as_ref().canonicalize().map_err(io)?;
        let root = development.join("store-fixture/m51-package-builds");
        create_private_dir(&development.join("store-fixture"))?;
        create_private_dir(&root)?;
        for child in ["objects", "leases", "slots"] {
            create_private_dir(&root.join(child))?;
        }
        let root = root.canonicalize().map_err(io)?;
        if !root.starts_with(&development) {
            return Err(boundary("package artifact Store escaped development root"));
        }
        Ok(Self { root })
    }

    #[must_use]
    pub fn store_root(&self) -> &Path {
        &self.root
    }

    pub fn publish_or_reuse(
        &self,
        key: PackageBuildKeyV1,
        candidate: &Path,
    ) -> Result<PackageArtifactObjectV1, BuildError> {
        self.publish_or_reuse_with_fault(key, candidate, PackageArtifactStoreFaultV1::None)
    }

    pub fn publish_or_reuse_with_fault(
        &self,
        key: PackageBuildKeyV1,
        candidate: &Path,
        fault: PackageArtifactStoreFaultV1,
    ) -> Result<PackageArtifactObjectV1, BuildError> {
        let candidate = candidate.canonicalize().map_err(io)?;
        if !candidate.is_dir() || candidate.starts_with(&self.root) {
            return Err(boundary(
                "candidate package artifact must be an external directory",
            ));
        }
        let artifact = project_artifact_sha256_v1(&candidate)?;
        let object = self.object_path(key);
        if object.exists() {
            let lease = self.acquire(key)?;
            drop(lease);
            return self.verify_expected(key, Some(artifact), PackageArtifactOutcomeV1::Reused);
        }
        let slot = self.root.join("slots").join(format!(
            "{}-{}",
            std::process::id(),
            SLOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_dir(&slot)?;
        let staged = slot.join("object");
        create_private_dir(&staged)?;
        copy_tree(&candidate, &staged.join("tree"), false)?;
        inject(fault, PackageArtifactStoreFaultV1::AfterTree)?;
        let record = record_bytes(key, artifact);
        let record_path = staged.join("artifact.meta");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&record_path)
            .map_err(io)?;
        file.write_all(record.as_bytes()).map_err(io)?;
        file.sync_all().map_err(io)?;
        sync_tree(&staged).map_err(|error| contextual("sync staged package artifact", error))?;
        set_tree_read_only(&staged)
            .map_err(|error| contextual("seal staged package artifact", error))?;
        // Some macOS volumes reject renaming a directory whose own write bit
        // is cleared. Contents are already sealed; keep only the transaction
        // envelope writable until the atomic rename, then seal it immediately.
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).map_err(io)?;
        inject(fault, PackageArtifactStoreFaultV1::AfterRecord)?;
        // Copying and fsyncing a large Mathlib package can take much longer
        // than the bounded lease wait.  Prepare the private slot first; hold
        // the cross-process lease only for the final compare-and-publish step.
        let lease = self.acquire(key)?;
        if object.exists() {
            make_tree_writable(&slot);
            fs::remove_dir_all(&slot).map_err(io)?;
            drop(lease);
            return self.verify_expected(key, Some(artifact), PackageArtifactOutcomeV1::Reused);
        }
        fs::rename(&staged, &object)
            .map_err(|error| contextual("rename staged package artifact", io(error)))?;
        fs::set_permissions(&object, fs::Permissions::from_mode(0o500)).map_err(io)?;
        sync_dir(&self.root.join("objects"))
            .map_err(|error| contextual("sync package artifact object directory", error))?;
        inject(fault, PackageArtifactStoreFaultV1::AfterRename)?;
        let _ = fs::remove_dir_all(&slot);
        drop(lease);
        self.verify_expected(key, Some(artifact), PackageArtifactOutcomeV1::Published)
    }

    pub fn materialize_if_present(
        &self,
        key: PackageBuildKeyV1,
        destination: &Path,
    ) -> Result<Option<PackageArtifactObjectV1>, BuildError> {
        if !self.object_path(key).exists() {
            return Ok(None);
        }
        if destination.exists() {
            return Err(boundary("package artifact destination already exists"));
        }
        let verified = self.verify_expected(key, None, PackageArtifactOutcomeV1::Materialized)?;
        let parent = destination
            .parent()
            .ok_or_else(|| boundary("package artifact destination has no parent"))?;
        let temporary = parent.join(format!(
            ".leanbun-build-{}-{}.tmp",
            std::process::id(),
            SLOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        if temporary.exists() {
            return Err(BuildError::new(
                BuildErrorKind::RecordDrift,
                "package artifact materialization staging already exists",
            ));
        }
        if let Err(error) = copy_tree(&verified.object_path.join("tree"), &temporary, true)
            .and_then(|()| {
                if project_artifact_sha256_v1(&temporary)? != verified.artifact_sha256 {
                    return Err(BuildError::new(
                        BuildErrorKind::ArtifactDrift,
                        "materialized package artifact differs before publication",
                    ));
                }
                fs::rename(&temporary, destination).map_err(io)
            })
        {
            make_tree_writable(&temporary);
            let _ = fs::remove_dir_all(&temporary);
            return Err(error);
        }
        Ok(Some(verified))
    }

    pub fn verify(&self, key: PackageBuildKeyV1) -> Result<PackageArtifactObjectV1, BuildError> {
        self.verify_expected(key, None, PackageArtifactOutcomeV1::Reused)
    }

    fn verify_expected(
        &self,
        key: PackageBuildKeyV1,
        expected: Option<Sha256>,
        outcome: PackageArtifactOutcomeV1,
    ) -> Result<PackageArtifactObjectV1, BuildError> {
        let object = self.object_path(key);
        let record = fs::read_to_string(object.join("artifact.meta")).map_err(io)?;
        let artifact = parse_record(&record, key)?;
        if expected.is_some_and(|value| value != artifact)
            || project_artifact_sha256_v1(&object.join("tree"))? != artifact
        {
            return Err(BuildError::new(
                BuildErrorKind::ArtifactDrift,
                "package artifact bytes drifted",
            ));
        }
        if tree_has_writable_entry(&object)? {
            return Err(BuildError::new(
                BuildErrorKind::RecordDrift,
                "published package artifact is writable",
            ));
        }
        Ok(PackageArtifactObjectV1 {
            key,
            artifact_sha256: artifact,
            object_path: object,
            outcome,
        })
    }

    fn acquire(&self, key: PackageBuildKeyV1) -> Result<Lease, BuildError> {
        let path = self
            .root
            .join("leases")
            .join(format!("{}.lock", key.digest()));
        let fd = rustix::fs::open(
            &path,
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| io(std::io::Error::from(error)))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Lease { _descriptor: fd }),
                Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    return Err(BuildError::new(
                        BuildErrorKind::LockBusy,
                        "package artifact lease timed out",
                    ));
                }
                Err(error) => return Err(io(std::io::Error::from(error))),
            }
        }
    }

    fn object_path(&self, key: PackageBuildKeyV1) -> PathBuf {
        self.root.join("objects").join(key.digest().to_string())
    }
}

fn record_bytes(key: PackageBuildKeyV1, artifact: Sha256) -> String {
    format!(
        "leanbun-package-artifact-v1\t1\nkey\t{}\nartifact\t{}\n",
        key.digest(),
        artifact
    )
}

fn parse_record(text: &str, key: PackageBuildKeyV1) -> Result<Sha256, BuildError> {
    let prefix = format!(
        "leanbun-package-artifact-v1\t1\nkey\t{}\nartifact\t",
        key.digest()
    );
    let value = text
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix('\n'))
        .ok_or_else(|| {
            BuildError::new(
                BuildErrorKind::RecordDrift,
                "package artifact record drifted",
            )
        })?;
    Sha256::parse(value).map_err(|_| {
        BuildError::new(
            BuildErrorKind::RecordDrift,
            "package artifact digest is invalid",
        )
    })
}

fn copy_tree(source: &Path, destination: &Path, writable: bool) -> Result<(), BuildError> {
    create_private_dir(destination)?;
    for entry in fs::read_dir(source).map_err(io)? {
        let entry = entry.map_err(io)?;
        let kind = entry.file_type().map_err(io)?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target, writable)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target).map_err(io)?;
            let mode = entry.metadata().map_err(io)?.permissions().mode() & 0o111;
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(if writable { 0o600 | mode } else { 0o400 | mode }),
            )
            .map_err(io)?;
        } else {
            return Err(boundary(
                "package artifact contains a symlink or special file",
            ));
        }
    }
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(if writable { 0o700 } else { 0o500 }),
    )
    .map_err(io)
}

fn set_tree_read_only(root: &Path) -> Result<(), BuildError> {
    for entry in fs::read_dir(root).map_err(io)? {
        let entry = entry.map_err(io)?;
        let metadata = entry.metadata().map_err(io)?;
        if metadata.is_dir() {
            set_tree_read_only(&entry.path())?;
        } else if metadata.is_file() {
            fs::set_permissions(
                entry.path(),
                fs::Permissions::from_mode(0o400 | (metadata.permissions().mode() & 0o111)),
            )
            .map_err(io)?;
        } else {
            return Err(boundary("package artifact contains a special entry"));
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o500)).map_err(io)
}

fn make_tree_writable(root: &Path) {
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return;
    };
    if metadata.is_dir() {
        let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                make_tree_writable(&entry.path());
            }
        }
    } else if metadata.is_file() {
        let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o600));
    }
}

fn sync_tree(root: &Path) -> Result<(), BuildError> {
    for entry in fs::read_dir(root).map_err(io)? {
        let entry = entry.map_err(io)?;
        if entry.file_type().map_err(io)?.is_dir() {
            sync_tree(&entry.path())?;
        } else {
            OpenOptions::new()
                .read(true)
                .open(entry.path())
                .map_err(io)?
                .sync_all()
                .map_err(io)?;
        }
    }
    sync_dir(root)
}

fn sync_dir(path: &Path) -> Result<(), BuildError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(io)?
        .sync_all()
        .map_err(io)
}

fn create_private_dir(path: &Path) -> Result<(), BuildError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io(error)),
    }
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.file_type().is_dir() {
        return Err(boundary(
            "package artifact Store path is not a direct directory",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io)
}

fn tree_has_writable_entry(path: &Path) -> Result<bool, BuildError> {
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if metadata.permissions().mode() & 0o222 != 0 {
        return Ok(true);
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(io)? {
            if tree_has_writable_entry(&entry.map_err(io)?.path())? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn inject(
    actual: PackageArtifactStoreFaultV1,
    expected: PackageArtifactStoreFaultV1,
) -> Result<(), BuildError> {
    if actual == expected {
        Err(BuildError::new(
            BuildErrorKind::Io,
            format!("M51C fault injected at {expected:?}"),
        ))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), BuildError> {
    if value.is_empty() || value.len() > maximum || value.contains(['\0', '\n', '\r']) {
        Err(invalid(format!("{label} is empty or non-canonical")))
    } else {
        Ok(())
    }
}

fn hash_text(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn invalid(message: impl Into<String>) -> BuildError {
    BuildError::new(BuildErrorKind::InvalidField, message)
}
fn boundary(message: impl Into<String>) -> BuildError {
    BuildError::new(BuildErrorKind::BoundaryViolation, message)
}
fn io(error: std::io::Error) -> BuildError {
    BuildError::new(BuildErrorKind::Io, error.to_string())
}

fn contextual(context: &str, error: BuildError) -> BuildError {
    BuildError::new(error.kind, format!("{context}: {}", error.message))
}

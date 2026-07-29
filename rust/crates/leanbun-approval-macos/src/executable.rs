use core::fmt;
use leanbun_core::Sha256Hasher;
use leanbun_plan::{
    LakeCommandPlanV1, LakeExecutableObservationV1, PlanExecutionAuthorityV1,
    SUPPORTED_LAKE_VERSION, verify_lake_update_plan_contract_v1,
};
use rustix::fs::{FileType, Mode, OFlags, Stat};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LAKE_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

pub struct TrustedLakeExecutableObservationV1 {
    pub(crate) observation: LakeExecutableObservationV1,
    pub(crate) observed_at_unix_ms: u64,
}

impl TrustedLakeExecutableObservationV1 {
    #[must_use]
    pub fn observation(&self) -> &LakeExecutableObservationV1 {
        &self.observation
    }

    #[must_use]
    pub fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsLakeExecutableObservationRejectionV1 {
    InvalidToolchainRoot,
    ReviewedPathMismatch,
    UnsafeMetadata,
    ExecutableTooLarge,
    ReadFailed,
    ChangedDuringRead,
    ReviewedIdentityMismatch,
    ClockInvalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsLakeExecutableObservationError {
    pub rejection: MacOsLakeExecutableObservationRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsLakeExecutableObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsLakeExecutableObservationError {}

pub fn observe_reviewed_lake_executable_v1(
    managed_toolchain_root: &Path,
    reviewed_plan: &LakeCommandPlanV1,
) -> Result<TrustedLakeExecutableObservationV1, MacOsLakeExecutableObservationError> {
    observe_with_hook_v1(managed_toolchain_root, reviewed_plan, || Ok(()))
}

fn observe_with_hook_v1(
    managed_toolchain_root: &Path,
    reviewed_plan: &LakeCommandPlanV1,
    after_open: impl FnOnce() -> std::io::Result<()>,
) -> Result<TrustedLakeExecutableObservationV1, MacOsLakeExecutableObservationError> {
    if !managed_toolchain_root.is_absolute() {
        return Err(observation_error(
            MacOsLakeExecutableObservationRejectionV1::InvalidToolchainRoot,
            "managed toolchain root must be absolute",
        ));
    }
    let canonical_root = std::fs::canonicalize(managed_toolchain_root).map_err(|error| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::InvalidToolchainRoot,
            format!("cannot canonicalize managed toolchain root: {error}"),
        )
    })?;
    if canonical_root.join("bin/lake") != reviewed_plan.executable.as_path() {
        return Err(observation_error(
            MacOsLakeExecutableObservationRejectionV1::ReviewedPathMismatch,
            "reviewed executable is not the fixed bin/lake beneath the managed toolchain root",
        ));
    }
    if reviewed_plan.lake_version != SUPPORTED_LAKE_VERSION
        || reviewed_plan.execution_authority != PlanExecutionAuthorityV1::Withheld
    {
        return Err(observation_error(
            MacOsLakeExecutableObservationRejectionV1::ReviewedIdentityMismatch,
            "reviewed plan is outside the supported withheld Lake identity",
        ));
    }
    verify_lake_update_plan_contract_v1(reviewed_plan).map_err(|error| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::ReviewedIdentityMismatch,
            format!("reviewed Lake plan contract is invalid: {}", error.message),
        )
    })?;

    let root = open_directory(managed_toolchain_root, "managed toolchain root")?;
    let root_before = rustix::fs::fstat(&root).map_err(read_failed)?;
    verify_private_identity(&root_before, FileType::Directory, "managed toolchain root")?;
    let bin = rustix::fs::openat(
        &root,
        "bin",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::UnsafeMetadata,
            format!("cannot open direct bin directory: {error}"),
        )
    })?;
    let bin_before = rustix::fs::fstat(&bin).map_err(read_failed)?;
    verify_private_identity(&bin_before, FileType::Directory, "toolchain bin directory")?;
    let lake = rustix::fs::openat(
        &bin,
        "lake",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::UnsafeMetadata,
            format!("cannot open direct bin/lake file: {error}"),
        )
    })?;
    let lake_before = rustix::fs::fstat(&lake).map_err(read_failed)?;
    verify_private_identity(&lake_before, FileType::RegularFile, "Lake executable")?;
    let lake_mode = Mode::from_raw_mode(lake_before.st_mode);
    if !lake_mode.intersects(Mode::XUSR | Mode::XGRP | Mode::XOTH) || lake_before.st_size <= 0 {
        return Err(observation_error(
            MacOsLakeExecutableObservationRejectionV1::UnsafeMetadata,
            "Lake executable must be non-empty and executable",
        ));
    }
    let lake_size = u64::try_from(lake_before.st_size).map_err(|_| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::UnsafeMetadata,
            "Lake executable size is invalid",
        )
    })?;
    if lake_size > MAX_LAKE_EXECUTABLE_BYTES {
        return Err(observation_error(
            MacOsLakeExecutableObservationRejectionV1::ExecutableTooLarge,
            format!("Lake executable exceeds {MAX_LAKE_EXECUTABLE_BYTES} bytes"),
        ));
    }

    let mut lake: File = lake.into();
    after_open().map_err(|error| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::ReadFailed,
            format!("Lake executable observation hook failed: {error}"),
        )
    })?;
    let mut hasher = Sha256Hasher::new();
    let mut bytes_read = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = lake.read(&mut chunk).map_err(|error| {
            observation_error(
                MacOsLakeExecutableObservationRejectionV1::ReadFailed,
                format!("cannot read Lake executable: {error}"),
            )
        })?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                observation_error(
                    MacOsLakeExecutableObservationRejectionV1::ExecutableTooLarge,
                    "Lake executable byte count overflow",
                )
            })?;
        if bytes_read > MAX_LAKE_EXECUTABLE_BYTES {
            return Err(observation_error(
                MacOsLakeExecutableObservationRejectionV1::ExecutableTooLarge,
                "Lake executable grew beyond the bounded reader limit",
            ));
        }
        hasher.update(&chunk[..count]);
    }
    let lake_after = rustix::fs::fstat(&lake).map_err(read_failed)?;
    let reopened_root = open_directory(managed_toolchain_root, "managed toolchain root")?;
    let reopened_bin = rustix::fs::openat(
        &root,
        "bin",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(changed)?;
    let reopened_lake = rustix::fs::openat(
        &bin,
        "lake",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(changed)?;
    let canonical_after = std::fs::canonicalize(managed_toolchain_root).map_err(changed)?;
    if canonical_after != canonical_root
        || identity(&root_before) != identity(&rustix::fs::fstat(&reopened_root).map_err(changed)?)
        || identity(&bin_before) != identity(&rustix::fs::fstat(&reopened_bin).map_err(changed)?)
        || identity(&lake_before) != identity(&lake_after)
        || identity(&lake_before) != identity(&rustix::fs::fstat(&reopened_lake).map_err(changed)?)
        || bytes_read != lake_size
    {
        return Err(observation_error(
            MacOsLakeExecutableObservationRejectionV1::ChangedDuringRead,
            "managed toolchain path or Lake executable changed during observation",
        ));
    }

    let sha256 = hasher.finalize();
    let unix_mode = u32::from(lake_mode.as_raw_mode());
    if sha256 != reviewed_plan.executable_sha256
        || lake_size != reviewed_plan.executable_byte_length
        || unix_mode != reviewed_plan.executable_unix_mode
        || !reviewed_plan.executable_regular_file
        || !reviewed_plan.executable_symlink_free
    {
        return Err(observation_error(
            MacOsLakeExecutableObservationRejectionV1::ReviewedIdentityMismatch,
            "observed Lake executable differs from the reviewed plan",
        ));
    }
    let observed_at_unix_ms = current_unix_ms()?;
    Ok(TrustedLakeExecutableObservationV1 {
        observation: LakeExecutableObservationV1 {
            schema_version: 1,
            canonical_path: reviewed_plan.executable.clone(),
            lake_version: reviewed_plan.lake_version.clone(),
            sha256,
            byte_length: lake_size,
            unix_mode,
            regular_file: true,
            symlink_free: true,
        },
        observed_at_unix_ms,
    })
}

fn open_directory(
    path: &Path,
    label: &str,
) -> Result<std::os::fd::OwnedFd, MacOsLakeExecutableObservationError> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::InvalidToolchainRoot,
            format!("cannot open {label}: {error}"),
        )
    })
}

fn verify_private_identity(
    stat: &Stat,
    expected_type: FileType,
    label: &str,
) -> Result<(), MacOsLakeExecutableObservationError> {
    let mode = Mode::from_raw_mode(stat.st_mode);
    if FileType::from_raw_mode(stat.st_mode) != expected_type
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || mode.intersects(Mode::WGRP | Mode::WOTH)
    {
        return Err(observation_error(
            MacOsLakeExecutableObservationRejectionV1::UnsafeMetadata,
            format!("{label} must be effective-user-owned and not group/world writable"),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner_uid: u32,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn identity(stat: &Stat) -> FileIdentity {
    FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino,
        mode: stat.st_mode as u32,
        owner_uid: stat.st_uid,
        size: stat.st_size,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    }
}

fn current_unix_ms() -> Result<u64, MacOsLakeExecutableObservationError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::ClockInvalid,
            "system clock is before Unix epoch",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        observation_error(
            MacOsLakeExecutableObservationRejectionV1::ClockInvalid,
            "system clock is out of range",
        )
    })
}

fn read_failed(error: rustix::io::Errno) -> MacOsLakeExecutableObservationError {
    observation_error(
        MacOsLakeExecutableObservationRejectionV1::ReadFailed,
        format!("cannot inspect Lake executable identity: {error}"),
    )
}

fn changed(error: impl fmt::Display) -> MacOsLakeExecutableObservationError {
    observation_error(
        MacOsLakeExecutableObservationRejectionV1::ChangedDuringRead,
        format!("cannot reverify Lake executable path: {error}"),
    )
}

fn observation_error(
    rejection: MacOsLakeExecutableObservationRejectionV1,
    message: impl Into<String>,
) -> MacOsLakeExecutableObservationError {
    MacOsLakeExecutableObservationError {
        rejection,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanbun_core::Sha256;
    use leanbun_evidence::{canonicalize_contained, canonicalize_directory};
    use leanbun_plan::{
        CommandNetworkPolicyV1, CommandPermissionClassV1, LakeCommandFamilyV1, PlanRiskV1,
        PlannedEffectV1,
    };
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        lake: PathBuf,
        plan: LakeCommandPlanV1,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = PathBuf::from(format!(
                "/tmp/leanbun-executable-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("bin"))?;
            fs::create_dir(root.join("project"))?;
            let lake = root.join("bin/lake");
            fs::write(&lake, b"reviewed-lake-binary")?;
            fs::set_permissions(&lake, fs::Permissions::from_mode(0o755))?;
            let canonical_root = canonicalize_directory(&root)?;
            let canonical_lake = canonicalize_contained(&canonical_root, "bin/lake")?;
            let project =
                leanbun_evidence::canonicalize_contained_directory(&canonical_root, "project")?;
            let sha256 = bytes_sha256(b"reviewed-lake-binary");
            let plan = LakeCommandPlanV1 {
                schema_version: 1,
                family: LakeCommandFamilyV1::Update,
                lake_version: SUPPORTED_LAKE_VERSION.to_owned(),
                inventory_snapshot_sha256: Sha256::parse(&"5".repeat(64))?,
                executable: canonical_lake,
                executable_sha256: sha256,
                executable_byte_length: 20,
                executable_unix_mode: 0o755,
                executable_regular_file: true,
                executable_symlink_free: true,
                arguments: vec![
                    "--keep-toolchain".to_owned(),
                    "update".to_owned(),
                    "mathlib".to_owned(),
                ],
                cwd: project,
                environment_allowlist: vec!["PATH".to_owned()],
                permission_class: CommandPermissionClassV1::ExplicitExternalUpdate,
                network_policy: CommandNetworkPolicyV1::Required,
                expected_effects: vec![
                    PlannedEffectV1::LoadAndExecuteProjectConfiguration,
                    PlannedEffectV1::ReadPackageOverrides,
                    PlannedEffectV1::RewriteManifest,
                    PlannedEffectV1::CreateOrModifyLakeDirectory,
                    PlannedEffectV1::FetchRemotePackageContent,
                    PlannedEffectV1::CreateOrModifyPackageCheckouts,
                    PlannedEffectV1::ExecutePostUpdateHooks,
                ],
                risks: vec![
                    PlanRiskV1::UntrustedProjectConfigurationExecution,
                    PlanRiskV1::NetworkAndRemoteContent,
                    PlanRiskV1::ManifestRewrite,
                    PlanRiskV1::CheckoutMutation,
                    PlanRiskV1::LakeInternalStateMutation,
                    PlanRiskV1::PostUpdateHookExecution,
                    PlanRiskV1::ExecutablePropertiesRequireGateRecheck,
                ],
                execution_authority: PlanExecutionAuthorityV1::Withheld,
            };
            Ok(Self { root, lake, plan })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn bytes_sha256(bytes: &[u8]) -> Sha256 {
        let mut hasher = Sha256Hasher::new();
        hasher.update(bytes);
        hasher.finalize()
    }

    #[test]
    fn stable_direct_binary_matches_the_reviewed_plan() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let observed = observe_reviewed_lake_executable_v1(&fixture.root, &fixture.plan)?;
        assert_eq!(observed.observation.sha256, fixture.plan.executable_sha256);
        assert_eq!(observed.observation.byte_length, 20);
        assert_eq!(observed.observation.unix_mode, 0o755);
        assert!(observed.observation.regular_file);
        assert!(observed.observation.symlink_free);
        assert!(observed.observed_at_unix_ms > 0);
        Ok(())
    }

    #[test]
    fn symlink_and_writable_directory_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let moved = fixture.root.join("bin/real-lake");
        fs::rename(&fixture.lake, &moved)?;
        symlink(&moved, &fixture.lake)?;
        let symlink_error = match observe_reviewed_lake_executable_v1(&fixture.root, &fixture.plan)
        {
            Ok(_) => return Err("symlinked Lake executable was accepted".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            symlink_error,
            MacOsLakeExecutableObservationRejectionV1::UnsafeMetadata
        );

        fs::remove_file(&fixture.lake)?;
        fs::rename(&moved, &fixture.lake)?;
        fs::set_permissions(fixture.root.join("bin"), fs::Permissions::from_mode(0o777))?;
        let writable_error = match observe_reviewed_lake_executable_v1(&fixture.root, &fixture.plan)
        {
            Ok(_) => return Err("writable toolchain bin was accepted".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            writable_error,
            MacOsLakeExecutableObservationRejectionV1::UnsafeMetadata
        );
        Ok(())
    }

    #[test]
    fn content_and_path_replacement_drift_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::write(&fixture.lake, b"changed--lake-binary")?;
        let content_error = match observe_reviewed_lake_executable_v1(&fixture.root, &fixture.plan)
        {
            Ok(_) => return Err("changed Lake bytes were accepted".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            content_error,
            MacOsLakeExecutableObservationRejectionV1::ReviewedIdentityMismatch
        );

        fs::write(&fixture.lake, b"reviewed-lake-binary")?;
        fs::set_permissions(&fixture.lake, fs::Permissions::from_mode(0o755))?;
        let lake = fixture.lake.clone();
        let replacement_error = match observe_with_hook_v1(&fixture.root, &fixture.plan, || {
            let old = lake.with_extension("old");
            fs::rename(&lake, &old)?;
            fs::write(&lake, b"reviewed-lake-binary")?;
            fs::set_permissions(&lake, fs::Permissions::from_mode(0o755))?;
            Ok(())
        }) {
            Ok(_) => return Err("replaced Lake path was accepted".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            replacement_error,
            MacOsLakeExecutableObservationRejectionV1::ChangedDuringRead
        );
        Ok(())
    }

    #[test]
    fn oversized_binary_is_rejected_before_streaming() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        File::options()
            .write(true)
            .open(&fixture.lake)?
            .set_len(MAX_LAKE_EXECUTABLE_BYTES + 1)?;
        let error = match observe_reviewed_lake_executable_v1(&fixture.root, &fixture.plan) {
            Ok(_) => return Err("oversized Lake executable was accepted".into()),
            Err(error) => error.rejection,
        };
        assert_eq!(
            error,
            MacOsLakeExecutableObservationRejectionV1::ExecutableTooLarge
        );
        Ok(())
    }
}

use leanbun_macos_acl_sys::{
    MacOsAclMutationDecisionV1, MacOsAclReadErrorKindV1, observe_fd_acl_v1,
};
use leanbun_plan::PlanExecutionAuthorityV1;
use rustix::fs::{Access, AtFlags, FileType, Mode, OFlags, StatVfsMountFlags};
use std::ffi::OsString;
use std::fmt;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

const MAX_PATH_COMPONENTS: usize = 128;
const UF_IMMUTABLE: u32 = 0x0000_0002;
const SF_IMMUTABLE: u32 = 0x0002_0000;
const SF_NOUNLINK: u32 = 0x0010_0000;
const MNT_RDONLY: u64 = 0x0000_0001;
const MNT_NOEXEC: u64 = 0x0000_0004;
const MNT_LOCAL: u64 = 0x0000_1000;
const MNT_ROOTFS: u64 = 0x0000_4000;
const MNT_IGNORE_OWNERSHIP: u64 = 0x0020_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPathComponentKindV1 {
    RootDirectory,
    Directory,
    ExecutableFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsEffectiveWriteAccessV1 {
    Allowed,
    Denied,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclCoverageV1 {
    EffectiveUidOnly,
    ConservativeMutationAllowScan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsComponentAclDecisionV1 {
    NoMutationAllowEntry,
    DeniedMutationAllowEntry,
    DeniedUnknownAllowPermission,
    Unsupported,
    Unverified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsPathComponentProvenanceV1 {
    pub path: PathBuf,
    pub kind: MacOsPathComponentKindV1,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub unix_mode: u32,
    pub darwin_flags: u32,
    pub user_immutable: bool,
    pub system_immutable: bool,
    pub system_nounlink: bool,
    pub effective_uid_write_access: MacOsEffectiveWriteAccessV1,
    pub acl_decision: MacOsComponentAclDecisionV1,
    pub acl_entry_count: u16,
    pub acl_mutation_allow_mask: u64,
    pub acl_unknown_allow_mask: u64,
    pub mount_fsid: u64,
    pub mount_flags: u64,
    pub mount_read_only: bool,
    pub native_mount_flags: u64,
    pub native_mount_read_only: bool,
    pub native_mount_noexec: bool,
    pub native_mount_local: bool,
    pub native_mount_rootfs: bool,
    pub native_mount_ignores_ownership: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPathProvenanceDecisionV1 {
    DeniedUserOwnedComponent,
    DeniedEffectiveUidWriteAccess,
    DeniedGroupOrWorldWritable,
    DeniedEffectiveAccessUnverified,
    DeniedAclMutationAllowEntry,
    DeniedAclCoverageUnverified,
    DeniedMountOrWriterContinuityUnverified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsPathProvenanceObservationV1 {
    pub schema_version: u8,
    pub executable: PathBuf,
    pub effective_uid: u32,
    pub acl_coverage: MacOsAclCoverageV1,
    pub components: Vec<MacOsPathComponentProvenanceV1>,
    pub decision: MacOsPathProvenanceDecisionV1,
    pub execution_authority: PlanExecutionAuthorityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPathProvenanceRejectionV1 {
    InvalidPath,
    TooManyComponents,
    OpenFailed,
    UnsafeFileType,
    ExecutableModeMissing,
    MetadataReadFailed,
    ChangedDuringObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsPathProvenanceError {
    pub rejection: MacOsPathProvenanceRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsPathProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsPathProvenanceError {}

struct OpenedComponent {
    fd: OwnedFd,
    path: PathBuf,
    kind: MacOsPathComponentKindV1,
    fingerprint: ComponentFingerprint,
    mount_fsid: u64,
    mount_flags: u64,
    native_mount_flags: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ComponentFingerprint {
    device: u64,
    inode: u64,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    flags: u32,
    size: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

/// Observes every direct component from `/` through an executable path.
///
/// The observer is read-only and fail-closed. Its ACL coverage is deliberately
/// limited to the effective-UID result exposed by safe `accessat`; it neither
/// enumerates ACL principals nor grants production eligibility.
pub fn observe_macos_path_provenance_v1(
    executable: &Path,
) -> Result<MacOsPathProvenanceObservationV1, MacOsPathProvenanceError> {
    let names = direct_component_names(executable)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let root = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| provenance_error(MacOsPathProvenanceRejectionV1::OpenFailed, error))?;

    let root_access = observe_write_access(&root, ".");
    let mut opened = Vec::with_capacity(names.len() + 1);
    let mut components = Vec::with_capacity(names.len() + 1);
    push_component(
        &mut opened,
        &mut components,
        root,
        PathBuf::from("/"),
        MacOsPathComponentKindV1::RootDirectory,
        root_access,
    )?;

    let mut current_path = PathBuf::from("/");
    for (index, name) in names.iter().enumerate() {
        let is_leaf = index + 1 == names.len();
        let parent = match opened.last() {
            Some(parent) => &parent.fd,
            None => {
                return Err(provenance_message(
                    MacOsPathProvenanceRejectionV1::MetadataReadFailed,
                    "path observer lost the root capability",
                ));
            }
        };
        let access = observe_write_access(parent, name);
        let flags = if is_leaf {
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
        };
        let fd = rustix::fs::openat(parent, name, flags, Mode::empty())
            .map_err(|error| provenance_error(MacOsPathProvenanceRejectionV1::OpenFailed, error))?;
        current_path.push(name);
        push_component(
            &mut opened,
            &mut components,
            fd,
            current_path.clone(),
            if is_leaf {
                MacOsPathComponentKindV1::ExecutableFile
            } else {
                MacOsPathComponentKindV1::Directory
            },
            access,
        )?;
    }

    verify_stable_components(&opened)?;
    let acl_coverage = if components.iter().all(|component| {
        component.acl_decision == MacOsComponentAclDecisionV1::NoMutationAllowEntry
    }) {
        MacOsAclCoverageV1::ConservativeMutationAllowScan
    } else {
        MacOsAclCoverageV1::EffectiveUidOnly
    };
    let decision = classify_components(effective_uid, &components);
    Ok(MacOsPathProvenanceObservationV1 {
        schema_version: 1,
        executable: executable.to_path_buf(),
        effective_uid,
        acl_coverage,
        components,
        decision,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

fn direct_component_names(path: &Path) -> Result<Vec<OsString>, MacOsPathProvenanceError> {
    if !path.is_absolute() {
        return Err(provenance_message(
            MacOsPathProvenanceRejectionV1::InvalidPath,
            "executable path must be absolute",
        ));
    }
    let mut saw_root = false;
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if !saw_root && names.is_empty() => saw_root = true,
            Component::Normal(name) if saw_root => names.push(name.to_os_string()),
            _ => {
                return Err(provenance_message(
                    MacOsPathProvenanceRejectionV1::InvalidPath,
                    "executable path must contain only direct normal components after root",
                ));
            }
        }
    }
    if !saw_root || names.is_empty() {
        return Err(provenance_message(
            MacOsPathProvenanceRejectionV1::InvalidPath,
            "executable path must name a file below root",
        ));
    }
    if names.len() > MAX_PATH_COMPONENTS {
        return Err(provenance_message(
            MacOsPathProvenanceRejectionV1::TooManyComponents,
            "executable path exceeds the component limit",
        ));
    }
    Ok(names)
}

fn observe_write_access<Fd: std::os::fd::AsFd>(
    parent: Fd,
    name: impl rustix::path::Arg,
) -> MacOsEffectiveWriteAccessV1 {
    match rustix::fs::accessat(
        parent,
        name,
        Access::WRITE_OK,
        AtFlags::EACCESS | AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(()) => MacOsEffectiveWriteAccessV1::Allowed,
        Err(rustix::io::Errno::ACCESS | rustix::io::Errno::PERM) => {
            MacOsEffectiveWriteAccessV1::Denied
        }
        Err(_) => MacOsEffectiveWriteAccessV1::Unverified,
    }
}

fn push_component(
    opened: &mut Vec<OpenedComponent>,
    components: &mut Vec<MacOsPathComponentProvenanceV1>,
    fd: OwnedFd,
    path: PathBuf,
    kind: MacOsPathComponentKindV1,
    access: MacOsEffectiveWriteAccessV1,
) -> Result<(), MacOsPathProvenanceError> {
    let stat = rustix::fs::fstat(&fd).map_err(|error| {
        provenance_error(MacOsPathProvenanceRejectionV1::MetadataReadFailed, error)
    })?;
    let expected = match kind {
        MacOsPathComponentKindV1::RootDirectory | MacOsPathComponentKindV1::Directory => {
            FileType::Directory
        }
        MacOsPathComponentKindV1::ExecutableFile => FileType::RegularFile,
    };
    if FileType::from_raw_mode(stat.st_mode) != expected {
        return Err(provenance_message(
            MacOsPathProvenanceRejectionV1::UnsafeFileType,
            "path component has an unexpected file type",
        ));
    }
    let mode = Mode::from_raw_mode(stat.st_mode);
    if kind == MacOsPathComponentKindV1::ExecutableFile
        && !mode.intersects(Mode::XUSR | Mode::XGRP | Mode::XOTH)
    {
        return Err(provenance_message(
            MacOsPathProvenanceRejectionV1::ExecutableModeMissing,
            "leaf path is not executable",
        ));
    }
    let mount = rustix::fs::fstatvfs(&fd).map_err(|error| {
        provenance_error(MacOsPathProvenanceRejectionV1::MetadataReadFailed, error)
    })?;
    let native_mount = rustix::fs::fstatfs(&fd).map_err(|error| {
        provenance_error(MacOsPathProvenanceRejectionV1::MetadataReadFailed, error)
    })?;
    let native_mount_flags = native_mount.f_flags as u64;
    let (acl_decision, acl_entry_count, acl_mutation_allow_mask, acl_unknown_allow_mask) =
        match observe_fd_acl_v1(fd.as_fd()) {
            Ok(summary) => (
                match summary.decision {
                    MacOsAclMutationDecisionV1::NoMutationAllowEntry => {
                        MacOsComponentAclDecisionV1::NoMutationAllowEntry
                    }
                    MacOsAclMutationDecisionV1::DeniedMutationAllowEntry => {
                        MacOsComponentAclDecisionV1::DeniedMutationAllowEntry
                    }
                    MacOsAclMutationDecisionV1::DeniedUnknownAllowPermission => {
                        MacOsComponentAclDecisionV1::DeniedUnknownAllowPermission
                    }
                },
                summary.entry_count,
                summary.mutation_allow_mask,
                summary.unknown_allow_mask,
            ),
            Err(error) if error.kind == MacOsAclReadErrorKindV1::Unsupported => {
                (MacOsComponentAclDecisionV1::Unsupported, 0, 0, 0)
            }
            Err(_) => (MacOsComponentAclDecisionV1::Unverified, 0, 0, 0),
        };
    let mount_flags = mount.f_flag.bits();
    let fingerprint = fingerprint(&stat, kind);
    components.push(MacOsPathComponentProvenanceV1 {
        path: path.clone(),
        kind,
        device: fingerprint.device,
        inode: fingerprint.inode,
        owner_uid: fingerprint.owner_uid,
        owner_gid: fingerprint.owner_gid,
        unix_mode: fingerprint.mode,
        darwin_flags: fingerprint.flags,
        user_immutable: fingerprint.flags & UF_IMMUTABLE != 0,
        system_immutable: fingerprint.flags & SF_IMMUTABLE != 0,
        system_nounlink: fingerprint.flags & SF_NOUNLINK != 0,
        effective_uid_write_access: access,
        acl_decision,
        acl_entry_count,
        acl_mutation_allow_mask,
        acl_unknown_allow_mask,
        mount_fsid: mount.f_fsid,
        mount_flags,
        mount_read_only: mount.f_flag.contains(StatVfsMountFlags::RDONLY),
        native_mount_flags,
        native_mount_read_only: native_mount_flags & MNT_RDONLY != 0,
        native_mount_noexec: native_mount_flags & MNT_NOEXEC != 0,
        native_mount_local: native_mount_flags & MNT_LOCAL != 0,
        native_mount_rootfs: native_mount_flags & MNT_ROOTFS != 0,
        native_mount_ignores_ownership: native_mount_flags & MNT_IGNORE_OWNERSHIP != 0,
    });
    opened.push(OpenedComponent {
        fd,
        path: path.clone(),
        kind,
        fingerprint,
        mount_fsid: mount.f_fsid,
        mount_flags,
        native_mount_flags,
    });
    Ok(())
}

fn verify_stable_components(opened: &[OpenedComponent]) -> Result<(), MacOsPathProvenanceError> {
    for component in opened {
        let stat = rustix::fs::fstat(&component.fd).map_err(|error| {
            provenance_error(MacOsPathProvenanceRejectionV1::MetadataReadFailed, error)
        })?;
        let mount = rustix::fs::fstatvfs(&component.fd).map_err(|error| {
            provenance_error(MacOsPathProvenanceRejectionV1::MetadataReadFailed, error)
        })?;
        let native_mount = rustix::fs::fstatfs(&component.fd).map_err(|error| {
            provenance_error(MacOsPathProvenanceRejectionV1::MetadataReadFailed, error)
        })?;
        let current_fingerprint = fingerprint(&stat, component.kind);
        let current_mount_flags = mount.f_flag.bits();
        let current_native_mount_flags = native_mount.f_flags as u64;
        if current_fingerprint != component.fingerprint
            || mount.f_fsid != component.mount_fsid
            || current_mount_flags != component.mount_flags
            || current_native_mount_flags != component.native_mount_flags
        {
            return Err(provenance_message(
                MacOsPathProvenanceRejectionV1::ChangedDuringObservation,
                format!(
                    "path component or mount changed during provenance observation: {} fingerprint={} fsid={} mount-flags={} native-flags={}",
                    component.path.display(),
                    current_fingerprint != component.fingerprint,
                    mount.f_fsid != component.mount_fsid,
                    current_mount_flags != component.mount_flags,
                    current_native_mount_flags != component.native_mount_flags,
                ),
            ));
        }
    }
    Ok(())
}

fn classify_components(
    effective_uid: u32,
    components: &[MacOsPathComponentProvenanceV1],
) -> MacOsPathProvenanceDecisionV1 {
    if components
        .iter()
        .any(|component| component.owner_uid == effective_uid)
    {
        return MacOsPathProvenanceDecisionV1::DeniedUserOwnedComponent;
    }
    if components.iter().any(|component| {
        component.effective_uid_write_access == MacOsEffectiveWriteAccessV1::Allowed
    }) {
        return MacOsPathProvenanceDecisionV1::DeniedEffectiveUidWriteAccess;
    }
    if components
        .iter()
        .any(|component| component.unix_mode & 0o022 != 0)
    {
        return MacOsPathProvenanceDecisionV1::DeniedGroupOrWorldWritable;
    }
    if components.iter().any(|component| {
        component.effective_uid_write_access == MacOsEffectiveWriteAccessV1::Unverified
    }) {
        return MacOsPathProvenanceDecisionV1::DeniedEffectiveAccessUnverified;
    }
    if components.iter().any(|component| {
        matches!(
            component.acl_decision,
            MacOsComponentAclDecisionV1::DeniedMutationAllowEntry
                | MacOsComponentAclDecisionV1::DeniedUnknownAllowPermission
        )
    }) {
        return MacOsPathProvenanceDecisionV1::DeniedAclMutationAllowEntry;
    }
    if components.iter().any(|component| {
        matches!(
            component.acl_decision,
            MacOsComponentAclDecisionV1::Unsupported | MacOsComponentAclDecisionV1::Unverified
        )
    }) {
        return MacOsPathProvenanceDecisionV1::DeniedAclCoverageUnverified;
    }
    MacOsPathProvenanceDecisionV1::DeniedMountOrWriterContinuityUnverified
}

fn fingerprint(stat: &rustix::fs::Stat, kind: MacOsPathComponentKindV1) -> ComponentFingerprint {
    let stable_file_metadata = kind == MacOsPathComponentKindV1::ExecutableFile;
    ComponentFingerprint {
        device: stat.st_dev as u64,
        inode: stat.st_ino,
        mode: stat.st_mode as u32,
        owner_uid: stat.st_uid,
        owner_gid: stat.st_gid,
        flags: stat.st_flags,
        size: if stable_file_metadata {
            stat.st_size
        } else {
            0
        },
        changed_seconds: if stable_file_metadata {
            stat.st_ctime
        } else {
            0
        },
        changed_nanoseconds: if stable_file_metadata {
            stat.st_ctime_nsec
        } else {
            0
        },
    }
}

fn provenance_error(
    rejection: MacOsPathProvenanceRejectionV1,
    error: impl fmt::Display,
) -> MacOsPathProvenanceError {
    provenance_message(
        rejection,
        format!("path provenance observation failed: {error}"),
    )
}

fn provenance_message(
    rejection: MacOsPathProvenanceRejectionV1,
    message: impl Into<String>,
) -> MacOsPathProvenanceError {
    MacOsPathProvenanceError {
        rejection,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        executable: PathBuf,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = PathBuf::from(format!(
                "/private/tmp/leanbun-path-provenance-{}-{sequence}",
                std::process::id()
            ));
            let executable = root.join("toolchain/bin/lake");
            fs::create_dir_all(executable.parent().ok_or("missing executable parent")?)?;
            fs::write(&executable, b"fixture")?;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
            Ok(Self { root, executable })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn user_owned_fixture_is_observed_and_denied_without_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let observation = observe_macos_path_provenance_v1(&fixture.executable)?;

        assert_eq!(
            observation.decision,
            MacOsPathProvenanceDecisionV1::DeniedUserOwnedComponent
        );
        assert!(matches!(
            observation.acl_coverage,
            MacOsAclCoverageV1::ConservativeMutationAllowScan
                | MacOsAclCoverageV1::EffectiveUidOnly
        ));
        assert_eq!(
            observation.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        let leaf = observation.components.last().ok_or("missing leaf")?;
        assert_eq!(leaf.path, fixture.executable);
        assert_eq!(leaf.kind, MacOsPathComponentKindV1::ExecutableFile);
        assert_eq!(leaf.owner_uid, observation.effective_uid);
        assert!(!leaf.user_immutable);
        assert!(!leaf.system_immutable);
        assert!(matches!(
            leaf.acl_decision,
            MacOsComponentAclDecisionV1::NoMutationAllowEntry
                | MacOsComponentAclDecisionV1::Unsupported
                | MacOsComponentAclDecisionV1::Unverified
        ));
        assert!(leaf.native_mount_local);
        Ok(())
    }

    #[test]
    fn symlink_component_and_non_executable_leaf_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let link = fixture.root.join("linked-toolchain");
        symlink(fixture.root.join("toolchain"), &link)?;
        let linked_lake = link.join("bin/lake");
        let symlink_error = observe_macos_path_provenance_v1(&linked_lake)
            .err()
            .ok_or("symlink path unexpectedly accepted")?;
        assert_eq!(
            symlink_error.rejection,
            MacOsPathProvenanceRejectionV1::OpenFailed
        );

        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o644))?;
        let mode_error = observe_macos_path_provenance_v1(&fixture.executable)
            .err()
            .ok_or("non-executable leaf unexpectedly accepted")?;
        assert_eq!(
            mode_error.rejection,
            MacOsPathProvenanceRejectionV1::ExecutableModeMissing
        );
        Ok(())
    }

    #[test]
    fn mutation_acl_has_a_dedicated_denial_after_stronger_path_checks()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let observation = observe_macos_path_provenance_v1(&fixture.executable)?;
        let mut components = observation.components;
        for component in &mut components {
            component.owner_uid = 0;
            component.unix_mode &= !0o022;
            component.effective_uid_write_access = MacOsEffectiveWriteAccessV1::Denied;
            component.acl_decision = MacOsComponentAclDecisionV1::NoMutationAllowEntry;
        }
        let leaf = components.last_mut().ok_or("missing leaf")?;
        leaf.acl_decision = MacOsComponentAclDecisionV1::DeniedMutationAllowEntry;

        assert_eq!(
            classify_components(observation.effective_uid, &components),
            MacOsPathProvenanceDecisionV1::DeniedAclMutationAllowEntry
        );
        Ok(())
    }
}

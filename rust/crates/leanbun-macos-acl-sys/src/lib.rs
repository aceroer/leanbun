#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "macos"))]
compile_error!("leanbun-macos-acl-sys requires macOS ACL semantics");

use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;

const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
const ACL_EXTENDED_ALLOW: c_int = 1;
const ACL_EXTENDED_DENY: c_int = 2;
const ACL_MAX_ENTRIES: u16 = 128;

const ACL_READ_DATA: u64 = 1 << 1;
const ACL_WRITE_DATA: u64 = 1 << 2;
const ACL_EXECUTE: u64 = 1 << 3;
const ACL_DELETE: u64 = 1 << 4;
const ACL_APPEND_DATA: u64 = 1 << 5;
const ACL_DELETE_CHILD: u64 = 1 << 6;
const ACL_READ_ATTRIBUTES: u64 = 1 << 7;
const ACL_WRITE_ATTRIBUTES: u64 = 1 << 8;
const ACL_READ_EXTATTRIBUTES: u64 = 1 << 9;
const ACL_WRITE_EXTATTRIBUTES: u64 = 1 << 10;
const ACL_READ_SECURITY: u64 = 1 << 11;
const ACL_WRITE_SECURITY: u64 = 1 << 12;
const ACL_CHANGE_OWNER: u64 = 1 << 13;
const ACL_SYNCHRONIZE: u64 = 1 << 20;

const MUTATION_MASK: u64 = ACL_WRITE_DATA
    | ACL_DELETE
    | ACL_APPEND_DATA
    | ACL_DELETE_CHILD
    | ACL_WRITE_ATTRIBUTES
    | ACL_WRITE_EXTATTRIBUTES
    | ACL_WRITE_SECURITY
    | ACL_CHANGE_OWNER;
const KNOWN_NON_MUTATING_MASK: u64 = ACL_READ_DATA
    | ACL_EXECUTE
    | ACL_READ_ATTRIBUTES
    | ACL_READ_EXTATTRIBUTES
    | ACL_READ_SECURITY
    | ACL_SYNCHRONIZE;
const KNOWN_PERMISSION_MASK: u64 = MUTATION_MASK | KNOWN_NON_MUTATING_MASK;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag_type: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
    fn acl_free(object: *mut c_void) -> c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclPresenceV1 {
    Absent,
    Extended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclMutationDecisionV1 {
    NoMutationAllowEntry,
    DeniedMutationAllowEntry,
    DeniedUnknownAllowPermission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsAclSummaryV1 {
    pub schema_version: u8,
    pub presence: MacOsAclPresenceV1,
    pub entry_count: u16,
    pub allow_entry_count: u16,
    pub deny_entry_count: u16,
    pub mutation_allow_mask: u64,
    pub unknown_allow_mask: u64,
    pub decision: MacOsAclMutationDecisionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclReadErrorKindV1 {
    Unsupported,
    NativeCallFailed,
    InvalidEntryTag,
    TooManyEntries,
    FreeFailed,
}

#[derive(Debug)]
pub struct MacOsAclReadError {
    pub kind: MacOsAclReadErrorKindV1,
    pub operation: &'static str,
    pub source: Option<io::Error>,
}

impl std::fmt::Display for MacOsAclReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(source) => write!(formatter, "{} failed: {source}", self.operation),
            None => write!(formatter, "{} failed", self.operation),
        }
    }
}

impl std::error::Error for MacOsAclReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

struct AclHandle {
    pointer: Option<NonNull<c_void>>,
}

impl AclHandle {
    fn new(pointer: NonNull<c_void>) -> Self {
        Self {
            pointer: Some(pointer),
        }
    }

    fn pointer(&self) -> Result<*mut c_void, MacOsAclReadError> {
        self.pointer.map(NonNull::as_ptr).ok_or(MacOsAclReadError {
            kind: MacOsAclReadErrorKindV1::NativeCallFailed,
            operation: "access released ACL storage",
            source: None,
        })
    }

    fn release(mut self) -> Result<(), MacOsAclReadError> {
        let pointer = self.pointer.take().ok_or(MacOsAclReadError {
            kind: MacOsAclReadErrorKindV1::FreeFailed,
            operation: "release ACL storage twice",
            source: None,
        })?;
        // SAFETY: `pointer` came from `acl_get_fd_np`, remains uniquely owned
        // by this handle, and is removed before the native release call.
        let result = unsafe { acl_free(pointer.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(native_error(
                MacOsAclReadErrorKindV1::FreeFailed,
                "acl_free",
            ))
        }
    }
}

impl Drop for AclHandle {
    fn drop(&mut self) {
        if let Some(pointer) = self.pointer.take() {
            // SAFETY: this is the unique fallback owner and the pointer came
            // from `acl_get_fd_np`. Return status cannot escape `Drop`.
            let _ = unsafe { acl_free(pointer.as_ptr()) };
        }
    }
}

/// Conservatively enumerates the macOS extended ACL attached to an open FD.
///
/// The function never modifies ACL state, never performs path lookup, and
/// never exposes native pointers. Any mutation-capable or unknown ALLOW mask
/// yields a denied value result.
pub fn observe_fd_acl_v1(fd: BorrowedFd<'_>) -> Result<MacOsAclSummaryV1, MacOsAclReadError> {
    // SAFETY: the borrowed descriptor is valid for the duration of this call;
    // the returned allocation is immediately placed under `AclHandle`.
    let pointer = unsafe { acl_get_fd_np(fd.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(pointer) = NonNull::new(pointer) else {
        let source = io::Error::last_os_error();
        return match source.raw_os_error() {
            Some(2) => Ok(absent_summary()),
            Some(45 | 102) => Err(MacOsAclReadError {
                kind: MacOsAclReadErrorKindV1::Unsupported,
                operation: "acl_get_fd_np",
                source: Some(source),
            }),
            _ => Err(MacOsAclReadError {
                kind: MacOsAclReadErrorKindV1::NativeCallFailed,
                operation: "acl_get_fd_np",
                source: Some(source),
            }),
        };
    };
    let handle = AclHandle::new(pointer);
    let enumeration = enumerate_acl(&handle);
    let release = handle.release();
    match (enumeration, release) {
        (Ok(summary), Ok(())) => Ok(summary),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn enumerate_acl(handle: &AclHandle) -> Result<MacOsAclSummaryV1, MacOsAclReadError> {
    let acl = handle.pointer()?;
    let mut entry_id = ACL_FIRST_ENTRY;
    let mut entry_count = 0_u16;
    let mut allow_entry_count = 0_u16;
    let mut deny_entry_count = 0_u16;
    let mut mutation_allow_mask = 0_u64;
    let mut unknown_allow_mask = 0_u64;

    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl` is a live working copy, `entry` points to writable
        // storage, and no native pointer is retained after this iteration.
        let result = unsafe { acl_get_entry(acl, entry_id, &mut entry) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(22) {
                break;
            }
            return Err(MacOsAclReadError {
                kind: MacOsAclReadErrorKindV1::NativeCallFailed,
                operation: "acl_get_entry",
                source: Some(error),
            });
        }
        if entry_count == ACL_MAX_ENTRIES {
            return Err(MacOsAclReadError {
                kind: MacOsAclReadErrorKindV1::TooManyEntries,
                operation: "acl_get_entry exceeded ACL_MAX_ENTRIES",
                source: None,
            });
        }
        let Some(entry) = NonNull::new(entry) else {
            return Err(MacOsAclReadError {
                kind: MacOsAclReadErrorKindV1::NativeCallFailed,
                operation: "acl_get_entry returned null entry",
                source: None,
            });
        };
        entry_count += 1;

        let mut tag: c_int = 0;
        // SAFETY: `entry` belongs to the live ACL working copy and `tag`
        // points to initialized writable storage.
        if unsafe { acl_get_tag_type(entry.as_ptr(), &mut tag) } != 0 {
            return Err(native_error(
                MacOsAclReadErrorKindV1::NativeCallFailed,
                "acl_get_tag_type",
            ));
        }
        let mut mask = 0_u64;
        // SAFETY: `entry` belongs to the live ACL working copy and `mask`
        // points to initialized writable storage.
        if unsafe { acl_get_permset_mask_np(entry.as_ptr(), &mut mask) } != 0 {
            return Err(native_error(
                MacOsAclReadErrorKindV1::NativeCallFailed,
                "acl_get_permset_mask_np",
            ));
        }
        match tag {
            ACL_EXTENDED_ALLOW => {
                allow_entry_count += 1;
                mutation_allow_mask |= mask & MUTATION_MASK;
                unknown_allow_mask |= mask & !KNOWN_PERMISSION_MASK;
            }
            ACL_EXTENDED_DENY => deny_entry_count += 1,
            _ => {
                return Err(MacOsAclReadError {
                    kind: MacOsAclReadErrorKindV1::InvalidEntryTag,
                    operation: "acl_get_tag_type returned unknown tag",
                    source: None,
                });
            }
        }
        entry_id = ACL_NEXT_ENTRY;
    }

    let decision = classify_allow_masks(mutation_allow_mask, unknown_allow_mask);
    Ok(MacOsAclSummaryV1 {
        schema_version: 1,
        presence: MacOsAclPresenceV1::Extended,
        entry_count,
        allow_entry_count,
        deny_entry_count,
        mutation_allow_mask,
        unknown_allow_mask,
        decision,
    })
}

fn classify_allow_masks(
    mutation_allow_mask: u64,
    unknown_allow_mask: u64,
) -> MacOsAclMutationDecisionV1 {
    if unknown_allow_mask != 0 {
        MacOsAclMutationDecisionV1::DeniedUnknownAllowPermission
    } else if mutation_allow_mask != 0 {
        MacOsAclMutationDecisionV1::DeniedMutationAllowEntry
    } else {
        MacOsAclMutationDecisionV1::NoMutationAllowEntry
    }
}

const fn absent_summary() -> MacOsAclSummaryV1 {
    MacOsAclSummaryV1 {
        schema_version: 1,
        presence: MacOsAclPresenceV1::Absent,
        entry_count: 0,
        allow_entry_count: 0,
        deny_entry_count: 0,
        mutation_allow_mask: 0,
        unknown_allow_mask: 0,
        decision: MacOsAclMutationDecisionV1::NoMutationAllowEntry,
    }
}

fn native_error(kind: MacOsAclReadErrorKindV1, operation: &'static str) -> MacOsAclReadError {
    MacOsAclReadError {
        kind,
        operation,
        source: Some(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::AsFd;

    #[test]
    fn conservative_mask_classifier_denies_mutation_and_unknown_bits() {
        assert_eq!(
            classify_allow_masks(ACL_WRITE_DATA | ACL_DELETE_CHILD, 0),
            MacOsAclMutationDecisionV1::DeniedMutationAllowEntry
        );
        assert_eq!(
            classify_allow_masks(0, 1_u64 << 63),
            MacOsAclMutationDecisionV1::DeniedUnknownAllowPermission
        );
        assert_eq!(
            classify_allow_masks(0, 0),
            MacOsAclMutationDecisionV1::NoMutationAllowEntry
        );
    }

    #[test]
    fn ordinary_open_file_produces_value_only_acl_summary() -> Result<(), Box<dyn std::error::Error>>
    {
        let file = File::open("/dev/null")?;
        match observe_fd_acl_v1(file.as_fd()) {
            Ok(summary) => {
                assert_eq!(summary.schema_version, 1);
                assert!(summary.entry_count <= ACL_MAX_ENTRIES);
            }
            Err(error) => assert_eq!(error.kind, MacOsAclReadErrorKindV1::Unsupported),
        }
        Ok(())
    }
}

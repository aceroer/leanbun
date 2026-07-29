use leanbun_plan::PlanExecutionAuthorityV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclNativeApiV1 {
    AclGetFdNp,
    AclGetEntry,
    AclGetTagType,
    AclGetPermsetMaskNp,
    AclFree,
    AclGetQualifierAndMembership,
    AclMutationFunctions,
    RustixFstatfs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclNativeApiDispositionV1 {
    RequiredInSeparateAuditedFfiCrate,
    AvailableThroughSafeRustix,
    NotRequiredByConservativePolicy,
    ForbiddenReadOnlyBoundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsAclNativeApiAssessmentV1 {
    pub api: MacOsAclNativeApiV1,
    pub disposition: MacOsAclNativeApiDispositionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclMutationPermissionV1 {
    WriteDataOrAddFile,
    AppendDataOrAddSubdirectory,
    Delete,
    DeleteChild,
    WriteAttributes,
    WriteExtendedAttributes,
    WriteSecurity,
    ChangeOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclFfiRequirementV1 {
    OpaquePointersNeverEscape,
    NullAndErrnoChecked,
    MaximumEntriesBounded,
    AclStorageFreedExactlyOnce,
    NoTextAclParsing,
    AnyMutationAllowEntryDenies,
    DescriptorIdentityReverified,
    NativeMountFlagsReverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsAclBoundaryDecisionV1 {
    RequiresSeparateAuditedFfiCrate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsAclNativeBoundaryV1 {
    pub schema_version: u8,
    pub sdk_version: &'static str,
    pub rustix_version: &'static str,
    pub libc_version: &'static str,
    pub maximum_acl_entries: u16,
    pub api_assessments: [MacOsAclNativeApiAssessmentV1; 8],
    pub mutation_permissions: [MacOsAclMutationPermissionV1; 8],
    pub ffi_requirements: [MacOsAclFfiRequirementV1; 8],
    pub decision: MacOsAclBoundaryDecisionV1,
    pub execution_authority: PlanExecutionAuthorityV1,
}

/// Returns the M23 exact native-API audit contract.
///
/// It contains no native declarations or calls. The approval adapter remains
/// entirely safe Rust and does not enumerate, modify, or serialize ACLs.
#[must_use]
pub const fn macos_acl_native_boundary_v1() -> MacOsAclNativeBoundaryV1 {
    use MacOsAclNativeApiDispositionV1 as Disposition;
    use MacOsAclNativeApiV1 as Api;

    MacOsAclNativeBoundaryV1 {
        schema_version: 1,
        sdk_version: "26.5",
        rustix_version: "1.1.4",
        libc_version: "0.2.189",
        maximum_acl_entries: 128,
        api_assessments: [
            MacOsAclNativeApiAssessmentV1 {
                api: Api::AclGetFdNp,
                disposition: Disposition::RequiredInSeparateAuditedFfiCrate,
            },
            MacOsAclNativeApiAssessmentV1 {
                api: Api::AclGetEntry,
                disposition: Disposition::RequiredInSeparateAuditedFfiCrate,
            },
            MacOsAclNativeApiAssessmentV1 {
                api: Api::AclGetTagType,
                disposition: Disposition::RequiredInSeparateAuditedFfiCrate,
            },
            MacOsAclNativeApiAssessmentV1 {
                api: Api::AclGetPermsetMaskNp,
                disposition: Disposition::RequiredInSeparateAuditedFfiCrate,
            },
            MacOsAclNativeApiAssessmentV1 {
                api: Api::AclFree,
                disposition: Disposition::RequiredInSeparateAuditedFfiCrate,
            },
            MacOsAclNativeApiAssessmentV1 {
                api: Api::AclGetQualifierAndMembership,
                disposition: Disposition::NotRequiredByConservativePolicy,
            },
            MacOsAclNativeApiAssessmentV1 {
                api: Api::AclMutationFunctions,
                disposition: Disposition::ForbiddenReadOnlyBoundary,
            },
            MacOsAclNativeApiAssessmentV1 {
                api: Api::RustixFstatfs,
                disposition: Disposition::AvailableThroughSafeRustix,
            },
        ],
        mutation_permissions: [
            MacOsAclMutationPermissionV1::WriteDataOrAddFile,
            MacOsAclMutationPermissionV1::AppendDataOrAddSubdirectory,
            MacOsAclMutationPermissionV1::Delete,
            MacOsAclMutationPermissionV1::DeleteChild,
            MacOsAclMutationPermissionV1::WriteAttributes,
            MacOsAclMutationPermissionV1::WriteExtendedAttributes,
            MacOsAclMutationPermissionV1::WriteSecurity,
            MacOsAclMutationPermissionV1::ChangeOwner,
        ],
        ffi_requirements: [
            MacOsAclFfiRequirementV1::OpaquePointersNeverEscape,
            MacOsAclFfiRequirementV1::NullAndErrnoChecked,
            MacOsAclFfiRequirementV1::MaximumEntriesBounded,
            MacOsAclFfiRequirementV1::AclStorageFreedExactlyOnce,
            MacOsAclFfiRequirementV1::NoTextAclParsing,
            MacOsAclFfiRequirementV1::AnyMutationAllowEntryDenies,
            MacOsAclFfiRequirementV1::DescriptorIdentityReverified,
            MacOsAclFfiRequirementV1::NativeMountFlagsReverified,
        ],
        decision: MacOsAclBoundaryDecisionV1::RequiresSeparateAuditedFfiCrate,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_acl_calls_are_confined_to_a_future_audited_crate() {
        let boundary = macos_acl_native_boundary_v1();

        assert_eq!(boundary.maximum_acl_entries, 128);
        assert_eq!(boundary.mutation_permissions.len(), 8);
        assert_eq!(
            boundary.decision,
            MacOsAclBoundaryDecisionV1::RequiresSeparateAuditedFfiCrate
        );
        assert_eq!(
            boundary.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        assert!(boundary.api_assessments[..5].iter().all(|assessment| {
            assessment.disposition
                == MacOsAclNativeApiDispositionV1::RequiredInSeparateAuditedFfiCrate
        }));
    }

    #[test]
    fn conservative_policy_avoids_membership_and_forbids_acl_mutation() {
        let boundary = macos_acl_native_boundary_v1();

        assert_eq!(
            boundary.api_assessments[5].disposition,
            MacOsAclNativeApiDispositionV1::NotRequiredByConservativePolicy
        );
        assert_eq!(
            boundary.api_assessments[6].disposition,
            MacOsAclNativeApiDispositionV1::ForbiddenReadOnlyBoundary
        );
        assert_eq!(
            boundary.api_assessments[7].disposition,
            MacOsAclNativeApiDispositionV1::AvailableThroughSafeRustix
        );
    }
}

use leanbun_plan::PlanExecutionAuthorityV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsStableDeploymentEvidenceV1 {
    SdkMountReadOnlyDeniesEvenSuperUserWrites,
    SdkMountUpdateCanChangeFlags,
    SdkUnmountCanReplaceTopology,
    HdiutilReadOnlyIsAnAttachOption,
    RustixMountModuleIsLinuxOnly,
    RustixFileLocksAreAdvisory,
    SealedSystemVolumeObservedReadOnly,
    ProductionExternalVolumeObservedReadWriteNoOwners,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsStableDeploymentRequirementV1 {
    AbsoluteDirectSymlinkFreePath,
    EveryComponentOwnedByTrustedPrincipal,
    EffectiveUidMutationDeniedForEveryComponent,
    GroupAndWorldMutationDeniedForEveryComponent,
    AclAndDarwinFlagsVerifiedForEveryComponent,
    MountIsExecutableAndDoesNotIgnoreOwnership,
    MountIdentityAndReadOnlyStateStable,
    LeafMatchesSealedReservation,
    UpdaterExcludedThroughChildCreation,
    MountLifecycleExcludedThroughChildCreation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsStableDeploymentClassV1 {
    ExistingSealedSystemVolumeBinary,
    PrivilegedRootOwnedDataVolumeInstall,
    UserMountedReadOnlyDiskImage,
    PrivilegedManagedReadOnlyDiskImage,
    UserOwnedBundleOrToolchain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsStableDeploymentAcquisitionV1 {
    NotAvailableForCustomLeanLake,
    RequiresPrivilegedInstaller,
    UserControlledHdiutilAttach,
    RequiresPrivilegedMountCoordinator,
    UnprivilegedCopy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsStableDeploymentWriterContinuityV1 {
    ExistingOperatingSystemSealOnly,
    RequiresPrivilegedUpdaterLease,
    DeniedUserCanReplaceMountTopology,
    RequiresPrivilegedMountLifecycleLease,
    DeniedSameUidMutation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsStableDeploymentDispositionV1 {
    ExistingPlatformBinaryOnly,
    CandidateRequiresExternalCoordinator,
    DeniedMutableByInScopeActor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsStableDeploymentAssessmentV1 {
    pub class: MacOsStableDeploymentClassV1,
    pub acquisition: MacOsStableDeploymentAcquisitionV1,
    pub writer_continuity: MacOsStableDeploymentWriterContinuityV1,
    pub disposition: MacOsStableDeploymentDispositionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsStableExecutableDeploymentContractV1 {
    pub schema_version: u8,
    pub evidence: [MacOsStableDeploymentEvidenceV1; 8],
    pub requirements: [MacOsStableDeploymentRequirementV1; 10],
    pub assessments: [MacOsStableDeploymentAssessmentV1; 5],
    pub execution_authority: PlanExecutionAuthorityV1,
}

/// Returns the M26 acquisition and verification audit as a pure contract.
///
/// No assessment admits a custom executable to a process adapter. Candidate
/// classes still require an external privileged coordinator whose updater or
/// mount lease remains held through child creation.
#[must_use]
pub const fn macos_stable_executable_deployment_contract_v1()
-> MacOsStableExecutableDeploymentContractV1 {
    use MacOsStableDeploymentAcquisitionV1 as Acquisition;
    use MacOsStableDeploymentClassV1 as Class;
    use MacOsStableDeploymentDispositionV1 as Disposition;
    use MacOsStableDeploymentWriterContinuityV1 as Continuity;

    MacOsStableExecutableDeploymentContractV1 {
        schema_version: 1,
        evidence: [
            MacOsStableDeploymentEvidenceV1::SdkMountReadOnlyDeniesEvenSuperUserWrites,
            MacOsStableDeploymentEvidenceV1::SdkMountUpdateCanChangeFlags,
            MacOsStableDeploymentEvidenceV1::SdkUnmountCanReplaceTopology,
            MacOsStableDeploymentEvidenceV1::HdiutilReadOnlyIsAnAttachOption,
            MacOsStableDeploymentEvidenceV1::RustixMountModuleIsLinuxOnly,
            MacOsStableDeploymentEvidenceV1::RustixFileLocksAreAdvisory,
            MacOsStableDeploymentEvidenceV1::SealedSystemVolumeObservedReadOnly,
            MacOsStableDeploymentEvidenceV1::ProductionExternalVolumeObservedReadWriteNoOwners,
        ],
        requirements: [
            MacOsStableDeploymentRequirementV1::AbsoluteDirectSymlinkFreePath,
            MacOsStableDeploymentRequirementV1::EveryComponentOwnedByTrustedPrincipal,
            MacOsStableDeploymentRequirementV1::EffectiveUidMutationDeniedForEveryComponent,
            MacOsStableDeploymentRequirementV1::GroupAndWorldMutationDeniedForEveryComponent,
            MacOsStableDeploymentRequirementV1::AclAndDarwinFlagsVerifiedForEveryComponent,
            MacOsStableDeploymentRequirementV1::MountIsExecutableAndDoesNotIgnoreOwnership,
            MacOsStableDeploymentRequirementV1::MountIdentityAndReadOnlyStateStable,
            MacOsStableDeploymentRequirementV1::LeafMatchesSealedReservation,
            MacOsStableDeploymentRequirementV1::UpdaterExcludedThroughChildCreation,
            MacOsStableDeploymentRequirementV1::MountLifecycleExcludedThroughChildCreation,
        ],
        assessments: [
            MacOsStableDeploymentAssessmentV1 {
                class: Class::ExistingSealedSystemVolumeBinary,
                acquisition: Acquisition::NotAvailableForCustomLeanLake,
                writer_continuity: Continuity::ExistingOperatingSystemSealOnly,
                disposition: Disposition::ExistingPlatformBinaryOnly,
            },
            MacOsStableDeploymentAssessmentV1 {
                class: Class::PrivilegedRootOwnedDataVolumeInstall,
                acquisition: Acquisition::RequiresPrivilegedInstaller,
                writer_continuity: Continuity::RequiresPrivilegedUpdaterLease,
                disposition: Disposition::CandidateRequiresExternalCoordinator,
            },
            MacOsStableDeploymentAssessmentV1 {
                class: Class::UserMountedReadOnlyDiskImage,
                acquisition: Acquisition::UserControlledHdiutilAttach,
                writer_continuity: Continuity::DeniedUserCanReplaceMountTopology,
                disposition: Disposition::DeniedMutableByInScopeActor,
            },
            MacOsStableDeploymentAssessmentV1 {
                class: Class::PrivilegedManagedReadOnlyDiskImage,
                acquisition: Acquisition::RequiresPrivilegedMountCoordinator,
                writer_continuity: Continuity::RequiresPrivilegedMountLifecycleLease,
                disposition: Disposition::CandidateRequiresExternalCoordinator,
            },
            MacOsStableDeploymentAssessmentV1 {
                class: Class::UserOwnedBundleOrToolchain,
                acquisition: Acquisition::UnprivilegedCopy,
                writer_continuity: Continuity::DeniedSameUidMutation,
                disposition: Disposition::DeniedMutableByInScopeActor,
            },
        ],
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_deployment_has_no_admitted_class() {
        let contract = macos_stable_executable_deployment_contract_v1();

        assert_eq!(contract.schema_version, 1);
        assert_eq!(contract.requirements.len(), 10);
        assert!(contract.assessments.iter().all(|assessment| {
            assessment.disposition != MacOsStableDeploymentDispositionV1::ExistingPlatformBinaryOnly
                || assessment.class
                    == MacOsStableDeploymentClassV1::ExistingSealedSystemVolumeBinary
        }));
        assert_eq!(
            contract.assessments[0].acquisition,
            MacOsStableDeploymentAcquisitionV1::NotAvailableForCustomLeanLake
        );
        assert_eq!(
            contract.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
    }

    #[test]
    fn read_only_state_does_not_substitute_for_mount_lifecycle_exclusion() {
        let contract = macos_stable_executable_deployment_contract_v1();

        assert_eq!(
            contract.assessments[2],
            MacOsStableDeploymentAssessmentV1 {
                class: MacOsStableDeploymentClassV1::UserMountedReadOnlyDiskImage,
                acquisition: MacOsStableDeploymentAcquisitionV1::UserControlledHdiutilAttach,
                writer_continuity:
                    MacOsStableDeploymentWriterContinuityV1::DeniedUserCanReplaceMountTopology,
                disposition: MacOsStableDeploymentDispositionV1::DeniedMutableByInScopeActor,
            }
        );
        assert_eq!(
            contract.assessments[3].writer_continuity,
            MacOsStableDeploymentWriterContinuityV1::RequiresPrivilegedMountLifecycleLease
        );
    }

    #[test]
    fn advisory_lock_is_not_claimed_as_os_enforced_writer_exclusion() {
        let contract = macos_stable_executable_deployment_contract_v1();

        assert!(
            contract
                .evidence
                .contains(&MacOsStableDeploymentEvidenceV1::RustixFileLocksAreAdvisory)
        );
        assert!(contract.assessments.iter().all(|assessment| {
            assessment.writer_continuity
                != MacOsStableDeploymentWriterContinuityV1::ExistingOperatingSystemSealOnly
                || assessment.class
                    == MacOsStableDeploymentClassV1::ExistingSealedSystemVolumeBinary
        }));
    }
}

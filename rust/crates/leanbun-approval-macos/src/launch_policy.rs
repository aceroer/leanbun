use leanbun_plan::PlanExecutionAuthorityV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPathLaunchThreatV1 {
    SameEffectiveUidConcurrentMutation,
    GroupOrWorldWritableMutation,
    AuthorizedUpdaterOverlap,
    MountTopologyReplacement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPathLaunchExcludedThreatV1 {
    PrivilegedRootOrKernelCompromise,
    PhysicalHardwareCompromise,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPathLaunchRequirementV1 {
    AbsoluteCanonicalDirectPath,
    NoSymlinkInAnyComponent,
    StableMountIdentity,
    EveryComponentMutationDeniedToEffectiveUid,
    EveryComponentMutationDeniedToGroupAndWorld,
    AccessControlListsAndFileFlagsVerified,
    LeafIdentityMatchesSealedReservation,
    UpdateWriterExcludedUntilChildCreation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPathLaunchProvenanceClassV1 {
    SystemOwnedProtectedPath,
    ReadOnlyFileSystemPath,
    UserOwnedManagedToolchain,
    UserImmutableFlagOnly,
    IsolatedTestFixture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPathLaunchAdmissibilityV1 {
    EligibleForFutureProductionAdapter,
    DeniedMutableByInScopeActor,
    IsolatedFixtureOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsPathLaunchAssessmentV1 {
    pub provenance: MacOsPathLaunchProvenanceClassV1,
    pub admissibility: MacOsPathLaunchAdmissibilityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsPathLaunchPolicyV1 {
    pub schema_version: u8,
    pub in_scope_threats: [MacOsPathLaunchThreatV1; 4],
    pub excluded_threats: [MacOsPathLaunchExcludedThreatV1; 2],
    pub production_requirements: [MacOsPathLaunchRequirementV1; 8],
    pub assessments: [MacOsPathLaunchAssessmentV1; 5],
    pub execution_authority: PlanExecutionAuthorityV1,
}

/// Returns the M21 path-based launch policy without observing or launching.
///
/// `EligibleForFutureProductionAdapter` is only a policy classification. It
/// does not attest that a concrete path meets every requirement and never
/// grants execution authority.
#[must_use]
pub const fn macos_path_launch_policy_v1() -> MacOsPathLaunchPolicyV1 {
    use MacOsPathLaunchAdmissibilityV1 as Admissibility;
    use MacOsPathLaunchProvenanceClassV1 as Provenance;

    MacOsPathLaunchPolicyV1 {
        schema_version: 1,
        in_scope_threats: [
            MacOsPathLaunchThreatV1::SameEffectiveUidConcurrentMutation,
            MacOsPathLaunchThreatV1::GroupOrWorldWritableMutation,
            MacOsPathLaunchThreatV1::AuthorizedUpdaterOverlap,
            MacOsPathLaunchThreatV1::MountTopologyReplacement,
        ],
        excluded_threats: [
            MacOsPathLaunchExcludedThreatV1::PrivilegedRootOrKernelCompromise,
            MacOsPathLaunchExcludedThreatV1::PhysicalHardwareCompromise,
        ],
        production_requirements: [
            MacOsPathLaunchRequirementV1::AbsoluteCanonicalDirectPath,
            MacOsPathLaunchRequirementV1::NoSymlinkInAnyComponent,
            MacOsPathLaunchRequirementV1::StableMountIdentity,
            MacOsPathLaunchRequirementV1::EveryComponentMutationDeniedToEffectiveUid,
            MacOsPathLaunchRequirementV1::EveryComponentMutationDeniedToGroupAndWorld,
            MacOsPathLaunchRequirementV1::AccessControlListsAndFileFlagsVerified,
            MacOsPathLaunchRequirementV1::LeafIdentityMatchesSealedReservation,
            MacOsPathLaunchRequirementV1::UpdateWriterExcludedUntilChildCreation,
        ],
        assessments: [
            MacOsPathLaunchAssessmentV1 {
                provenance: Provenance::SystemOwnedProtectedPath,
                admissibility: Admissibility::EligibleForFutureProductionAdapter,
            },
            MacOsPathLaunchAssessmentV1 {
                provenance: Provenance::ReadOnlyFileSystemPath,
                admissibility: Admissibility::EligibleForFutureProductionAdapter,
            },
            MacOsPathLaunchAssessmentV1 {
                provenance: Provenance::UserOwnedManagedToolchain,
                admissibility: Admissibility::DeniedMutableByInScopeActor,
            },
            MacOsPathLaunchAssessmentV1 {
                provenance: Provenance::UserImmutableFlagOnly,
                admissibility: Admissibility::DeniedMutableByInScopeActor,
            },
            MacOsPathLaunchAssessmentV1 {
                provenance: Provenance::IsolatedTestFixture,
                admissibility: Admissibility::IsolatedFixtureOnly,
            },
        ],
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_uid_mutation_is_in_scope_and_user_owned_paths_are_denied() {
        let policy = macos_path_launch_policy_v1();

        assert!(
            policy
                .in_scope_threats
                .contains(&MacOsPathLaunchThreatV1::SameEffectiveUidConcurrentMutation)
        );
        assert_eq!(policy.production_requirements.len(), 8);
        assert_eq!(
            policy.assessments[2],
            MacOsPathLaunchAssessmentV1 {
                provenance: MacOsPathLaunchProvenanceClassV1::UserOwnedManagedToolchain,
                admissibility: MacOsPathLaunchAdmissibilityV1::DeniedMutableByInScopeActor,
            }
        );
        assert_eq!(
            policy.assessments[3],
            MacOsPathLaunchAssessmentV1 {
                provenance: MacOsPathLaunchProvenanceClassV1::UserImmutableFlagOnly,
                admissibility: MacOsPathLaunchAdmissibilityV1::DeniedMutableByInScopeActor,
            }
        );
        assert_eq!(
            policy.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
    }

    #[test]
    fn eligible_classes_and_test_fixture_still_do_not_grant_authority() {
        let policy = macos_path_launch_policy_v1();

        assert_eq!(
            policy.assessments[0].admissibility,
            MacOsPathLaunchAdmissibilityV1::EligibleForFutureProductionAdapter
        );
        assert_eq!(
            policy.assessments[1].admissibility,
            MacOsPathLaunchAdmissibilityV1::EligibleForFutureProductionAdapter
        );
        assert_eq!(
            policy.assessments[4].admissibility,
            MacOsPathLaunchAdmissibilityV1::IsolatedFixtureOnly
        );
        assert_eq!(
            policy.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
    }
}

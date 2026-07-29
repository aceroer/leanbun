use leanbun_plan::PlanExecutionAuthorityV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPrivilegedCoordinatorEvidenceV1 {
    SmAppServiceRequiresCodeSigning,
    LaunchDaemonRequiresNotarizationAndAdminApproval,
    SmJobBlessIsDeprecated,
    AuthorizationExecuteWithPrivilegesIsDeprecated,
    AuthorizationExternalFormIsForOnlineTransmission,
    XpcSupportsPrivilegedMachService,
    XpcSupportsPeerCodeSigningRequirement,
    LaunchdExecutesProgramByPath,
    ReservationCapabilityIsNotTransportSerializable,
    PathAssessmentUsesProcessEffectiveUid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPrivilegedCoordinatorMechanismV1 {
    SmAppServiceLaunchDaemon,
    SmJobBless,
    AuthorizationExecuteWithPrivileges,
    PrivilegedXpcMachService,
    PeerUidAndPidOnly,
    AuthorizationExternalFormAlone,
    CurrentM19M25DirectReuse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPrivilegedCoordinatorMechanismDispositionV1 {
    HostCandidate,
    TransportCandidate,
    DeniedDeprecated,
    DeniedInsufficientPeerIdentity,
    DeniedAuthorizationNotRequestBound,
    DeniedPrincipalAndCapabilityMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsPrivilegedCoordinatorMechanismAssessmentV1 {
    pub mechanism: MacOsPrivilegedCoordinatorMechanismV1,
    pub disposition: MacOsPrivilegedCoordinatorMechanismDispositionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPrivilegedCoordinatorRequirementV1 {
    SignedAndNotarizedLaunchDaemon,
    ExplicitAdminApproval,
    FixedPrivilegedMachService,
    PeerCodeSigningRequirementBeforeMessages,
    BoundedVersionedCanonicalRequest,
    ExactNamedAuthorizationRight,
    AuthorizationBoundToPeerRequestNonceAndDeadline,
    CoordinatorOwnedReplayAndReservationLedger,
    ExplicitUnprivilegedThreatPrincipal,
    CoordinatorOwnedToolchainAndUpdater,
    UpdaterAndMountLeaseBeforeFinalRevalidation,
    LeaseHeldThroughChildCreationAndTerminalRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPrivilegedCoordinatorDecisionV1 {
    DeniedCoordinatorProtocolNotEstablished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsPrivilegedCoordinatorContractV1 {
    pub schema_version: u8,
    pub evidence: [MacOsPrivilegedCoordinatorEvidenceV1; 10],
    pub mechanisms: [MacOsPrivilegedCoordinatorMechanismAssessmentV1; 7],
    pub requirements: [MacOsPrivilegedCoordinatorRequirementV1; 12],
    pub decision: MacOsPrivilegedCoordinatorDecisionV1,
    pub execution_authority: PlanExecutionAuthorityV1,
}

/// Returns the M27 privileged service, authorization, and IPC audit.
///
/// The contract identifies viable host and transport primitives, but denies a
/// coordinator until a principal-explicit request protocol and a
/// coordinator-owned replay/reservation ledger replace direct M19/M25 reuse.
#[must_use]
pub const fn macos_privileged_coordinator_contract_v1() -> MacOsPrivilegedCoordinatorContractV1 {
    use MacOsPrivilegedCoordinatorMechanismDispositionV1 as Disposition;
    use MacOsPrivilegedCoordinatorMechanismV1 as Mechanism;

    MacOsPrivilegedCoordinatorContractV1 {
        schema_version: 1,
        evidence: [
            MacOsPrivilegedCoordinatorEvidenceV1::SmAppServiceRequiresCodeSigning,
            MacOsPrivilegedCoordinatorEvidenceV1::LaunchDaemonRequiresNotarizationAndAdminApproval,
            MacOsPrivilegedCoordinatorEvidenceV1::SmJobBlessIsDeprecated,
            MacOsPrivilegedCoordinatorEvidenceV1::AuthorizationExecuteWithPrivilegesIsDeprecated,
            MacOsPrivilegedCoordinatorEvidenceV1::AuthorizationExternalFormIsForOnlineTransmission,
            MacOsPrivilegedCoordinatorEvidenceV1::XpcSupportsPrivilegedMachService,
            MacOsPrivilegedCoordinatorEvidenceV1::XpcSupportsPeerCodeSigningRequirement,
            MacOsPrivilegedCoordinatorEvidenceV1::LaunchdExecutesProgramByPath,
            MacOsPrivilegedCoordinatorEvidenceV1::ReservationCapabilityIsNotTransportSerializable,
            MacOsPrivilegedCoordinatorEvidenceV1::PathAssessmentUsesProcessEffectiveUid,
        ],
        mechanisms: [
            MacOsPrivilegedCoordinatorMechanismAssessmentV1 {
                mechanism: Mechanism::SmAppServiceLaunchDaemon,
                disposition: Disposition::HostCandidate,
            },
            MacOsPrivilegedCoordinatorMechanismAssessmentV1 {
                mechanism: Mechanism::SmJobBless,
                disposition: Disposition::DeniedDeprecated,
            },
            MacOsPrivilegedCoordinatorMechanismAssessmentV1 {
                mechanism: Mechanism::AuthorizationExecuteWithPrivileges,
                disposition: Disposition::DeniedDeprecated,
            },
            MacOsPrivilegedCoordinatorMechanismAssessmentV1 {
                mechanism: Mechanism::PrivilegedXpcMachService,
                disposition: Disposition::TransportCandidate,
            },
            MacOsPrivilegedCoordinatorMechanismAssessmentV1 {
                mechanism: Mechanism::PeerUidAndPidOnly,
                disposition: Disposition::DeniedInsufficientPeerIdentity,
            },
            MacOsPrivilegedCoordinatorMechanismAssessmentV1 {
                mechanism: Mechanism::AuthorizationExternalFormAlone,
                disposition: Disposition::DeniedAuthorizationNotRequestBound,
            },
            MacOsPrivilegedCoordinatorMechanismAssessmentV1 {
                mechanism: Mechanism::CurrentM19M25DirectReuse,
                disposition: Disposition::DeniedPrincipalAndCapabilityMismatch,
            },
        ],
        requirements: [
            MacOsPrivilegedCoordinatorRequirementV1::SignedAndNotarizedLaunchDaemon,
            MacOsPrivilegedCoordinatorRequirementV1::ExplicitAdminApproval,
            MacOsPrivilegedCoordinatorRequirementV1::FixedPrivilegedMachService,
            MacOsPrivilegedCoordinatorRequirementV1::PeerCodeSigningRequirementBeforeMessages,
            MacOsPrivilegedCoordinatorRequirementV1::BoundedVersionedCanonicalRequest,
            MacOsPrivilegedCoordinatorRequirementV1::ExactNamedAuthorizationRight,
            MacOsPrivilegedCoordinatorRequirementV1::AuthorizationBoundToPeerRequestNonceAndDeadline,
            MacOsPrivilegedCoordinatorRequirementV1::CoordinatorOwnedReplayAndReservationLedger,
            MacOsPrivilegedCoordinatorRequirementV1::ExplicitUnprivilegedThreatPrincipal,
            MacOsPrivilegedCoordinatorRequirementV1::CoordinatorOwnedToolchainAndUpdater,
            MacOsPrivilegedCoordinatorRequirementV1::UpdaterAndMountLeaseBeforeFinalRevalidation,
            MacOsPrivilegedCoordinatorRequirementV1::LeaseHeldThroughChildCreationAndTerminalRecord,
        ],
        decision: MacOsPrivilegedCoordinatorDecisionV1::DeniedCoordinatorProtocolNotEstablished,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_host_and_transport_primitives_do_not_grant_a_protocol() {
        let contract = macos_privileged_coordinator_contract_v1();

        assert_eq!(
            contract.mechanisms[0].disposition,
            MacOsPrivilegedCoordinatorMechanismDispositionV1::HostCandidate
        );
        assert_eq!(
            contract.mechanisms[3].disposition,
            MacOsPrivilegedCoordinatorMechanismDispositionV1::TransportCandidate
        );
        assert_eq!(
            contract.decision,
            MacOsPrivilegedCoordinatorDecisionV1::DeniedCoordinatorProtocolNotEstablished
        );
        assert_eq!(
            contract.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
    }

    #[test]
    fn deprecated_privilege_escalation_paths_are_denied() {
        let contract = macos_privileged_coordinator_contract_v1();

        for assessment in &contract.mechanisms[1..=2] {
            assert_eq!(
                assessment.disposition,
                MacOsPrivilegedCoordinatorMechanismDispositionV1::DeniedDeprecated
            );
        }
    }

    #[test]
    fn peer_identity_authorization_and_principal_are_distinct_requirements() {
        let contract = macos_privileged_coordinator_contract_v1();

        assert_eq!(
            contract.mechanisms[4].disposition,
            MacOsPrivilegedCoordinatorMechanismDispositionV1::DeniedInsufficientPeerIdentity
        );
        assert_eq!(
            contract.mechanisms[5].disposition,
            MacOsPrivilegedCoordinatorMechanismDispositionV1::DeniedAuthorizationNotRequestBound
        );
        assert_eq!(
            contract.mechanisms[6].disposition,
            MacOsPrivilegedCoordinatorMechanismDispositionV1::DeniedPrincipalAndCapabilityMismatch
        );
        assert!(contract.requirements.contains(
            &MacOsPrivilegedCoordinatorRequirementV1::ExplicitUnprivilegedThreatPrincipal
        ));
        assert!(contract.requirements.contains(
            &MacOsPrivilegedCoordinatorRequirementV1::CoordinatorOwnedReplayAndReservationLedger
        ));
    }
}

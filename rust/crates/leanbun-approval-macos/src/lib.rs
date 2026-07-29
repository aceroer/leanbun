#![forbid(unsafe_code)]

#[cfg(not(target_os = "macos"))]
compile_error!("leanbun-approval-macos requires macOS terminal semantics");

use leanbun_plan::PlanExecutionAuthorityV1;
use std::fs;
use std::io::{self, IsTerminal};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

mod acl_boundary;
mod candidate;
mod coordinator_contract;
mod coordinator_request;
mod coordinator_wire;
mod deployment_contract;
mod executable;
mod execution_grant;
mod fresh_plan;
mod launch_intent;
mod launch_policy;
mod launch_reservation;
mod path_eligibility;
mod path_provenance;
mod presentation;
mod proof;
mod replay;
mod spawn_boundary;

pub use acl_boundary::{
    MacOsAclBoundaryDecisionV1, MacOsAclFfiRequirementV1, MacOsAclMutationPermissionV1,
    MacOsAclNativeApiAssessmentV1, MacOsAclNativeApiDispositionV1, MacOsAclNativeApiV1,
    MacOsAclNativeBoundaryV1, macos_acl_native_boundary_v1,
};
pub use candidate::{
    TrustedLakeExecutionCandidateDecisionV1, TrustedLakeExecutionCandidateV1,
    seal_trusted_lake_execution_candidate_v1,
};
pub use coordinator_contract::{
    MacOsPrivilegedCoordinatorContractV1, MacOsPrivilegedCoordinatorDecisionV1,
    MacOsPrivilegedCoordinatorEvidenceV1, MacOsPrivilegedCoordinatorMechanismAssessmentV1,
    MacOsPrivilegedCoordinatorMechanismDispositionV1, MacOsPrivilegedCoordinatorMechanismV1,
    MacOsPrivilegedCoordinatorRequirementV1, macos_privileged_coordinator_contract_v1,
};
pub use coordinator_request::{
    MACOS_COORDINATOR_AUTHORIZATION_RIGHT_V1, MacOsCoordinatorLineageReferenceV1,
    MacOsCoordinatorOperationV1, MacOsCoordinatorPeerIdentityClaimV1,
    MacOsCoordinatorRequestDecisionV1, MacOsCoordinatorRequestError,
    MacOsCoordinatorRequestRejectionV1, MacOsCoordinatorRequestV1,
    MacOsCoordinatorThreatPrincipalV1, macos_coordinator_peer_identity_claim_v1,
    macos_coordinator_threat_principal_v1, prepare_macos_coordinator_request_v1,
};
pub use coordinator_wire::{
    MAX_MACOS_COORDINATOR_REQUEST_WIRE_BYTES_V1, MacOsCoordinatorWireError,
    MacOsCoordinatorWireRejectionV1, decode_macos_coordinator_request_wire_v1,
    encode_macos_coordinator_request_wire_v1,
};
pub use deployment_contract::{
    MacOsStableDeploymentAcquisitionV1, MacOsStableDeploymentAssessmentV1,
    MacOsStableDeploymentClassV1, MacOsStableDeploymentDispositionV1,
    MacOsStableDeploymentEvidenceV1, MacOsStableDeploymentRequirementV1,
    MacOsStableDeploymentWriterContinuityV1, MacOsStableExecutableDeploymentContractV1,
    macos_stable_executable_deployment_contract_v1,
};
pub use executable::{
    MacOsLakeExecutableObservationError, MacOsLakeExecutableObservationRejectionV1,
    TrustedLakeExecutableObservationV1, observe_reviewed_lake_executable_v1,
};
pub use execution_grant::{
    TrustedLakeExecutionAuthorityV1, TrustedLakeExecutionGrantDecisionV1,
    TrustedLakeExecutionGrantError, TrustedLakeExecutionGrantRejectionV1,
    TrustedLakeExecutionGrantV1, grant_trusted_lake_execution_once_v1,
};
pub use fresh_plan::{
    LakeProviderEvidenceLocationV1, MacOsFreshLakePlanError, MacOsFreshLakePlanRejectionV1,
    TrustedFreshLakeUpdatePlanV1, derive_trusted_fresh_lake_update_plan_v1,
};
pub use launch_intent::{
    LakeLaunchEnvironmentEntryV1, LakeLaunchEnvironmentLocationV1, TrustedLakeLaunchAuthorityV1,
    TrustedLakeLaunchIntentDecisionV1, TrustedLakeLaunchIntentError,
    TrustedLakeLaunchIntentRejectionV1, TrustedLakeLaunchIntentV1,
    prepare_trusted_lake_launch_intent_v1,
};
pub use launch_policy::{
    MacOsPathLaunchAdmissibilityV1, MacOsPathLaunchAssessmentV1, MacOsPathLaunchExcludedThreatV1,
    MacOsPathLaunchPolicyV1, MacOsPathLaunchProvenanceClassV1, MacOsPathLaunchRequirementV1,
    MacOsPathLaunchThreatV1, macos_path_launch_policy_v1,
};
pub use launch_reservation::{
    TrustedLakeLaunchReservationAuthorityV1, TrustedLakeLaunchReservationDecisionV1,
    TrustedLakeLaunchReservationError, TrustedLakeLaunchReservationRegistryV1,
    TrustedLakeLaunchReservationRejectionV1, TrustedLakeLaunchReservationV1,
    open_trusted_lake_launch_reservation_registry_v1,
};
pub use path_eligibility::{
    MacOsReservationBoundPathEligibilityDecisionV1, MacOsReservationBoundPathEligibilityError,
    MacOsReservationBoundPathEligibilityRejectionV1, MacOsReservationBoundPathEligibilityV1,
    assess_reservation_bound_path_eligibility_v1,
};
pub use path_provenance::{
    MacOsAclCoverageV1, MacOsComponentAclDecisionV1, MacOsEffectiveWriteAccessV1,
    MacOsPathComponentKindV1, MacOsPathComponentProvenanceV1, MacOsPathProvenanceDecisionV1,
    MacOsPathProvenanceError, MacOsPathProvenanceObservationV1, MacOsPathProvenanceRejectionV1,
    observe_macos_path_provenance_v1,
};
pub use presentation::{
    LakeCommandApprovalPresentationV1, LakeCommandApprovalResponseClaimV1,
    LakeCommandApprovalResponseDecisionV1, MacOsApprovalPresentationError,
    MacOsApprovalResponseError, MacOsApprovalResponseRejectionV1, TrustedTerminalBindingV1,
    prepare_lake_command_approval_presentation_v1,
    present_lake_command_approval_to_current_terminal_v1,
    read_bounded_exact_response_from_current_terminal_v1,
};
pub use proof::{
    LakeCommandTrustedApprovalProofDecisionV1, LakeCommandTrustedApprovalProofV1,
    MacOsApprovalProofError, MacOsApprovalProofRejectionV1,
    reverify_consumed_lake_command_approval_v1,
};
pub use replay::{
    LakeCommandApprovalConsumptionDecisionV1, LakeCommandApprovalConsumptionRecordV1,
    LakeCommandApprovalReplayRegistryV1, MacOsApprovalReplayError, MacOsApprovalReplayRejectionV1,
    open_lake_command_approval_replay_registry_v1,
};
pub use spawn_boundary::{
    MacOsExecutableHandoffAssessmentV1, MacOsExecutableHandoffContractV1,
    MacOsExecutableHandoffDecisionV1, MacOsExecutableHandoffMechanismV1,
    MacOsExecutableHandoffRejectionV1, macos_executable_handoff_contract_v1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalPresenceV1 {
    Terminal,
    NotTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalPairIdentityV1 {
    SameTerminal,
    DistinctTerminal,
    NotObserved,
    MetadataUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformProofV1 {
    Verified,
    Mismatch,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsTerminalIngressDecisionV1 {
    DeniedNonInteractive,
    DeniedUnverifiableTerminal,
    DeniedDistinctTerminal,
    DeniedTerminalOwnerMismatch,
    DeniedBackgroundProcessGroup,
    DeniedForeignTerminalSession,
    RequiresOwnershipAndForegroundProof,
    ReadyForChallengeResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalDeviceIdentityV1 {
    pub device: u64,
    pub inode: u64,
    pub raw_device: u64,
    pub owner_uid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentProcessTerminalObservationV1 {
    pub schema_version: u8,
    pub process_id: u32,
    pub stdin: TerminalPresenceV1,
    pub stderr: TerminalPresenceV1,
    pub pair_identity: TerminalPairIdentityV1,
    pub terminal_device: Option<TerminalDeviceIdentityV1>,
    pub effective_user_id: Option<u32>,
    pub process_group_id: Option<i32>,
    pub terminal_foreground_process_group_id: Option<i32>,
    pub process_session_id: Option<i32>,
    pub terminal_session_id: Option<i32>,
    pub effective_user_ownership: PlatformProofV1,
    pub foreground_process_group: PlatformProofV1,
    pub controlling_terminal_session: PlatformProofV1,
    pub decision: MacOsTerminalIngressDecisionV1,
    pub execution_authority: PlanExecutionAuthorityV1,
}

/// Observes the current process' streams, `/dev/fd` metadata, user, process
/// group, and controlling-terminal session through safe Rust/rustix APIs.
/// It never reads input, prompts, spawns a process, or grants execution authority.
#[must_use]
pub fn observe_current_process_terminal_v1() -> CurrentProcessTerminalObservationV1 {
    let stdin = presence(io::stdin().is_terminal());
    let stderr = presence(io::stderr().is_terminal());
    let pair = if stdin == TerminalPresenceV1::Terminal && stderr == TerminalPresenceV1::Terminal {
        terminal_pair_metadata()
    } else {
        None
    };
    let observation = classify_current_process_terminal_v1(stdin, stderr, pair);
    if observation.decision == MacOsTerminalIngressDecisionV1::RequiresOwnershipAndForegroundProof {
        observe_platform_proofs_v1(observation)
    } else {
        observation
    }
}

fn presence(value: bool) -> TerminalPresenceV1 {
    if value {
        TerminalPresenceV1::Terminal
    } else {
        TerminalPresenceV1::NotTerminal
    }
}

fn terminal_pair_metadata() -> Option<(TerminalDeviceIdentityV1, TerminalDeviceIdentityV1)> {
    Some((
        terminal_metadata("/dev/fd/0")?,
        terminal_metadata("/dev/fd/2")?,
    ))
}

fn terminal_metadata(path: &str) -> Option<TerminalDeviceIdentityV1> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.file_type().is_char_device() {
        return None;
    }
    Some(TerminalDeviceIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        raw_device: metadata.rdev(),
        owner_uid: metadata.uid(),
    })
}

fn classify_current_process_terminal_v1(
    stdin: TerminalPresenceV1,
    stderr: TerminalPresenceV1,
    pair: Option<(TerminalDeviceIdentityV1, TerminalDeviceIdentityV1)>,
) -> CurrentProcessTerminalObservationV1 {
    let (pair_identity, terminal_device, decision) =
        if stdin != TerminalPresenceV1::Terminal || stderr != TerminalPresenceV1::Terminal {
            (
                TerminalPairIdentityV1::NotObserved,
                None,
                MacOsTerminalIngressDecisionV1::DeniedNonInteractive,
            )
        } else {
            match pair {
                None => (
                    TerminalPairIdentityV1::MetadataUnavailable,
                    None,
                    MacOsTerminalIngressDecisionV1::DeniedUnverifiableTerminal,
                ),
                Some((stdin_device, stderr_device)) if stdin_device == stderr_device => (
                    TerminalPairIdentityV1::SameTerminal,
                    Some(stdin_device),
                    MacOsTerminalIngressDecisionV1::RequiresOwnershipAndForegroundProof,
                ),
                Some(_) => (
                    TerminalPairIdentityV1::DistinctTerminal,
                    None,
                    MacOsTerminalIngressDecisionV1::DeniedDistinctTerminal,
                ),
            }
        };

    CurrentProcessTerminalObservationV1 {
        schema_version: 1,
        process_id: std::process::id(),
        stdin,
        stderr,
        pair_identity,
        terminal_device,
        effective_user_id: None,
        process_group_id: None,
        terminal_foreground_process_group_id: None,
        process_session_id: None,
        terminal_session_id: None,
        effective_user_ownership: PlatformProofV1::Unverified,
        foreground_process_group: PlatformProofV1::Unverified,
        controlling_terminal_session: PlatformProofV1::Unverified,
        decision,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlatformIdentityObservationV1 {
    effective_user_id: u32,
    process_group_id: i32,
    terminal_foreground_process_group_id: Option<i32>,
    process_session_id: Option<i32>,
    terminal_session_id: Option<i32>,
    stable_terminal_device: Option<TerminalDeviceIdentityV1>,
}

fn observe_platform_proofs_v1(
    observation: CurrentProcessTerminalObservationV1,
) -> CurrentProcessTerminalObservationV1 {
    let stdin = io::stdin();
    let effective_user_id = rustix::process::geteuid().as_raw();
    let process_group_id = rustix::process::getpgrp().as_raw_pid();
    let terminal_foreground_process_group_id = rustix::termios::tcgetpgrp(&stdin)
        .ok()
        .map(rustix::process::Pid::as_raw_pid);
    let process_session_id = rustix::process::getsid(None)
        .ok()
        .map(rustix::process::Pid::as_raw_pid);
    let terminal_session_id = rustix::termios::tcgetsid(&stdin)
        .ok()
        .map(rustix::process::Pid::as_raw_pid);
    let stable_terminal_device =
        terminal_pair_metadata().and_then(
            |(stdin, stderr)| {
                if stdin == stderr { Some(stdin) } else { None }
            },
        );
    apply_platform_proofs_v1(
        observation,
        PlatformIdentityObservationV1 {
            effective_user_id,
            process_group_id,
            terminal_foreground_process_group_id,
            process_session_id,
            terminal_session_id,
            stable_terminal_device,
        },
    )
}

fn apply_platform_proofs_v1(
    mut observation: CurrentProcessTerminalObservationV1,
    platform: PlatformIdentityObservationV1,
) -> CurrentProcessTerminalObservationV1 {
    observation.effective_user_id = Some(platform.effective_user_id);
    observation.process_group_id = Some(platform.process_group_id);
    observation.terminal_foreground_process_group_id =
        platform.terminal_foreground_process_group_id;
    observation.process_session_id = platform.process_session_id;
    observation.terminal_session_id = platform.terminal_session_id;

    if platform.stable_terminal_device != observation.terminal_device {
        observation.pair_identity = TerminalPairIdentityV1::MetadataUnavailable;
        observation.terminal_device = None;
        observation.decision = MacOsTerminalIngressDecisionV1::DeniedUnverifiableTerminal;
        return observation;
    }
    let Some(terminal_device) = observation.terminal_device else {
        observation.decision = MacOsTerminalIngressDecisionV1::DeniedUnverifiableTerminal;
        return observation;
    };

    observation.effective_user_ownership =
        if terminal_device.owner_uid == platform.effective_user_id {
            PlatformProofV1::Verified
        } else {
            PlatformProofV1::Mismatch
        };
    observation.foreground_process_group = match platform.terminal_foreground_process_group_id {
        Some(foreground) if foreground == platform.process_group_id => PlatformProofV1::Verified,
        Some(_) => PlatformProofV1::Mismatch,
        None => PlatformProofV1::Unverified,
    };
    observation.controlling_terminal_session =
        match (platform.process_session_id, platform.terminal_session_id) {
            (Some(process), Some(terminal)) if process == terminal => PlatformProofV1::Verified,
            (Some(_), Some(_)) => PlatformProofV1::Mismatch,
            _ => PlatformProofV1::Unverified,
        };

    observation.decision = if observation.effective_user_ownership == PlatformProofV1::Mismatch {
        MacOsTerminalIngressDecisionV1::DeniedTerminalOwnerMismatch
    } else if observation.foreground_process_group == PlatformProofV1::Mismatch {
        MacOsTerminalIngressDecisionV1::DeniedBackgroundProcessGroup
    } else if observation.controlling_terminal_session == PlatformProofV1::Mismatch {
        MacOsTerminalIngressDecisionV1::DeniedForeignTerminalSession
    } else if observation.effective_user_ownership == PlatformProofV1::Verified
        && observation.foreground_process_group == PlatformProofV1::Verified
        && observation.controlling_terminal_session == PlatformProofV1::Verified
    {
        MacOsTerminalIngressDecisionV1::ReadyForChallengeResponse
    } else {
        MacOsTerminalIngressDecisionV1::DeniedUnverifiableTerminal
    };
    observation
}

#[cfg(test)]
mod tests {
    use super::*;

    const TERMINAL: TerminalDeviceIdentityV1 = TerminalDeviceIdentityV1 {
        device: 1,
        inode: 2,
        raw_device: 3,
        owner_uid: 501,
    };

    #[test]
    fn non_interactive_streams_are_denied_without_platform_claims() {
        let observation = classify_current_process_terminal_v1(
            TerminalPresenceV1::NotTerminal,
            TerminalPresenceV1::NotTerminal,
            None,
        );
        assert_eq!(
            observation.decision,
            MacOsTerminalIngressDecisionV1::DeniedNonInteractive
        );
        assert_eq!(
            observation.pair_identity,
            TerminalPairIdentityV1::NotObserved
        );
        assert_eq!(observation.terminal_device, None);
        assert_eq!(
            observation.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
    }

    #[test]
    fn same_terminal_still_requires_unforgeable_platform_proofs() {
        let observation = classify_current_process_terminal_v1(
            TerminalPresenceV1::Terminal,
            TerminalPresenceV1::Terminal,
            Some((TERMINAL, TERMINAL)),
        );
        assert_eq!(
            observation.decision,
            MacOsTerminalIngressDecisionV1::RequiresOwnershipAndForegroundProof
        );
        assert_eq!(
            observation.effective_user_ownership,
            PlatformProofV1::Unverified
        );
        assert_eq!(
            observation.foreground_process_group,
            PlatformProofV1::Unverified
        );
        assert_eq!(
            observation.controlling_terminal_session,
            PlatformProofV1::Unverified
        );
        assert_eq!(
            observation.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
    }

    #[test]
    fn distinct_terminal_devices_are_denied() {
        let another = TerminalDeviceIdentityV1 {
            inode: 4,
            ..TERMINAL
        };
        let observation = classify_current_process_terminal_v1(
            TerminalPresenceV1::Terminal,
            TerminalPresenceV1::Terminal,
            Some((TERMINAL, another)),
        );
        assert_eq!(
            observation.decision,
            MacOsTerminalIngressDecisionV1::DeniedDistinctTerminal
        );
        assert_eq!(observation.terminal_device, None);
    }

    #[test]
    fn missing_terminal_metadata_is_denied_as_unverifiable() {
        let observation = classify_current_process_terminal_v1(
            TerminalPresenceV1::Terminal,
            TerminalPresenceV1::Terminal,
            None,
        );
        assert_eq!(
            observation.decision,
            MacOsTerminalIngressDecisionV1::DeniedUnverifiableTerminal
        );
        assert_eq!(
            observation.pair_identity,
            TerminalPairIdentityV1::MetadataUnavailable
        );
    }

    #[test]
    fn matching_safe_platform_observations_only_reach_response_gate() {
        let observation = classify_current_process_terminal_v1(
            TerminalPresenceV1::Terminal,
            TerminalPresenceV1::Terminal,
            Some((TERMINAL, TERMINAL)),
        );
        let verified = apply_platform_proofs_v1(
            observation,
            PlatformIdentityObservationV1 {
                effective_user_id: 501,
                process_group_id: 42,
                terminal_foreground_process_group_id: Some(42),
                process_session_id: Some(10),
                terminal_session_id: Some(10),
                stable_terminal_device: Some(TERMINAL),
            },
        );
        assert_eq!(
            verified.decision,
            MacOsTerminalIngressDecisionV1::ReadyForChallengeResponse
        );
        assert_eq!(verified.effective_user_ownership, PlatformProofV1::Verified);
        assert_eq!(verified.foreground_process_group, PlatformProofV1::Verified);
        assert_eq!(
            verified.controlling_terminal_session,
            PlatformProofV1::Verified
        );
        assert_eq!(
            verified.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
    }

    #[test]
    fn ownership_foreground_and_session_mismatches_are_typed_denials() {
        let observation = classify_current_process_terminal_v1(
            TerminalPresenceV1::Terminal,
            TerminalPresenceV1::Terminal,
            Some((TERMINAL, TERMINAL)),
        );
        let facts = PlatformIdentityObservationV1 {
            effective_user_id: 502,
            process_group_id: 42,
            terminal_foreground_process_group_id: Some(43),
            process_session_id: Some(10),
            terminal_session_id: Some(11),
            stable_terminal_device: Some(TERMINAL),
        };
        assert_eq!(
            apply_platform_proofs_v1(observation, facts).decision,
            MacOsTerminalIngressDecisionV1::DeniedTerminalOwnerMismatch
        );
        assert_eq!(
            apply_platform_proofs_v1(
                observation,
                PlatformIdentityObservationV1 {
                    effective_user_id: 501,
                    ..facts
                },
            )
            .decision,
            MacOsTerminalIngressDecisionV1::DeniedBackgroundProcessGroup
        );
        assert_eq!(
            apply_platform_proofs_v1(
                observation,
                PlatformIdentityObservationV1 {
                    effective_user_id: 501,
                    terminal_foreground_process_group_id: Some(42),
                    ..facts
                },
            )
            .decision,
            MacOsTerminalIngressDecisionV1::DeniedForeignTerminalSession
        );
    }

    #[test]
    fn live_observation_never_grants_authority() {
        let observation = observe_current_process_terminal_v1();
        assert_eq!(observation.schema_version, 1);
        assert_eq!(observation.process_id, std::process::id());
        assert_eq!(
            observation.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
    }
}

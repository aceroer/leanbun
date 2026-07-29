#![forbid(unsafe_code)]

use core::fmt;
use leanbun_core::{DiagnosticCode, ExecutionId, ImageId, ProjectId, Sha256};
use leanbun_evidence::{BuildExecutionLockV1, build_lock_key};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockPublicationStep {
    VerifyDirectContainedStore,
    CreateExclusiveNoFollow,
    WriteCanonicalV1,
    SyncWrittenFile,
    SetModeReadOnly0444,
    SyncReadOnlyFile,
    SyncStoreDirectory,
    StrictReadback,
    UnlinkExactObservedLock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateRootScope {
    NewlyCreatedIsolatedRootOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemMutationAuthority {
    Withheld,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockPublicationInvariant {
    NeverReplaceExistingLock,
    NeverDeleteUnownedLock,
    CleanupOnlyNewlyCreatedLock,
    StrictReadbackBeforeSuccess,
    SyncDirectoryAfterMutation,
}

pub const ACQUIRE_PUBLICATION_PROTOCOL_V1: &[LockPublicationStep] = &[
    LockPublicationStep::VerifyDirectContainedStore,
    LockPublicationStep::CreateExclusiveNoFollow,
    LockPublicationStep::WriteCanonicalV1,
    LockPublicationStep::SyncWrittenFile,
    LockPublicationStep::SetModeReadOnly0444,
    LockPublicationStep::SyncReadOnlyFile,
    LockPublicationStep::SyncStoreDirectory,
    LockPublicationStep::StrictReadback,
];

pub const RELEASE_PUBLICATION_PROTOCOL_V1: &[LockPublicationStep] = &[
    LockPublicationStep::VerifyDirectContainedStore,
    LockPublicationStep::StrictReadback,
    LockPublicationStep::UnlinkExactObservedLock,
    LockPublicationStep::SyncStoreDirectory,
];

pub const LOCK_PUBLICATION_INVARIANTS_V1: &[LockPublicationInvariant] = &[
    LockPublicationInvariant::NeverReplaceExistingLock,
    LockPublicationInvariant::NeverDeleteUnownedLock,
    LockPublicationInvariant::CleanupOnlyNewlyCreatedLock,
    LockPublicationInvariant::StrictReadbackBeforeSuccess,
    LockPublicationInvariant::SyncDirectoryAfterMutation,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLockPublicationContractV1 {
    pub state_root_scope: StateRootScope,
    pub filesystem_mutation_authority: FilesystemMutationAuthority,
    pub acquire_protocol: &'static [LockPublicationStep],
    pub release_protocol: &'static [LockPublicationStep],
    pub invariants: &'static [LockPublicationInvariant],
}

pub const BUILD_LOCK_PUBLICATION_CONTRACT_V1: BuildLockPublicationContractV1 =
    BuildLockPublicationContractV1 {
        state_root_scope: StateRootScope::NewlyCreatedIsolatedRootOnly,
        filesystem_mutation_authority: FilesystemMutationAuthority::Withheld,
        acquire_protocol: ACQUIRE_PUBLICATION_PROTOCOL_V1,
        release_protocol: RELEASE_PUBLICATION_PROTOCOL_V1,
        invariants: LOCK_PUBLICATION_INVARIANTS_V1,
    };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLockOwnershipV1 {
    key: Sha256,
    execution_id: ExecutionId,
    project_id: ProjectId,
    image_id: ImageId,
}

impl BuildLockOwnershipV1 {
    pub fn new(
        key: Sha256,
        execution_id: ExecutionId,
        project_id: ProjectId,
        image_id: ImageId,
    ) -> Result<Self, StateTransitionError> {
        if key != build_lock_key(project_id, image_id) {
            return Err(StateTransitionError::new(
                DiagnosticCode::BUILD_LOCK_FAILED,
                "build lock ownership key does not match project/image identity",
            ));
        }
        Ok(Self {
            key,
            execution_id,
            project_id,
            image_id,
        })
    }

    pub fn from_lock(lock: &BuildExecutionLockV1) -> Result<Self, StateTransitionError> {
        Self::new(lock.key, lock.execution_id, lock.project_id, lock.image_id)
    }

    #[must_use]
    pub const fn key(self) -> Sha256 {
        self.key
    }

    #[must_use]
    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    #[must_use]
    pub const fn project_id(self) -> ProjectId {
        self.project_id
    }

    #[must_use]
    pub const fn image_id(self) -> ImageId {
        self.image_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildLockObservation<'a> {
    Absent,
    Held(&'a BuildExecutionLockV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquireBuildLockDecision {
    PublishNew {
        document: BuildExecutionLockV1,
        protocol: &'static [LockPublicationStep],
    },
    Busy {
        owner: BuildLockOwnershipV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseBuildLockDecision {
    AlreadyReleased,
    RemoveOwned {
        owner: BuildLockOwnershipV1,
        protocol: &'static [LockPublicationStep],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateTransitionError {
    pub code: DiagnosticCode,
    pub message: String,
}

impl StateTransitionError {
    fn new(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for StateTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StateTransitionError {}

pub fn decide_acquire_build_lock(
    observation: &BuildLockObservation<'_>,
    requested: BuildExecutionLockV1,
) -> Result<AcquireBuildLockDecision, StateTransitionError> {
    BuildLockOwnershipV1::from_lock(&requested)?;
    match observation {
        BuildLockObservation::Absent => Ok(AcquireBuildLockDecision::PublishNew {
            document: requested,
            protocol: ACQUIRE_PUBLICATION_PROTOCOL_V1,
        }),
        BuildLockObservation::Held(existing) => {
            let owner = BuildLockOwnershipV1::from_lock(existing).map_err(|_| {
                StateTransitionError::new(
                    DiagnosticCode::BUILD_LOCK_CONFLICT,
                    "observed build lock ownership is internally inconsistent",
                )
            })?;
            Ok(AcquireBuildLockDecision::Busy { owner })
        }
    }
}

pub fn decide_release_build_lock(
    observation: &BuildLockObservation<'_>,
    expected: BuildLockOwnershipV1,
) -> Result<ReleaseBuildLockDecision, StateTransitionError> {
    match observation {
        BuildLockObservation::Absent => Ok(ReleaseBuildLockDecision::AlreadyReleased),
        BuildLockObservation::Held(existing) => {
            let observed = BuildLockOwnershipV1::from_lock(existing).map_err(|_| {
                StateTransitionError::new(
                    DiagnosticCode::BUILD_LOCK_CONFLICT,
                    "observed build lock ownership is internally inconsistent",
                )
            })?;
            if observed != expected {
                return Err(StateTransitionError::new(
                    DiagnosticCode::BUILD_LOCK_CONFLICT,
                    "build lock belongs to another execution",
                ));
            }
            Ok(ReleaseBuildLockDecision::RemoveOwned {
                owner: observed,
                protocol: RELEASE_PUBLICATION_PROTOCOL_V1,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanbun_core::{BuildTarget, project_id};

    const EXECUTION: &str = "12345678-1234-4123-8123-123456789abc";
    const OTHER_EXECUTION: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    fn lock(execution: &str) -> Result<BuildExecutionLockV1, Box<dyn std::error::Error>> {
        let project = project_id("/fixture/project");
        let image = ImageId::parse(&"1".repeat(64))?;
        Ok(BuildExecutionLockV1 {
            key: build_lock_key(project, image),
            execution_id: ExecutionId::parse(execution)?,
            project_id: project,
            project_path: "/fixture/project".to_owned(),
            image_id: image,
            target: BuildTarget::parse("Fixture")?,
            coordinator_pid: 4242,
            acquired_at: "2026-07-24T00:00:00.000Z".to_owned(),
        })
    }

    #[test]
    fn absent_acquire_emits_a_pure_publication_intent() -> Result<(), Box<dyn std::error::Error>> {
        let requested = lock(EXECUTION)?;
        assert_eq!(
            decide_acquire_build_lock(&BuildLockObservation::Absent, requested.clone())?,
            AcquireBuildLockDecision::PublishNew {
                document: requested,
                protocol: ACQUIRE_PUBLICATION_PROTOCOL_V1,
            }
        );
        Ok(())
    }

    #[test]
    fn held_acquire_is_busy_for_same_or_other_execution() -> Result<(), Box<dyn std::error::Error>>
    {
        let requested = lock(EXECUTION)?;
        for existing in [lock(EXECUTION)?, lock(OTHER_EXECUTION)?] {
            assert!(matches!(
                decide_acquire_build_lock(
                    &BuildLockObservation::Held(&existing),
                    requested.clone()
                )?,
                AcquireBuildLockDecision::Busy { .. }
            ));
        }
        Ok(())
    }

    #[test]
    fn release_requires_exact_ownership() -> Result<(), Box<dyn std::error::Error>> {
        let expected = BuildLockOwnershipV1::from_lock(&lock(EXECUTION)?)?;
        let matching_lock = lock(EXECUTION)?;
        let matching =
            decide_release_build_lock(&BuildLockObservation::Held(&matching_lock), expected)?;
        assert!(matches!(
            matching,
            ReleaseBuildLockDecision::RemoveOwned { .. }
        ));
        let other_lock = lock(OTHER_EXECUTION)?;
        assert_eq!(
            decide_release_build_lock(&BuildLockObservation::Held(&other_lock), expected)
                .map_err(|error| error.code),
            Err(DiagnosticCode::BUILD_LOCK_CONFLICT)
        );
        Ok(())
    }

    #[test]
    fn absent_release_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let expected = BuildLockOwnershipV1::from_lock(&lock(EXECUTION)?)?;
        assert_eq!(
            decide_release_build_lock(&BuildLockObservation::Absent, expected)?,
            ReleaseBuildLockDecision::AlreadyReleased
        );
        Ok(())
    }

    #[test]
    fn invalid_key_cannot_form_ownership_or_publication() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut invalid = lock(EXECUTION)?;
        invalid.key = Sha256::parse(&"0".repeat(64))?;
        assert_eq!(
            BuildLockOwnershipV1::from_lock(&invalid).map_err(|error| error.code),
            Err(DiagnosticCode::BUILD_LOCK_FAILED)
        );
        assert_eq!(
            decide_acquire_build_lock(&BuildLockObservation::Absent, invalid)
                .map_err(|error| error.code),
            Err(DiagnosticCode::BUILD_LOCK_FAILED)
        );
        Ok(())
    }

    #[test]
    fn publication_protocol_keeps_critical_order() {
        assert_eq!(
            ACQUIRE_PUBLICATION_PROTOCOL_V1,
            &[
                LockPublicationStep::VerifyDirectContainedStore,
                LockPublicationStep::CreateExclusiveNoFollow,
                LockPublicationStep::WriteCanonicalV1,
                LockPublicationStep::SyncWrittenFile,
                LockPublicationStep::SetModeReadOnly0444,
                LockPublicationStep::SyncReadOnlyFile,
                LockPublicationStep::SyncStoreDirectory,
                LockPublicationStep::StrictReadback,
            ]
        );
        assert_eq!(
            RELEASE_PUBLICATION_PROTOCOL_V1,
            &[
                LockPublicationStep::VerifyDirectContainedStore,
                LockPublicationStep::StrictReadback,
                LockPublicationStep::UnlinkExactObservedLock,
                LockPublicationStep::SyncStoreDirectory,
            ]
        );
        assert_eq!(
            BUILD_LOCK_PUBLICATION_CONTRACT_V1.state_root_scope,
            StateRootScope::NewlyCreatedIsolatedRootOnly
        );
        assert_eq!(
            BUILD_LOCK_PUBLICATION_CONTRACT_V1.filesystem_mutation_authority,
            FilesystemMutationAuthority::Withheld
        );
        assert_eq!(
            BUILD_LOCK_PUBLICATION_CONTRACT_V1.invariants,
            LOCK_PUBLICATION_INVARIANTS_V1
        );
    }

    #[test]
    fn shared_transition_cases_match_bun_oracle() -> Result<(), Box<dyn std::error::Error>> {
        for line in include_str!("../../../golden/build-lock-transition-cases.tsv").lines() {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 5, "{line}");
            let expected = fields[0];
            let operation = fields[2];
            let observed = if fields[3] == "absent" {
                None
            } else {
                Some(lock(fields[3])?)
            };
            let observation = observed
                .as_ref()
                .map_or(BuildLockObservation::Absent, BuildLockObservation::Held);
            let requested = lock(fields[4])?;
            let actual = match operation {
                "acquire" => match decide_acquire_build_lock(&observation, requested)? {
                    AcquireBuildLockDecision::PublishNew { .. } => "publish-new",
                    AcquireBuildLockDecision::Busy { .. } => "busy",
                },
                "release" => {
                    let owner = BuildLockOwnershipV1::from_lock(&requested)?;
                    match decide_release_build_lock(&observation, owner) {
                        Ok(ReleaseBuildLockDecision::AlreadyReleased) => "already-released",
                        Ok(ReleaseBuildLockDecision::RemoveOwned { .. }) => "remove-owned",
                        Err(error) if error.code == DiagnosticCode::BUILD_LOCK_CONFLICT => {
                            "conflict"
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                _ => return Err(format!("unknown operation in {line}").into()),
            };
            assert_eq!(actual, expected, "{}", fields[1]);
        }
        Ok(())
    }
}

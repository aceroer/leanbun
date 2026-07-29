use leanbun_plan::PlanExecutionAuthorityV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsExecutableHandoffMechanismV1 {
    RustStandardCommand,
    RustStandardPreExec,
    RustixExecveAt,
    MacOsPosixSpawn,
    BunSystemPosixSpawn,
    DevFdExecutablePath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsExecutableHandoffRejectionV1 {
    ResolvesExecutableByPathAtLaunch,
    UnsafeCallbackWithoutFdExecutionPrimitive,
    UnavailableOnMacOs,
    ExecutableFdNotAccepted,
    ExecutableDevFdDeniedByKernel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsExecutableHandoffAssessmentV1 {
    pub mechanism: MacOsExecutableHandoffMechanismV1,
    pub rejection: MacOsExecutableHandoffRejectionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsExecutableHandoffDecisionV1 {
    DeniedNoStableFdBoundExecution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsExecutableHandoffContractV1 {
    pub schema_version: u8,
    pub rust_version: &'static str,
    pub rustix_version: &'static str,
    pub macos_sdk_version: &'static str,
    pub bun_source_revision: &'static str,
    pub assessments: [MacOsExecutableHandoffAssessmentV1; 6],
    pub decision: MacOsExecutableHandoffDecisionV1,
    pub execution_authority: PlanExecutionAuthorityV1,
}

/// Records the M20 macOS executable-handoff audit as a fail-closed contract.
///
/// The contract is descriptive only. It does not accept a reservation, open an
/// executable, create a child process, or grant execution authority.
#[must_use]
pub const fn macos_executable_handoff_contract_v1() -> MacOsExecutableHandoffContractV1 {
    use MacOsExecutableHandoffMechanismV1 as Mechanism;
    use MacOsExecutableHandoffRejectionV1 as Rejection;

    MacOsExecutableHandoffContractV1 {
        schema_version: 1,
        rust_version: "1.96.0",
        rustix_version: "1.1.4",
        macos_sdk_version: "26.5",
        bun_source_revision: "892b1dabc69e2a0a973244f772b84967c73ccad5",
        assessments: [
            MacOsExecutableHandoffAssessmentV1 {
                mechanism: Mechanism::RustStandardCommand,
                rejection: Rejection::ResolvesExecutableByPathAtLaunch,
            },
            MacOsExecutableHandoffAssessmentV1 {
                mechanism: Mechanism::RustStandardPreExec,
                rejection: Rejection::UnsafeCallbackWithoutFdExecutionPrimitive,
            },
            MacOsExecutableHandoffAssessmentV1 {
                mechanism: Mechanism::RustixExecveAt,
                rejection: Rejection::UnavailableOnMacOs,
            },
            MacOsExecutableHandoffAssessmentV1 {
                mechanism: Mechanism::MacOsPosixSpawn,
                rejection: Rejection::ExecutableFdNotAccepted,
            },
            MacOsExecutableHandoffAssessmentV1 {
                mechanism: Mechanism::BunSystemPosixSpawn,
                rejection: Rejection::ResolvesExecutableByPathAtLaunch,
            },
            MacOsExecutableHandoffAssessmentV1 {
                mechanism: Mechanism::DevFdExecutablePath,
                rejection: Rejection::ExecutableDevFdDeniedByKernel,
            },
        ],
        decision: MacOsExecutableHandoffDecisionV1::DeniedNoStableFdBoundExecution,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_audited_handoff_mechanisms_fail_closed() {
        let contract = macos_executable_handoff_contract_v1();

        assert_eq!(contract.schema_version, 1);
        assert_eq!(contract.rust_version, "1.96.0");
        assert_eq!(contract.rustix_version, "1.1.4");
        assert_eq!(contract.macos_sdk_version, "26.5");
        assert_eq!(
            contract.bun_source_revision,
            "892b1dabc69e2a0a973244f772b84967c73ccad5"
        );
        assert_eq!(contract.assessments.len(), 6);
        assert_eq!(
            contract.decision,
            MacOsExecutableHandoffDecisionV1::DeniedNoStableFdBoundExecution
        );
        assert_eq!(
            contract.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        assert!(contract.assessments.iter().all(|assessment| matches!(
            assessment.rejection,
            MacOsExecutableHandoffRejectionV1::ResolvesExecutableByPathAtLaunch
                | MacOsExecutableHandoffRejectionV1::UnsafeCallbackWithoutFdExecutionPrimitive
                | MacOsExecutableHandoffRejectionV1::UnavailableOnMacOs
                | MacOsExecutableHandoffRejectionV1::ExecutableFdNotAccepted
                | MacOsExecutableHandoffRejectionV1::ExecutableDevFdDeniedByKernel
        )));
    }
}

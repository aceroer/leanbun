use crate::{
    LakeCommandApprovalConsumptionDecisionV1, LakeCommandApprovalConsumptionRecordV1,
    TrustedFreshLakeUpdatePlanV1,
};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_plan::{
    LakeCommandApprovalRequestV1, LakeCommandPlanV1, LakeCommandPreflightV1,
    LakeExecutableObservationV1, PlanExecutionAuthorityV1, lake_command_preflight_v1,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeCommandTrustedApprovalProofDecisionV1 {
    FreshFactsReverified,
}

#[derive(Debug, Eq, PartialEq)]
pub struct LakeCommandTrustedApprovalProofV1 {
    pub(crate) schema_version: u8,
    pub(crate) decision: LakeCommandTrustedApprovalProofDecisionV1,
    pub(crate) challenge_id: Sha256,
    pub(crate) request_id: Sha256,
    pub(crate) consumption_record_sha256: Sha256,
    pub(crate) challenged_preflight_sha256: Sha256,
    pub(crate) fresh_preflight_sha256: Sha256,
    pub(crate) response_sha256: Sha256,
    pub(crate) plan_report_sha256: Sha256,
    pub(crate) inventory_snapshot_sha256: Sha256,
    pub(crate) executable_sha256: Sha256,
    pub(crate) responded_at_unix_ms: u64,
    pub(crate) consumed_at_unix_ms: u64,
    pub(crate) executable_observed_at_unix_ms: u64,
    pub(crate) verified_at_unix_ms: u64,
    pub(crate) proof_sha256: Sha256,
    pub(crate) execution_authority: PlanExecutionAuthorityV1,
}

impl LakeCommandTrustedApprovalProofV1 {
    #[must_use]
    pub fn decision(&self) -> LakeCommandTrustedApprovalProofDecisionV1 {
        self.decision
    }

    #[must_use]
    pub fn challenge_id(&self) -> Sha256 {
        self.challenge_id
    }

    #[must_use]
    pub fn request_id(&self) -> Sha256 {
        self.request_id
    }

    #[must_use]
    pub fn consumption_record_sha256(&self) -> Sha256 {
        self.consumption_record_sha256
    }

    #[must_use]
    pub fn challenged_preflight_sha256(&self) -> Sha256 {
        self.challenged_preflight_sha256
    }

    #[must_use]
    pub fn fresh_preflight_sha256(&self) -> Sha256 {
        self.fresh_preflight_sha256
    }

    #[must_use]
    pub fn response_sha256(&self) -> Sha256 {
        self.response_sha256
    }

    #[must_use]
    pub fn plan_report_sha256(&self) -> Sha256 {
        self.plan_report_sha256
    }

    #[must_use]
    pub fn inventory_snapshot_sha256(&self) -> Sha256 {
        self.inventory_snapshot_sha256
    }

    #[must_use]
    pub fn executable_sha256(&self) -> Sha256 {
        self.executable_sha256
    }

    #[must_use]
    pub fn responded_at_unix_ms(&self) -> u64 {
        self.responded_at_unix_ms
    }

    #[must_use]
    pub fn consumed_at_unix_ms(&self) -> u64 {
        self.consumed_at_unix_ms
    }

    #[must_use]
    pub fn executable_observed_at_unix_ms(&self) -> u64 {
        self.executable_observed_at_unix_ms
    }

    #[must_use]
    pub fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }

    #[must_use]
    pub fn proof_sha256(&self) -> Sha256 {
        self.proof_sha256
    }

    #[must_use]
    pub fn execution_authority(&self) -> PlanExecutionAuthorityV1 {
        self.execution_authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsApprovalProofRejectionV1 {
    InvalidConsumptionRecord,
    RequestMismatch,
    ObservationOrderingInvalid,
    FreshPreflightRejected,
    VerificationTimeInvalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsApprovalProofError {
    pub rejection: MacOsApprovalProofRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsApprovalProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsApprovalProofError {}

pub fn reverify_consumed_lake_command_approval_v1(
    consumption: LakeCommandApprovalConsumptionRecordV1,
    request: &LakeCommandApprovalRequestV1,
    fresh: TrustedFreshLakeUpdatePlanV1,
) -> Result<LakeCommandTrustedApprovalProofV1, MacOsApprovalProofError> {
    Ok(reverify_fresh_bundle_v1(consumption, request, fresh)?.1)
}

pub(crate) fn reverify_fresh_bundle_v1(
    consumption: LakeCommandApprovalConsumptionRecordV1,
    request: &LakeCommandApprovalRequestV1,
    fresh: TrustedFreshLakeUpdatePlanV1,
) -> Result<(LakeCommandPlanV1, LakeCommandTrustedApprovalProofV1), MacOsApprovalProofError> {
    let verified_at_unix_ms = current_unix_ms()?;
    let executable_observed_at_unix_ms = fresh.executable.observed_at_unix_ms;
    let proof = reverify_at_v1(
        consumption,
        request,
        &fresh.plan,
        &fresh.executable.observation,
        executable_observed_at_unix_ms,
        verified_at_unix_ms,
    )?;
    Ok((fresh.plan, proof))
}

fn reverify_at_v1(
    consumption: LakeCommandApprovalConsumptionRecordV1,
    request: &LakeCommandApprovalRequestV1,
    fresh_plan: &LakeCommandPlanV1,
    fresh_executable: &LakeExecutableObservationV1,
    executable_observed_at_unix_ms: u64,
    verified_at_unix_ms: u64,
) -> Result<LakeCommandTrustedApprovalProofV1, MacOsApprovalProofError> {
    if consumption.schema_version != 1
        || consumption.decision != LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce
        || consumption.execution_authority != PlanExecutionAuthorityV1::Withheld
        || consumption.responded_at_unix_ms > consumption.consumed_at_unix_ms
        || consumption.consumed_at_unix_ms >= consumption.challenge_expires_at_unix_ms
    {
        return Err(proof_error(
            MacOsApprovalProofRejectionV1::InvalidConsumptionRecord,
            "trusted approval proof requires a valid sealed single-use consumption record",
        ));
    }
    if consumption.request_id != request.request_id {
        return Err(proof_error(
            MacOsApprovalProofRejectionV1::RequestMismatch,
            "consumed response and approval request identities differ",
        ));
    }
    if executable_observed_at_unix_ms < consumption.consumed_at_unix_ms
        || verified_at_unix_ms < executable_observed_at_unix_ms
    {
        return Err(proof_error(
            MacOsApprovalProofRejectionV1::ObservationOrderingInvalid,
            "fresh preflight observation must occur after consumption and before verification",
        ));
    }
    if verified_at_unix_ms >= consumption.challenge_expires_at_unix_ms {
        return Err(proof_error(
            MacOsApprovalProofRejectionV1::VerificationTimeInvalid,
            "trusted approval proof must be completed inside the challenge window",
        ));
    }

    let fresh_preflight = lake_command_preflight_v1(
        request,
        fresh_plan,
        fresh_executable,
        executable_observed_at_unix_ms,
        verified_at_unix_ms,
    )
    .map_err(|error| {
        proof_error(
            MacOsApprovalProofRejectionV1::FreshPreflightRejected,
            format!("fresh Lake preflight was rejected: {}", error.message),
        )
    })?;
    let fresh_preflight_sha256 = preflight_sha256(&fresh_preflight);
    let proof_sha256 = proof_sha256(
        &consumption,
        &fresh_preflight,
        fresh_preflight_sha256,
        verified_at_unix_ms,
    );
    Ok(LakeCommandTrustedApprovalProofV1 {
        schema_version: 1,
        decision: LakeCommandTrustedApprovalProofDecisionV1::FreshFactsReverified,
        challenge_id: consumption.challenge_id,
        request_id: consumption.request_id,
        consumption_record_sha256: consumption.record_sha256,
        challenged_preflight_sha256: consumption.preflight_sha256,
        fresh_preflight_sha256,
        response_sha256: consumption.response_sha256,
        plan_report_sha256: fresh_preflight.plan_report_sha256,
        inventory_snapshot_sha256: fresh_preflight.inventory_snapshot_sha256,
        executable_sha256: fresh_preflight.executable_sha256,
        responded_at_unix_ms: consumption.responded_at_unix_ms,
        consumed_at_unix_ms: consumption.consumed_at_unix_ms,
        executable_observed_at_unix_ms,
        verified_at_unix_ms,
        proof_sha256,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

fn preflight_sha256(preflight: &LakeCommandPreflightV1) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(preflight.to_canonical_json().as_bytes());
    hasher.finalize()
}

fn proof_sha256(
    consumption: &LakeCommandApprovalConsumptionRecordV1,
    fresh_preflight: &LakeCommandPreflightV1,
    fresh_preflight_sha256: Sha256,
    verified_at_unix_ms: u64,
) -> Sha256 {
    let identity = format!(
        "{{\"schema\":\"leanbun-trusted-approval-proof-v1\",\"challengeId\":\"{}\",\"requestId\":\"{}\",\"consumptionRecordSha256\":\"{}\",\"challengedPreflightSha256\":\"{}\",\"freshPreflightSha256\":\"{}\",\"responseSha256\":\"{}\",\"planReportSha256\":\"{}\",\"inventorySnapshotSha256\":\"{}\",\"executableSha256\":\"{}\",\"respondedAtUnixMs\":{},\"consumedAtUnixMs\":{},\"executableObservedAtUnixMs\":{},\"verifiedAtUnixMs\":{},\"executionAuthority\":\"withheld\"}}",
        consumption.challenge_id,
        consumption.request_id,
        consumption.record_sha256,
        consumption.preflight_sha256,
        fresh_preflight_sha256,
        consumption.response_sha256,
        fresh_preflight.plan_report_sha256,
        fresh_preflight.inventory_snapshot_sha256,
        fresh_preflight.executable_sha256,
        consumption.responded_at_unix_ms,
        consumption.consumed_at_unix_ms,
        fresh_preflight.observed_at_unix_ms,
        verified_at_unix_ms,
    );
    let mut hasher = Sha256Hasher::new();
    hasher.update(identity.as_bytes());
    hasher.finalize()
}

fn current_unix_ms() -> Result<u64, MacOsApprovalProofError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        proof_error(
            MacOsApprovalProofRejectionV1::VerificationTimeInvalid,
            "system clock is before Unix epoch",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        proof_error(
            MacOsApprovalProofRejectionV1::VerificationTimeInvalid,
            "system clock is out of range",
        )
    })
}

fn proof_error(
    rejection: MacOsApprovalProofRejectionV1,
    message: impl Into<String>,
) -> MacOsApprovalProofError {
    MacOsApprovalProofError {
        rejection,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustedTerminalBindingV1;
    use leanbun_evidence::{canonicalize_contained, canonicalize_directory};
    use leanbun_plan::{
        CommandNetworkPolicyV1, CommandPermissionClassV1, LakeCommandFamilyV1, PlanRiskV1,
        PlannedEffectV1, SUPPORTED_LAKE_VERSION, lake_command_approval_request_v1,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const ISSUED: u64 = 1_800_000_000_000;
    const REQUEST_EXPIRES: u64 = 1_800_000_600_000;
    const RESPONDED: u64 = 1_800_000_300_000;
    const CONSUMED: u64 = 1_800_000_300_100;
    const CHALLENGE_EXPIRES: u64 = 1_800_000_360_000;
    const OBSERVED: u64 = 1_800_000_300_200;
    const VERIFIED: u64 = 1_800_000_300_300;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        plan: LakeCommandPlanV1,
        executable: LakeExecutableObservationV1,
        request: LakeCommandApprovalRequestV1,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = PathBuf::from(format!(
                "/tmp/leanbun-proof-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("toolchain/bin"))?;
            fs::create_dir(root.join("project"))?;
            fs::write(root.join("toolchain/bin/lake"), b"fixture")?;
            fs::set_permissions(
                root.join("toolchain/bin/lake"),
                fs::Permissions::from_mode(0o755),
            )?;
            let canonical_root = canonicalize_directory(&root)?;
            let executable_path = canonicalize_contained(&canonical_root, "toolchain/bin/lake")?;
            let project =
                leanbun_evidence::canonicalize_contained_directory(&canonical_root, "project")?;
            let executable_sha256 =
                Sha256::parse("f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d")?;
            let inventory_snapshot_sha256 =
                Sha256::parse("56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2")?;
            let executable = LakeExecutableObservationV1 {
                schema_version: 1,
                canonical_path: executable_path.clone(),
                lake_version: SUPPORTED_LAKE_VERSION.to_owned(),
                sha256: executable_sha256,
                byte_length: 7,
                unix_mode: 0o755,
                regular_file: true,
                symlink_free: true,
            };
            let plan = LakeCommandPlanV1 {
                schema_version: 1,
                family: LakeCommandFamilyV1::Update,
                lake_version: SUPPORTED_LAKE_VERSION.to_owned(),
                inventory_snapshot_sha256,
                executable: executable_path,
                executable_sha256,
                executable_byte_length: 7,
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
            let request = lake_command_approval_request_v1(
                &plan,
                "123e4567-e89b-42d3-a456-426614174000",
                ISSUED,
                REQUEST_EXPIRES,
            )?;
            Ok(Self {
                root,
                plan,
                executable,
                request,
            })
        }

        fn consumption(
            &self,
        ) -> Result<LakeCommandApprovalConsumptionRecordV1, Box<dyn std::error::Error>> {
            Ok(LakeCommandApprovalConsumptionRecordV1 {
                schema_version: 1,
                decision: LakeCommandApprovalConsumptionDecisionV1::ConsumedOnce,
                challenge_id: Sha256::parse(
                    "905b7cadc6b96de0468b0833883dc41f6126ae9260de971532a1d4e5d943e260",
                )?,
                request_id: self.request.request_id,
                preflight_sha256: Sha256::parse(
                    "3a3be2ae3e43dc3534d9f1e81f6caecf7851202f9cafd4c1b95af75ff598a6e8",
                )?,
                response_sha256: Sha256::parse(
                    "9667e61009b97e347b7186bc55ea573a6ee4c1d1d82861d7613b40c81e54681d",
                )?,
                terminal_binding: TrustedTerminalBindingV1 {
                    device: 10,
                    inode: 20,
                    raw_device: 30,
                    owner_uid: 501,
                    effective_user_id: 501,
                    process_group_id: 40,
                    process_session_id: 50,
                },
                responded_at_unix_ms: RESPONDED,
                consumed_at_unix_ms: CONSUMED,
                challenge_expires_at_unix_ms: CHALLENGE_EXPIRES,
                record_sha256: Sha256::parse(
                    "4f7c55fce1e711fdb559c3fe4193002c084acba8f2b06a954cc79f66a384b820",
                )?,
                execution_authority: PlanExecutionAuthorityV1::Withheld,
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn fresh_facts_form_only_a_withheld_proof() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let proof = reverify_at_v1(
            fixture.consumption()?,
            &fixture.request,
            &fixture.plan,
            &fixture.executable,
            OBSERVED,
            VERIFIED,
        )?;
        assert_eq!(
            proof.decision,
            LakeCommandTrustedApprovalProofDecisionV1::FreshFactsReverified
        );
        assert_eq!(proof.request_id, fixture.request.request_id);
        assert_eq!(
            proof.inventory_snapshot_sha256,
            fixture.plan.inventory_snapshot_sha256
        );
        assert_eq!(proof.executable_sha256, fixture.executable.sha256);
        assert_eq!(
            proof.execution_authority,
            PlanExecutionAuthorityV1::Withheld
        );
        Ok(())
    }

    #[test]
    fn inventory_executable_and_age_drift_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut changed_plan = fixture.plan.clone();
        changed_plan.inventory_snapshot_sha256 = Sha256::parse(&"2".repeat(64))?;
        let inventory_error = reverify_at_v1(
            fixture.consumption()?,
            &fixture.request,
            &changed_plan,
            &fixture.executable,
            OBSERVED,
            VERIFIED,
        )
        .map_err(|error| error.rejection);
        assert_eq!(
            inventory_error,
            Err(MacOsApprovalProofRejectionV1::FreshPreflightRejected)
        );

        let mut changed_executable = fixture.executable.clone();
        changed_executable.sha256 = Sha256::parse(&"3".repeat(64))?;
        let executable_error = reverify_at_v1(
            fixture.consumption()?,
            &fixture.request,
            &fixture.plan,
            &changed_executable,
            OBSERVED,
            VERIFIED,
        )
        .map_err(|error| error.rejection);
        assert_eq!(
            executable_error,
            Err(MacOsApprovalProofRejectionV1::FreshPreflightRejected)
        );

        let stale_error = reverify_at_v1(
            fixture.consumption()?,
            &fixture.request,
            &fixture.plan,
            &fixture.executable,
            OBSERVED,
            OBSERVED + 5_001,
        )
        .map_err(|error| error.rejection);
        assert_eq!(
            stale_error,
            Err(MacOsApprovalProofRejectionV1::FreshPreflightRejected)
        );
        Ok(())
    }

    #[test]
    fn ordering_request_and_challenge_expiry_are_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let ordering_error = reverify_at_v1(
            fixture.consumption()?,
            &fixture.request,
            &fixture.plan,
            &fixture.executable,
            CONSUMED - 1,
            VERIFIED,
        )
        .map_err(|error| error.rejection);
        assert_eq!(
            ordering_error,
            Err(MacOsApprovalProofRejectionV1::ObservationOrderingInvalid)
        );

        let mut wrong_request = fixture.request.clone();
        wrong_request.request_id = Sha256::parse(&"4".repeat(64))?;
        let request_error = reverify_at_v1(
            fixture.consumption()?,
            &wrong_request,
            &fixture.plan,
            &fixture.executable,
            OBSERVED,
            VERIFIED,
        )
        .map_err(|error| error.rejection);
        assert_eq!(
            request_error,
            Err(MacOsApprovalProofRejectionV1::RequestMismatch)
        );

        let expiry_error = reverify_at_v1(
            fixture.consumption()?,
            &fixture.request,
            &fixture.plan,
            &fixture.executable,
            OBSERVED,
            CHALLENGE_EXPIRES,
        )
        .map_err(|error| error.rejection);
        assert_eq!(
            expiry_error,
            Err(MacOsApprovalProofRejectionV1::VerificationTimeInvalid)
        );
        Ok(())
    }
}

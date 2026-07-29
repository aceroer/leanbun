use super::{
    LakeCommandApprovalRequestV1, LakeCommandPlanV1, LakeExecutableObservationV1,
    PlanExecutionAuthorityV1, verify_lake_command_approval_request_v1,
};
use core::fmt;
use leanbun_core::Sha256;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_OBSERVATION_AGE_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeCommandPreflightDecisionV1 {
    ReadyForExplicitApproval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeCommandPreflightRejectionV1 {
    RequestInvalid,
    ObservationTimeInvalid,
    ExecutableInvalid,
    ExecutableMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandPreflightV1 {
    pub schema_version: u8,
    pub decision: LakeCommandPreflightDecisionV1,
    pub request_id: Sha256,
    pub plan_report_sha256: Sha256,
    pub inventory_snapshot_sha256: Sha256,
    pub executable_sha256: Sha256,
    pub observed_at_unix_ms: u64,
    pub execution_authority: PlanExecutionAuthorityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandPreflightError {
    pub rejection: LakeCommandPreflightRejectionV1,
    pub message: String,
}

impl LakeCommandPreflightError {
    fn new(rejection: LakeCommandPreflightRejectionV1, message: impl Into<String>) -> Self {
        Self {
            rejection,
            message: message.into(),
        }
    }
}

impl fmt::Display for LakeCommandPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LakeCommandPreflightError {}

pub fn lake_command_preflight_v1(
    request: &LakeCommandApprovalRequestV1,
    fresh_plan: &LakeCommandPlanV1,
    fresh_executable: &LakeExecutableObservationV1,
    observed_at_unix_ms: u64,
    observed_now_unix_ms: u64,
) -> Result<LakeCommandPreflightV1, LakeCommandPreflightError> {
    verify_lake_command_approval_request_v1(request, fresh_plan, observed_now_unix_ms).map_err(
        |error| {
            LakeCommandPreflightError::new(
                LakeCommandPreflightRejectionV1::RequestInvalid,
                error.message,
            )
        },
    )?;
    if observed_at_unix_ms == 0
        || observed_at_unix_ms > MAX_SAFE_INTEGER
        || observed_now_unix_ms > MAX_SAFE_INTEGER
        || observed_at_unix_ms > observed_now_unix_ms
        || observed_now_unix_ms - observed_at_unix_ms > MAX_OBSERVATION_AGE_MS
    {
        return Err(LakeCommandPreflightError::new(
            LakeCommandPreflightRejectionV1::ObservationTimeInvalid,
            "executable observation must be current, ordered, and at most five seconds old",
        ));
    }
    if fresh_executable.schema_version != 1
        || !fresh_executable.regular_file
        || !fresh_executable.symlink_free
        || fresh_executable.byte_length == 0
        || fresh_executable.unix_mode & 0o111 == 0
    {
        return Err(LakeCommandPreflightError::new(
            LakeCommandPreflightRejectionV1::ExecutableInvalid,
            "fresh Lake executable observation is not safe",
        ));
    }
    if fresh_executable.canonical_path != fresh_plan.executable
        || fresh_executable.lake_version != fresh_plan.lake_version
        || fresh_executable.sha256 != fresh_plan.executable_sha256
        || fresh_executable.byte_length != fresh_plan.executable_byte_length
        || fresh_executable.unix_mode != fresh_plan.executable_unix_mode
        || fresh_executable.regular_file != fresh_plan.executable_regular_file
        || fresh_executable.symlink_free != fresh_plan.executable_symlink_free
    {
        return Err(LakeCommandPreflightError::new(
            LakeCommandPreflightRejectionV1::ExecutableMismatch,
            "fresh Lake executable observation differs from the reviewed plan",
        ));
    }

    Ok(LakeCommandPreflightV1 {
        schema_version: 1,
        decision: LakeCommandPreflightDecisionV1::ReadyForExplicitApproval,
        request_id: request.request_id,
        plan_report_sha256: request.plan_report_sha256,
        inventory_snapshot_sha256: request.inventory_snapshot_sha256,
        executable_sha256: fresh_executable.sha256,
        observed_at_unix_ms,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

impl LakeCommandPreflightV1 {
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        format!(
            "{{\"schemaVersion\":{},\"decision\":\"{}\",\"requestId\":\"{}\",\"planReportSha256\":\"{}\",\"inventorySnapshotSha256\":\"{}\",\"executableSha256\":\"{}\",\"observedAtUnixMs\":{},\"executionAuthority\":\"withheld\"}}",
            self.schema_version,
            decision_name(self.decision),
            self.request_id,
            self.plan_report_sha256,
            self.inventory_snapshot_sha256,
            self.executable_sha256,
            self.observed_at_unix_ms,
        )
    }
}

fn decision_name(value: LakeCommandPreflightDecisionV1) -> &'static str {
    match value {
        LakeCommandPreflightDecisionV1::ReadyForExplicitApproval => "ready-for-explicit-approval",
    }
}

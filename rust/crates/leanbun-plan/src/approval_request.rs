use super::{LakeCommandPlanV1, PlanExecutionAuthorityV1, lake_command_plan_report_v1};
use crate::plan_report::{push_json_array, push_json_string};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher, project_id};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_APPROVAL_WINDOW_MS: u64 = 15 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeCommandApprovalStateV1 {
    Pending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandApprovalRequestV1 {
    pub schema_version: u8,
    pub request_type: String,
    pub request_id: Sha256,
    pub approval_state: LakeCommandApprovalStateV1,
    pub plan_report_sha256: Sha256,
    pub inventory_snapshot_sha256: Sha256,
    pub project_id: String,
    pub project_path: String,
    pub packages: Vec<String>,
    pub lake_version: String,
    pub network_required: bool,
    pub nonce: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub execution_authority: PlanExecutionAuthorityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandApprovalRequestError {
    pub message: String,
}

impl LakeCommandApprovalRequestError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LakeCommandApprovalRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LakeCommandApprovalRequestError {}

pub fn lake_command_approval_request_v1(
    plan: &LakeCommandPlanV1,
    nonce: &str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<LakeCommandApprovalRequestV1, LakeCommandApprovalRequestError> {
    validate_approval_window(nonce, issued_at_unix_ms, expires_at_unix_ms)?;
    let report = lake_command_plan_report_v1(plan)
        .map_err(|error| LakeCommandApprovalRequestError::new(error.message))?;
    let report_json = report.to_canonical_json();
    let mut report_hasher = Sha256Hasher::new();
    report_hasher.update(report_json.as_bytes());
    let plan_report_sha256 = report_hasher.finalize();
    let project_id = project_id(&report.cwd).to_string();
    let packages = report.arguments.get(2..).unwrap_or_default().to_vec();
    let request_id = approval_request_id_v1(
        plan_report_sha256,
        &project_id,
        nonce,
        issued_at_unix_ms,
        expires_at_unix_ms,
    );

    Ok(LakeCommandApprovalRequestV1 {
        schema_version: 1,
        request_type: "lake-command-approval-request".to_owned(),
        request_id,
        approval_state: LakeCommandApprovalStateV1::Pending,
        plan_report_sha256,
        inventory_snapshot_sha256: plan.inventory_snapshot_sha256,
        project_id,
        project_path: report.cwd,
        packages,
        lake_version: report.lake_version,
        network_required: report.network_policy == "required",
        nonce: nonce.to_owned(),
        issued_at_unix_ms,
        expires_at_unix_ms,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

pub fn verify_lake_command_approval_request_v1(
    request: &LakeCommandApprovalRequestV1,
    plan: &LakeCommandPlanV1,
    observed_now_unix_ms: u64,
) -> Result<(), LakeCommandApprovalRequestError> {
    if observed_now_unix_ms < request.issued_at_unix_ms
        || observed_now_unix_ms >= request.expires_at_unix_ms
    {
        return Err(LakeCommandApprovalRequestError::new(
            "approval request is not currently valid",
        ));
    }
    let expected = lake_command_approval_request_v1(
        plan,
        &request.nonce,
        request.issued_at_unix_ms,
        request.expires_at_unix_ms,
    )?;
    if *request != expected {
        return Err(LakeCommandApprovalRequestError::new(
            "approval request does not exactly match the current plan",
        ));
    }
    Ok(())
}

impl LakeCommandApprovalRequestV1 {
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut output = String::from("{\"schemaVersion\":");
        output.push_str(&self.schema_version.to_string());
        output.push_str(",\"requestType\":");
        push_json_string(&mut output, &self.request_type);
        output.push_str(",\"requestId\":");
        push_json_string(&mut output, &self.request_id.to_string());
        output.push_str(",\"approvalState\":");
        push_json_string(&mut output, approval_state_name(self.approval_state));
        output.push_str(",\"planReportSha256\":");
        push_json_string(&mut output, &self.plan_report_sha256.to_string());
        output.push_str(",\"inventorySnapshotSha256\":");
        push_json_string(&mut output, &self.inventory_snapshot_sha256.to_string());
        output.push_str(",\"projectId\":");
        push_json_string(&mut output, &self.project_id);
        output.push_str(",\"projectPath\":");
        push_json_string(&mut output, &self.project_path);
        output.push_str(",\"packages\":");
        push_json_array(&mut output, &self.packages);
        output.push_str(",\"lakeVersion\":");
        push_json_string(&mut output, &self.lake_version);
        output.push_str(",\"networkRequired\":");
        output.push_str(if self.network_required {
            "true"
        } else {
            "false"
        });
        output.push_str(",\"nonce\":");
        push_json_string(&mut output, &self.nonce);
        output.push_str(",\"issuedAtUnixMs\":");
        output.push_str(&self.issued_at_unix_ms.to_string());
        output.push_str(",\"expiresAtUnixMs\":");
        output.push_str(&self.expires_at_unix_ms.to_string());
        output.push_str(",\"executionAuthority\":");
        push_json_string(&mut output, "withheld");
        output.push('}');
        output
    }
}

pub(crate) fn approval_request_id_v1(
    plan_report_sha256: Sha256,
    project_id: &str,
    nonce: &str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Sha256 {
    let mut identity = String::from(
        "{\"schema\":\"leanbun-lake-command-approval-request-v1\",\"planReportSha256\":",
    );
    push_json_string(&mut identity, &plan_report_sha256.to_string());
    identity.push_str(",\"projectId\":");
    push_json_string(&mut identity, project_id);
    identity.push_str(",\"nonce\":");
    push_json_string(&mut identity, nonce);
    identity.push_str(",\"issuedAtUnixMs\":");
    identity.push_str(&issued_at_unix_ms.to_string());
    identity.push_str(",\"expiresAtUnixMs\":");
    identity.push_str(&expires_at_unix_ms.to_string());
    identity.push('}');
    let mut hasher = Sha256Hasher::new();
    hasher.update(identity.as_bytes());
    hasher.finalize()
}

fn validate_approval_window(
    nonce: &str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<(), LakeCommandApprovalRequestError> {
    if !valid_nonce(nonce) {
        return Err(LakeCommandApprovalRequestError::new(
            "approval nonce must be a lowercase RFC 4122 UUID version 4",
        ));
    }
    if issued_at_unix_ms == 0
        || issued_at_unix_ms > MAX_SAFE_INTEGER
        || expires_at_unix_ms > MAX_SAFE_INTEGER
        || expires_at_unix_ms <= issued_at_unix_ms
        || expires_at_unix_ms - issued_at_unix_ms > MAX_APPROVAL_WINDOW_MS
    {
        return Err(LakeCommandApprovalRequestError::new(
            "approval window must be positive, JavaScript-safe, ordered, and at most 15 minutes",
        ));
    }
    Ok(())
}

fn valid_nonce(value: &str) -> bool {
    let bytes = value.as_bytes();
    let hyphens = [8, 13, 18, 23];
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if hyphens.contains(&index) {
                *byte == b'-'
            } else {
                matches!(byte, b'0'..=b'9' | b'a'..=b'f')
            }
        })
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

fn approval_state_name(value: LakeCommandApprovalStateV1) -> &'static str {
    match value {
        LakeCommandApprovalStateV1::Pending => "pending",
    }
}

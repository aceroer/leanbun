use super::{
    LakeCommandApprovalRequestV1, LakeCommandApprovalStateV1, LakeCommandPreflightDecisionV1,
    LakeCommandPreflightV1, PlanExecutionAuthorityV1,
};
use crate::plan_report::{push_json_array, push_json_string};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_CHALLENGE_WINDOW_MS: u64 = 60_000;

pub const TRUSTED_INGRESS_REQUIREMENTS_V1: &[&str] = &[
    "current-process-controlling-terminal",
    "stdin-and-stderr-same-terminal",
    "terminal-owned-by-effective-user",
    "current-process-in-foreground-group",
    "os-cryptographic-session-nonce",
    "exact-request-preflight-challenge",
    "atomic-single-use-consumption",
    "deadline-and-preflight-reverification",
];

pub const FORBIDDEN_APPROVAL_SOURCES_V1: &[&str] = &[
    "command-line-argument",
    "environment-variable",
    "external-json-claim",
    "ordinary-file",
    "pipe-or-redirected-stdin",
    "clipboard-only",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedApprovalIngressDecisionV1 {
    RequiresDedicatedMacOsAdapter,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedApprovalIngressContractV1 {
    pub schema_version: u8,
    pub decision: TrustedApprovalIngressDecisionV1,
    pub adapter_boundary: String,
    pub requirements: Vec<String>,
    pub forbidden_sources: Vec<String>,
    pub execution_authority: PlanExecutionAuthorityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandTrustedApprovalChallengeV1 {
    pub schema_version: u8,
    pub challenge_id: Sha256,
    pub request_id: Sha256,
    pub preflight_sha256: Sha256,
    pub session_nonce_sha256: Sha256,
    pub confirmation: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub execution_authority: PlanExecutionAuthorityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedApprovalIngressError {
    pub message: String,
}

impl fmt::Display for TrustedApprovalIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TrustedApprovalIngressError {}

#[must_use]
pub fn trusted_approval_ingress_contract_v1() -> TrustedApprovalIngressContractV1 {
    TrustedApprovalIngressContractV1 {
        schema_version: 1,
        decision: TrustedApprovalIngressDecisionV1::RequiresDedicatedMacOsAdapter,
        adapter_boundary: "leanbun-approval-macos".to_owned(),
        requirements: TRUSTED_INGRESS_REQUIREMENTS_V1
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        forbidden_sources: FORBIDDEN_APPROVAL_SOURCES_V1
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    }
}

pub fn lake_command_trusted_approval_challenge_v1(
    request: &LakeCommandApprovalRequestV1,
    preflight: &LakeCommandPreflightV1,
    session_nonce_sha256: Sha256,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<LakeCommandTrustedApprovalChallengeV1, TrustedApprovalIngressError> {
    if request.schema_version != 1
        || request.request_type != "lake-command-approval-request"
        || request.approval_state != LakeCommandApprovalStateV1::Pending
        || request.execution_authority != PlanExecutionAuthorityV1::Withheld
        || preflight.schema_version != 1
        || preflight.decision != LakeCommandPreflightDecisionV1::ReadyForExplicitApproval
        || preflight.execution_authority != PlanExecutionAuthorityV1::Withheld
        || request.request_id != preflight.request_id
    {
        return Err(invalid(
            "trusted approval challenge requires the exact pending request and preflight",
        ));
    }
    if session_nonce_sha256
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(invalid(
            "trusted approval session nonce digest must not be all zero",
        ));
    }
    if issued_at_unix_ms == 0
        || issued_at_unix_ms > MAX_SAFE_INTEGER
        || expires_at_unix_ms > MAX_SAFE_INTEGER
        || issued_at_unix_ms < request.issued_at_unix_ms
        || issued_at_unix_ms < preflight.observed_at_unix_ms
        || expires_at_unix_ms <= issued_at_unix_ms
        || expires_at_unix_ms > request.expires_at_unix_ms
        || expires_at_unix_ms - issued_at_unix_ms > MAX_CHALLENGE_WINDOW_MS
    {
        return Err(invalid(
            "trusted approval challenge must be fresh, ordered, and at most sixty seconds",
        ));
    }

    let mut preflight_hasher = Sha256Hasher::new();
    preflight_hasher.update(preflight.to_canonical_json().as_bytes());
    let preflight_sha256 = preflight_hasher.finalize();
    let challenge_id = challenge_id_v1(
        request.request_id,
        preflight_sha256,
        session_nonce_sha256,
        issued_at_unix_ms,
        expires_at_unix_ms,
    );
    let confirmation = format!(
        "approve:{}:{}:{}",
        request.request_id, preflight_sha256, challenge_id
    );

    Ok(LakeCommandTrustedApprovalChallengeV1 {
        schema_version: 1,
        challenge_id,
        request_id: request.request_id,
        preflight_sha256,
        session_nonce_sha256,
        confirmation,
        issued_at_unix_ms,
        expires_at_unix_ms,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

impl TrustedApprovalIngressContractV1 {
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut output = String::from("{\"schemaVersion\":");
        output.push_str(&self.schema_version.to_string());
        output.push_str(",\"decision\":\"requires-dedicated-macos-adapter\",\"adapterBoundary\":");
        push_json_string(&mut output, &self.adapter_boundary);
        output.push_str(",\"requirements\":");
        push_json_array(&mut output, &self.requirements);
        output.push_str(",\"forbiddenSources\":");
        push_json_array(&mut output, &self.forbidden_sources);
        output.push_str(",\"executionAuthority\":\"withheld\"}");
        output
    }
}

impl LakeCommandTrustedApprovalChallengeV1 {
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        format!(
            "{{\"schemaVersion\":{},\"challengeId\":\"{}\",\"requestId\":\"{}\",\"preflightSha256\":\"{}\",\"sessionNonceSha256\":\"{}\",\"confirmation\":\"{}\",\"issuedAtUnixMs\":{},\"expiresAtUnixMs\":{},\"executionAuthority\":\"withheld\"}}",
            self.schema_version,
            self.challenge_id,
            self.request_id,
            self.preflight_sha256,
            self.session_nonce_sha256,
            self.confirmation,
            self.issued_at_unix_ms,
            self.expires_at_unix_ms,
        )
    }
}

fn challenge_id_v1(
    request_id: Sha256,
    preflight_sha256: Sha256,
    session_nonce_sha256: Sha256,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Sha256 {
    let identity = format!(
        "{{\"schema\":\"leanbun-trusted-approval-challenge-v1\",\"requestId\":\"{request_id}\",\"preflightSha256\":\"{preflight_sha256}\",\"sessionNonceSha256\":\"{session_nonce_sha256}\",\"issuedAtUnixMs\":{issued_at_unix_ms},\"expiresAtUnixMs\":{expires_at_unix_ms}}}"
    );
    let mut hasher = Sha256Hasher::new();
    hasher.update(identity.as_bytes());
    hasher.finalize()
}

fn invalid(message: impl Into<String>) -> TrustedApprovalIngressError {
    TrustedApprovalIngressError {
        message: message.into(),
    }
}

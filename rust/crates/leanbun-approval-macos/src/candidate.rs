use crate::{
    LakeCommandApprovalConsumptionRecordV1, LakeCommandTrustedApprovalProofV1,
    MacOsApprovalProofError, TrustedFreshLakeUpdatePlanV1, proof::reverify_fresh_bundle_v1,
};
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_plan::{LakeCommandApprovalRequestV1, LakeCommandPlanV1, PlanExecutionAuthorityV1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeExecutionCandidateDecisionV1 {
    ExactPlanAndProofSealed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TrustedLakeExecutionCandidateV1 {
    pub(crate) schema_version: u8,
    pub(crate) decision: TrustedLakeExecutionCandidateDecisionV1,
    pub(crate) plan: LakeCommandPlanV1,
    pub(crate) proof: LakeCommandTrustedApprovalProofV1,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) candidate_sha256: Sha256,
    pub(crate) execution_authority: PlanExecutionAuthorityV1,
}

impl TrustedLakeExecutionCandidateV1 {
    #[must_use]
    pub fn decision(&self) -> TrustedLakeExecutionCandidateDecisionV1 {
        self.decision
    }

    #[must_use]
    pub fn plan(&self) -> &LakeCommandPlanV1 {
        &self.plan
    }

    #[must_use]
    pub fn proof(&self) -> &LakeCommandTrustedApprovalProofV1 {
        &self.proof
    }

    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub fn candidate_sha256(&self) -> Sha256 {
        self.candidate_sha256
    }

    #[must_use]
    pub fn execution_authority(&self) -> PlanExecutionAuthorityV1 {
        self.execution_authority
    }
}

pub fn seal_trusted_lake_execution_candidate_v1(
    consumption: LakeCommandApprovalConsumptionRecordV1,
    request: &LakeCommandApprovalRequestV1,
    fresh: TrustedFreshLakeUpdatePlanV1,
) -> Result<TrustedLakeExecutionCandidateV1, MacOsApprovalProofError> {
    let expires_at_unix_ms = consumption.challenge_expires_at_unix_ms;
    let (plan, proof) = reverify_fresh_bundle_v1(consumption, request, fresh)?;
    let candidate_sha256 = candidate_sha256(&proof, expires_at_unix_ms);
    Ok(TrustedLakeExecutionCandidateV1 {
        schema_version: 1,
        decision: TrustedLakeExecutionCandidateDecisionV1::ExactPlanAndProofSealed,
        plan,
        proof,
        expires_at_unix_ms,
        candidate_sha256,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

pub(crate) fn candidate_sha256(
    proof: &LakeCommandTrustedApprovalProofV1,
    expires_at_unix_ms: u64,
) -> Sha256 {
    let identity = format!(
        "{{\"schema\":\"leanbun-lake-execution-candidate-v1\",\"requestId\":\"{}\",\"proofSha256\":\"{}\",\"planReportSha256\":\"{}\",\"inventorySnapshotSha256\":\"{}\",\"executableSha256\":\"{}\",\"expiresAtUnixMs\":{},\"executionAuthority\":\"withheld\"}}",
        proof.request_id,
        proof.proof_sha256,
        proof.plan_report_sha256,
        proof.inventory_snapshot_sha256,
        proof.executable_sha256,
        expires_at_unix_ms,
    );
    let mut hasher = Sha256Hasher::new();
    hasher.update(identity.as_bytes());
    hasher.finalize()
}

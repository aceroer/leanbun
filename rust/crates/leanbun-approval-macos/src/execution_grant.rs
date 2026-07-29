use crate::{
    LakeCommandTrustedApprovalProofDecisionV1, TrustedLakeExecutionCandidateDecisionV1,
    TrustedLakeExecutionCandidateV1, candidate::candidate_sha256,
};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_plan::{LakeCommandPlanV1, PlanExecutionAuthorityV1, lake_command_plan_report_v1};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeExecutionGrantDecisionV1 {
    GrantedOnce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeExecutionAuthorityV1 {
    GrantedOnce,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TrustedLakeExecutionGrantV1 {
    pub(crate) schema_version: u8,
    pub(crate) decision: TrustedLakeExecutionGrantDecisionV1,
    pub(crate) candidate: TrustedLakeExecutionCandidateV1,
    pub(crate) granted_at_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) grant_sha256: Sha256,
    pub(crate) execution_authority: TrustedLakeExecutionAuthorityV1,
}

impl TrustedLakeExecutionGrantV1 {
    #[must_use]
    pub fn decision(&self) -> TrustedLakeExecutionGrantDecisionV1 {
        self.decision
    }

    #[must_use]
    pub fn plan(&self) -> &LakeCommandPlanV1 {
        &self.candidate.plan
    }

    #[must_use]
    pub fn candidate_sha256(&self) -> Sha256 {
        self.candidate.candidate_sha256
    }

    #[must_use]
    pub fn proof_sha256(&self) -> Sha256 {
        self.candidate.proof.proof_sha256
    }

    #[must_use]
    pub fn granted_at_unix_ms(&self) -> u64 {
        self.granted_at_unix_ms
    }

    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub fn grant_sha256(&self) -> Sha256 {
        self.grant_sha256
    }

    #[must_use]
    pub fn execution_authority(&self) -> TrustedLakeExecutionAuthorityV1 {
        self.execution_authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeExecutionGrantRejectionV1 {
    CandidateInvalid,
    ClockInvalid,
    CandidateExpired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedLakeExecutionGrantError {
    pub rejection: TrustedLakeExecutionGrantRejectionV1,
    pub message: String,
}

impl fmt::Display for TrustedLakeExecutionGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TrustedLakeExecutionGrantError {}

pub fn grant_trusted_lake_execution_once_v1(
    candidate: TrustedLakeExecutionCandidateV1,
) -> Result<TrustedLakeExecutionGrantV1, TrustedLakeExecutionGrantError> {
    grant_at_v1(candidate, current_unix_ms()?)
}

pub(crate) fn grant_at_v1(
    candidate: TrustedLakeExecutionCandidateV1,
    granted_at_unix_ms: u64,
) -> Result<TrustedLakeExecutionGrantV1, TrustedLakeExecutionGrantError> {
    let plan_report = lake_command_plan_report_v1(&candidate.plan).map_err(|error| {
        grant_error(
            TrustedLakeExecutionGrantRejectionV1::CandidateInvalid,
            format!("candidate plan contract is invalid: {}", error.message),
        )
    })?;
    let mut plan_report_hasher = Sha256Hasher::new();
    plan_report_hasher.update(plan_report.to_canonical_json().as_bytes());
    let plan_report_sha256 = plan_report_hasher.finalize();
    if candidate.schema_version != 1
        || candidate.decision != TrustedLakeExecutionCandidateDecisionV1::ExactPlanAndProofSealed
        || candidate.execution_authority != PlanExecutionAuthorityV1::Withheld
        || candidate.plan.execution_authority != PlanExecutionAuthorityV1::Withheld
        || candidate.proof.decision
            != LakeCommandTrustedApprovalProofDecisionV1::FreshFactsReverified
        || candidate.proof.execution_authority != PlanExecutionAuthorityV1::Withheld
        || candidate.proof.plan_report_sha256 != plan_report_sha256
        || candidate.proof.inventory_snapshot_sha256 != candidate.plan.inventory_snapshot_sha256
        || candidate.proof.executable_sha256 != candidate.plan.executable_sha256
        || candidate.candidate_sha256
            != candidate_sha256(&candidate.proof, candidate.expires_at_unix_ms)
        || candidate.expires_at_unix_ms <= candidate.proof.verified_at_unix_ms
    {
        return Err(grant_error(
            TrustedLakeExecutionGrantRejectionV1::CandidateInvalid,
            "trusted execution grant requires one intact sealed candidate",
        ));
    }
    if granted_at_unix_ms < candidate.proof.verified_at_unix_ms {
        return Err(grant_error(
            TrustedLakeExecutionGrantRejectionV1::ClockInvalid,
            "execution grant time is before the candidate proof verification time",
        ));
    }
    if granted_at_unix_ms >= candidate.expires_at_unix_ms {
        return Err(grant_error(
            TrustedLakeExecutionGrantRejectionV1::CandidateExpired,
            "execution candidate has expired",
        ));
    }

    let expires_at_unix_ms = candidate.expires_at_unix_ms;
    let grant_sha256 = grant_sha256(&candidate, granted_at_unix_ms);
    Ok(TrustedLakeExecutionGrantV1 {
        schema_version: 1,
        decision: TrustedLakeExecutionGrantDecisionV1::GrantedOnce,
        candidate,
        granted_at_unix_ms,
        expires_at_unix_ms,
        grant_sha256,
        execution_authority: TrustedLakeExecutionAuthorityV1::GrantedOnce,
    })
}

pub(crate) fn grant_sha256(
    candidate: &TrustedLakeExecutionCandidateV1,
    granted_at_unix_ms: u64,
) -> Sha256 {
    let identity = format!(
        "{{\"schema\":\"leanbun-trusted-lake-execution-grant-v1\",\"candidateSha256\":\"{}\",\"proofSha256\":\"{}\",\"planReportSha256\":\"{}\",\"grantedAtUnixMs\":{},\"expiresAtUnixMs\":{},\"executionAuthority\":\"granted-once\"}}",
        candidate.candidate_sha256,
        candidate.proof.proof_sha256,
        candidate.proof.plan_report_sha256,
        granted_at_unix_ms,
        candidate.expires_at_unix_ms,
    );
    let mut hasher = Sha256Hasher::new();
    hasher.update(identity.as_bytes());
    hasher.finalize()
}

fn current_unix_ms() -> Result<u64, TrustedLakeExecutionGrantError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        grant_error(
            TrustedLakeExecutionGrantRejectionV1::ClockInvalid,
            "system clock is before Unix epoch",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        grant_error(
            TrustedLakeExecutionGrantRejectionV1::ClockInvalid,
            "system clock is out of range",
        )
    })
}

fn grant_error(
    rejection: TrustedLakeExecutionGrantRejectionV1,
    message: impl Into<String>,
) -> TrustedLakeExecutionGrantError {
    TrustedLakeExecutionGrantError {
        rejection,
        message: message.into(),
    }
}

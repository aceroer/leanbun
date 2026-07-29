use super::{
    LakeCommandApprovalRequestV1, LakeCommandPreflightDecisionV1, LakeCommandPreflightV1,
    PlanExecutionAuthorityV1,
};
use crate::plan_report::push_json_string;
use core::fmt;
use leanbun_codec::{StrictJson, parse_strict_json};
use leanbun_core::{Sha256, Sha256Hasher};
use std::collections::BTreeMap;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_GRANT_WINDOW_MS: u64 = 5 * 60 * 1_000;
const ROOT_FIELDS: &[&str] = &[
    "approvalMethod",
    "confirmation",
    "expiresAtUnixMs",
    "grantId",
    "grantType",
    "grantedAtUnixMs",
    "preflightSha256",
    "principal",
    "requestId",
    "requestedAuthority",
    "schemaVersion",
    "scope",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandApprovalGrantV1 {
    pub grant_id: Sha256,
    pub request_id: Sha256,
    pub preflight_sha256: Sha256,
    pub principal: String,
    pub granted_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeCommandGrantClaimDecisionV1 {
    StructurallyValidExternalClaim,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandGrantClaimVerificationV1 {
    pub schema_version: u8,
    pub decision: LakeCommandGrantClaimDecisionV1,
    pub grant_id: Sha256,
    pub request_id: Sha256,
    pub preflight_sha256: Sha256,
    pub principal: String,
    pub execution_authority: PlanExecutionAuthorityV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeCommandApprovalGrantError {
    pub message: String,
}

impl LakeCommandApprovalGrantError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LakeCommandApprovalGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LakeCommandApprovalGrantError {}

pub fn parse_lake_command_approval_grant_v1(
    text: &str,
) -> Result<LakeCommandApprovalGrantV1, LakeCommandApprovalGrantError> {
    let value = parse_strict_json(text)
        .map_err(|error| LakeCommandApprovalGrantError::new(error.message))?;
    decode_lake_command_approval_grant_v1(&value)
}

pub fn decode_lake_command_approval_grant_v1(
    value: &StrictJson,
) -> Result<LakeCommandApprovalGrantV1, LakeCommandApprovalGrantError> {
    let root = match value {
        StrictJson::Object(root) => root,
        _ => return Err(invalid("approval grant root must be an object")),
    };
    if root.len() != ROOT_FIELDS.len()
        || root
            .keys()
            .any(|field| !ROOT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid("approval grant fields are not the exact v1 set"));
    }
    if required_integer(root, "schemaVersion")? != 1
        || required_string(root, "grantType", 64)? != "lake-command-approval-grant"
        || required_string(root, "approvalMethod", 64)? != "explicit-request-id-confirmation"
        || required_string(root, "scope", 64)? != "single-lake-command"
        || required_string(root, "requestedAuthority", 64)? != "single-use-execution"
    {
        return Err(invalid("approval grant fixed fields are invalid"));
    }
    let grant_id = required_sha256(root, "grantId")?;
    let request_id = required_sha256(root, "requestId")?;
    let preflight_sha256 = required_sha256(root, "preflightSha256")?;
    let principal = required_string(root, "principal", 128)?.to_owned();
    if !valid_principal(&principal) {
        return Err(invalid("approval grant principal is invalid"));
    }
    let granted_at_unix_ms = required_integer(root, "grantedAtUnixMs")?;
    let expires_at_unix_ms = required_integer(root, "expiresAtUnixMs")?;
    if granted_at_unix_ms == 0
        || granted_at_unix_ms > MAX_SAFE_INTEGER
        || expires_at_unix_ms > MAX_SAFE_INTEGER
        || expires_at_unix_ms <= granted_at_unix_ms
        || expires_at_unix_ms - granted_at_unix_ms > MAX_GRANT_WINDOW_MS
    {
        return Err(invalid("approval grant time window is invalid"));
    }
    let expected_confirmation = confirmation(request_id, preflight_sha256);
    if required_string(root, "confirmation", 256)? != expected_confirmation {
        return Err(invalid(
            "approval grant confirmation does not bind request and preflight",
        ));
    }
    let expected_grant_id = grant_id_v1(
        request_id,
        preflight_sha256,
        &principal,
        &expected_confirmation,
        granted_at_unix_ms,
        expires_at_unix_ms,
    );
    if grant_id != expected_grant_id {
        return Err(invalid(
            "approval grant id does not match canonical identity",
        ));
    }
    Ok(LakeCommandApprovalGrantV1 {
        grant_id,
        request_id,
        preflight_sha256,
        principal,
        granted_at_unix_ms,
        expires_at_unix_ms,
    })
}

pub fn verify_lake_command_approval_grant_v1(
    grant: &LakeCommandApprovalGrantV1,
    preflight: &LakeCommandPreflightV1,
    request: &LakeCommandApprovalRequestV1,
    observed_now_unix_ms: u64,
) -> Result<LakeCommandGrantClaimVerificationV1, LakeCommandApprovalGrantError> {
    if preflight.decision != LakeCommandPreflightDecisionV1::ReadyForExplicitApproval
        || preflight.execution_authority != PlanExecutionAuthorityV1::Withheld
        || request.execution_authority != PlanExecutionAuthorityV1::Withheld
        || grant.request_id != request.request_id
        || grant.request_id != preflight.request_id
    {
        return Err(invalid(
            "approval grant does not reference the pending request/preflight",
        ));
    }
    let mut preflight_hasher = Sha256Hasher::new();
    preflight_hasher.update(preflight.to_canonical_json().as_bytes());
    if grant.preflight_sha256 != preflight_hasher.finalize() {
        return Err(invalid("approval grant preflight digest differs"));
    }
    if grant.granted_at_unix_ms < preflight.observed_at_unix_ms
        || grant.granted_at_unix_ms < request.issued_at_unix_ms
        || grant.expires_at_unix_ms > request.expires_at_unix_ms
        || observed_now_unix_ms < grant.granted_at_unix_ms
        || observed_now_unix_ms >= grant.expires_at_unix_ms
    {
        return Err(invalid(
            "approval grant is outside request/preflight/current time bounds",
        ));
    }
    Ok(LakeCommandGrantClaimVerificationV1 {
        schema_version: 1,
        decision: LakeCommandGrantClaimDecisionV1::StructurallyValidExternalClaim,
        grant_id: grant.grant_id,
        request_id: grant.request_id,
        preflight_sha256: grant.preflight_sha256,
        principal: grant.principal.clone(),
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

fn grant_id_v1(
    request_id: Sha256,
    preflight_sha256: Sha256,
    principal: &str,
    confirmation: &str,
    granted_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Sha256 {
    let mut identity =
        String::from("{\"schema\":\"leanbun-lake-command-approval-grant-v1\",\"requestId\":");
    push_json_string(&mut identity, &request_id.to_string());
    identity.push_str(",\"preflightSha256\":");
    push_json_string(&mut identity, &preflight_sha256.to_string());
    identity.push_str(",\"principal\":");
    push_json_string(&mut identity, principal);
    identity.push_str(",\"approvalMethod\":\"explicit-request-id-confirmation\",\"confirmation\":");
    push_json_string(&mut identity, confirmation);
    identity.push_str(",\"grantedAtUnixMs\":");
    identity.push_str(&granted_at_unix_ms.to_string());
    identity.push_str(",\"expiresAtUnixMs\":");
    identity.push_str(&expires_at_unix_ms.to_string());
    identity.push_str(
        ",\"scope\":\"single-lake-command\",\"requestedAuthority\":\"single-use-execution\"}",
    );
    let mut hasher = Sha256Hasher::new();
    hasher.update(identity.as_bytes());
    hasher.finalize()
}

fn confirmation(request_id: Sha256, preflight_sha256: Sha256) -> String {
    format!("approve:{request_id}:{preflight_sha256}")
}

fn valid_principal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
}

fn required_string<'a>(
    root: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
) -> Result<&'a str, LakeCommandApprovalGrantError> {
    match root.get(field) {
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(value),
        _ => Err(invalid(format!(
            "approval grant {field} must be a bounded string"
        ))),
    }
}

fn required_integer(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
) -> Result<u64, LakeCommandApprovalGrantError> {
    match root.get(field) {
        Some(StrictJson::Number(value)) => value.as_str().parse::<u64>().map_err(|_| {
            invalid(format!(
                "approval grant {field} must be an unsigned integer"
            ))
        }),
        _ => Err(invalid(format!(
            "approval grant {field} must be an integer"
        ))),
    }
}

fn required_sha256(
    root: &BTreeMap<String, StrictJson>,
    field: &str,
) -> Result<Sha256, LakeCommandApprovalGrantError> {
    Sha256::parse(required_string(root, field, 64)?)
        .map_err(|_| invalid(format!("approval grant {field} must be lowercase SHA-256")))
}

fn invalid(message: impl Into<String>) -> LakeCommandApprovalGrantError {
    LakeCommandApprovalGrantError::new(message)
}

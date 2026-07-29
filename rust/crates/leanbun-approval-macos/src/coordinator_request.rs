use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_plan::PlanExecutionAuthorityV1;

pub const MACOS_COORDINATOR_AUTHORIZATION_RIGHT_V1: &str =
    "com.leanbun.execute-reserved-lake-command";
const MAX_REQUEST_LIFETIME_MS: u64 = 60_000;
const MAX_SIGNING_IDENTIFIER_BYTES: usize = 128;
const TEAM_IDENTIFIER_BYTES: usize = 10;
const MAX_SUPPLEMENTARY_GROUPS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsCoordinatorPeerIdentityClaimV1 {
    signing_identifier: String,
    team_identifier: String,
    code_requirement_sha256: Sha256,
    effective_uid: u32,
    audit_session_id: u32,
}

impl MacOsCoordinatorPeerIdentityClaimV1 {
    #[must_use]
    pub fn signing_identifier(&self) -> &str {
        &self.signing_identifier
    }

    #[must_use]
    pub fn team_identifier(&self) -> &str {
        &self.team_identifier
    }

    #[must_use]
    pub const fn code_requirement_sha256(&self) -> Sha256 {
        self.code_requirement_sha256
    }

    #[must_use]
    pub const fn effective_uid(&self) -> u32 {
        self.effective_uid
    }

    #[must_use]
    pub const fn audit_session_id(&self) -> u32 {
        self.audit_session_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsCoordinatorThreatPrincipalV1 {
    uid: u32,
    primary_gid: u32,
    supplementary_groups: Vec<u32>,
}

impl MacOsCoordinatorThreatPrincipalV1 {
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    #[must_use]
    pub const fn primary_gid(&self) -> u32 {
        self.primary_gid
    }

    #[must_use]
    pub fn supplementary_groups(&self) -> &[u32] {
        &self.supplementary_groups
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsCoordinatorLineageReferenceV1 {
    pub reservation_sha256: Sha256,
    pub intent_sha256: Sha256,
    pub grant_sha256: Sha256,
    pub candidate_sha256: Sha256,
    pub proof_sha256: Sha256,
    pub executable_sha256: Sha256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsCoordinatorOperationV1 {
    ExecuteReservedLakeCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsCoordinatorRequestDecisionV1 {
    PendingCoordinatorVerification,
}

pub struct MacOsCoordinatorRequestV1 {
    schema_version: u8,
    operation: MacOsCoordinatorOperationV1,
    peer: MacOsCoordinatorPeerIdentityClaimV1,
    threat_principal: MacOsCoordinatorThreatPrincipalV1,
    authorization_right: &'static str,
    lineage: MacOsCoordinatorLineageReferenceV1,
    nonce_sha256: Sha256,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    request_sha256: Sha256,
    decision: MacOsCoordinatorRequestDecisionV1,
    execution_authority: PlanExecutionAuthorityV1,
}

impl MacOsCoordinatorRequestV1 {
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        self.schema_version
    }

    #[must_use]
    pub const fn operation(&self) -> MacOsCoordinatorOperationV1 {
        self.operation
    }

    #[must_use]
    pub fn peer(&self) -> &MacOsCoordinatorPeerIdentityClaimV1 {
        &self.peer
    }

    #[must_use]
    pub fn threat_principal(&self) -> &MacOsCoordinatorThreatPrincipalV1 {
        &self.threat_principal
    }

    #[must_use]
    pub const fn authorization_right(&self) -> &'static str {
        self.authorization_right
    }

    #[must_use]
    pub const fn lineage(&self) -> MacOsCoordinatorLineageReferenceV1 {
        self.lineage
    }

    #[must_use]
    pub const fn nonce_sha256(&self) -> Sha256 {
        self.nonce_sha256
    }

    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub const fn request_sha256(&self) -> Sha256 {
        self.request_sha256
    }

    #[must_use]
    pub const fn decision(&self) -> MacOsCoordinatorRequestDecisionV1 {
        self.decision
    }

    #[must_use]
    pub const fn execution_authority(&self) -> PlanExecutionAuthorityV1 {
        self.execution_authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsCoordinatorRequestRejectionV1 {
    InvalidPeerIdentity,
    InvalidThreatPrincipal,
    InvalidSupplementaryGroups,
    PeerPrincipalMismatch,
    InvalidLineage,
    InvalidNonce,
    InvalidTimeWindow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsCoordinatorRequestError {
    pub rejection: MacOsCoordinatorRequestRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsCoordinatorRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsCoordinatorRequestError {}

pub fn macos_coordinator_peer_identity_claim_v1(
    signing_identifier: &str,
    team_identifier: &str,
    code_requirement_sha256: Sha256,
    effective_uid: u32,
    audit_session_id: u32,
) -> Result<MacOsCoordinatorPeerIdentityClaimV1, MacOsCoordinatorRequestError> {
    if !valid_signing_identifier(signing_identifier)
        || !valid_team_identifier(team_identifier)
        || is_zero_sha256(code_requirement_sha256)
        || effective_uid == 0
    {
        return Err(request_error(
            MacOsCoordinatorRequestRejectionV1::InvalidPeerIdentity,
            "coordinator peer claim requires bounded signing identity, code requirement, and non-root effective UID",
        ));
    }
    Ok(MacOsCoordinatorPeerIdentityClaimV1 {
        signing_identifier: signing_identifier.to_owned(),
        team_identifier: team_identifier.to_owned(),
        code_requirement_sha256,
        effective_uid,
        audit_session_id,
    })
}

pub fn macos_coordinator_threat_principal_v1(
    uid: u32,
    primary_gid: u32,
    supplementary_groups: Vec<u32>,
) -> Result<MacOsCoordinatorThreatPrincipalV1, MacOsCoordinatorRequestError> {
    if uid == 0 {
        return Err(request_error(
            MacOsCoordinatorRequestRejectionV1::InvalidThreatPrincipal,
            "coordinator threat principal must be an explicit non-root UID",
        ));
    }
    if supplementary_groups.len() > MAX_SUPPLEMENTARY_GROUPS
        || !supplementary_groups
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || supplementary_groups.contains(&primary_gid)
    {
        return Err(request_error(
            MacOsCoordinatorRequestRejectionV1::InvalidSupplementaryGroups,
            "supplementary groups must be bounded, strictly sorted, unique, and exclude the primary GID",
        ));
    }
    Ok(MacOsCoordinatorThreatPrincipalV1 {
        uid,
        primary_gid,
        supplementary_groups,
    })
}

pub fn prepare_macos_coordinator_request_v1(
    peer: MacOsCoordinatorPeerIdentityClaimV1,
    threat_principal: MacOsCoordinatorThreatPrincipalV1,
    lineage: MacOsCoordinatorLineageReferenceV1,
    nonce_sha256: Sha256,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<MacOsCoordinatorRequestV1, MacOsCoordinatorRequestError> {
    if peer.effective_uid != threat_principal.uid {
        return Err(request_error(
            MacOsCoordinatorRequestRejectionV1::PeerPrincipalMismatch,
            "authenticated peer effective UID must equal the explicit threat principal UID",
        ));
    }
    if lineage_digests(lineage)
        .iter()
        .any(|digest| is_zero_sha256(*digest))
    {
        return Err(request_error(
            MacOsCoordinatorRequestRejectionV1::InvalidLineage,
            "coordinator request requires every M19 lineage digest",
        ));
    }
    if is_zero_sha256(nonce_sha256) {
        return Err(request_error(
            MacOsCoordinatorRequestRejectionV1::InvalidNonce,
            "coordinator request nonce digest must not be the zero sentinel",
        ));
    }
    let lifetime = expires_at_unix_ms.checked_sub(issued_at_unix_ms);
    if !matches!(lifetime, Some(1..=MAX_REQUEST_LIFETIME_MS)) {
        return Err(request_error(
            MacOsCoordinatorRequestRejectionV1::InvalidTimeWindow,
            "coordinator request must have a positive lifetime of at most 60 seconds",
        ));
    }
    let request_sha256 = coordinator_request_sha256(
        &peer,
        &threat_principal,
        lineage,
        nonce_sha256,
        issued_at_unix_ms,
        expires_at_unix_ms,
    );
    Ok(MacOsCoordinatorRequestV1 {
        schema_version: 1,
        operation: MacOsCoordinatorOperationV1::ExecuteReservedLakeCommand,
        peer,
        threat_principal,
        authorization_right: MACOS_COORDINATOR_AUTHORIZATION_RIGHT_V1,
        lineage,
        nonce_sha256,
        issued_at_unix_ms,
        expires_at_unix_ms,
        request_sha256,
        decision: MacOsCoordinatorRequestDecisionV1::PendingCoordinatorVerification,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    })
}

fn coordinator_request_sha256(
    peer: &MacOsCoordinatorPeerIdentityClaimV1,
    threat: &MacOsCoordinatorThreatPrincipalV1,
    lineage: MacOsCoordinatorLineageReferenceV1,
    nonce_sha256: Sha256,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Sha256 {
    let mut bytes = b"leanbun-macos-coordinator-request-v1\0".to_vec();
    identity_field(&mut bytes, "operation", b"execute-reserved-lake-command");
    identity_field(
        &mut bytes,
        "authorizationRight",
        MACOS_COORDINATOR_AUTHORIZATION_RIGHT_V1.as_bytes(),
    );
    identity_field(
        &mut bytes,
        "peerSigningIdentifier",
        peer.signing_identifier.as_bytes(),
    );
    identity_field(
        &mut bytes,
        "peerTeamIdentifier",
        peer.team_identifier.as_bytes(),
    );
    identity_field(
        &mut bytes,
        "peerCodeRequirementSha256",
        peer.code_requirement_sha256.as_bytes(),
    );
    identity_field(
        &mut bytes,
        "peerEffectiveUid",
        &peer.effective_uid.to_be_bytes(),
    );
    identity_field(
        &mut bytes,
        "peerAuditSessionId",
        &peer.audit_session_id.to_be_bytes(),
    );
    identity_field(&mut bytes, "threatUid", &threat.uid.to_be_bytes());
    identity_field(
        &mut bytes,
        "threatPrimaryGid",
        &threat.primary_gid.to_be_bytes(),
    );
    let mut groups = Vec::with_capacity(threat.supplementary_groups.len() * 4);
    for group in &threat.supplementary_groups {
        groups.extend_from_slice(&group.to_be_bytes());
    }
    identity_field(&mut bytes, "threatSupplementaryGroups", &groups);
    for (name, digest) in [
        ("reservationSha256", lineage.reservation_sha256),
        ("intentSha256", lineage.intent_sha256),
        ("grantSha256", lineage.grant_sha256),
        ("candidateSha256", lineage.candidate_sha256),
        ("proofSha256", lineage.proof_sha256),
        ("executableSha256", lineage.executable_sha256),
        ("nonceSha256", nonce_sha256),
    ] {
        identity_field(&mut bytes, name, digest.as_bytes());
    }
    identity_field(
        &mut bytes,
        "issuedAtUnixMs",
        &issued_at_unix_ms.to_be_bytes(),
    );
    identity_field(
        &mut bytes,
        "expiresAtUnixMs",
        &expires_at_unix_ms.to_be_bytes(),
    );
    let mut hasher = Sha256Hasher::new();
    hasher.update(&bytes);
    hasher.finalize()
}

fn identity_field(output: &mut Vec<u8>, key: &str, value: &[u8]) {
    let key_length = key.len() as u64;
    let value_length = value.len() as u64;
    output.extend_from_slice(&key_length.to_be_bytes());
    output.extend_from_slice(key.as_bytes());
    output.extend_from_slice(&value_length.to_be_bytes());
    output.extend_from_slice(value);
}

fn lineage_digests(lineage: MacOsCoordinatorLineageReferenceV1) -> [Sha256; 6] {
    [
        lineage.reservation_sha256,
        lineage.intent_sha256,
        lineage.grant_sha256,
        lineage.candidate_sha256,
        lineage.proof_sha256,
        lineage.executable_sha256,
    ]
}

fn valid_signing_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_SIGNING_IDENTIFIER_BYTES
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && !value.contains("..")
}

fn valid_team_identifier(value: &str) -> bool {
    value.len() == TEAM_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_zero_sha256(value: Sha256) -> bool {
    value.as_bytes().iter().all(|byte| *byte == 0)
}

fn request_error(
    rejection: MacOsCoordinatorRequestRejectionV1,
    message: impl Into<String>,
) -> MacOsCoordinatorRequestError {
    MacOsCoordinatorRequestError {
        rejection,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256 {
        Sha256::from_bytes([byte; 32])
    }

    fn peer(uid: u32) -> Result<MacOsCoordinatorPeerIdentityClaimV1, MacOsCoordinatorRequestError> {
        macos_coordinator_peer_identity_claim_v1(
            "com.leanbun.cli",
            "AB12CD34EF",
            digest(1),
            uid,
            42,
        )
    }

    fn threat(uid: u32) -> Result<MacOsCoordinatorThreatPrincipalV1, MacOsCoordinatorRequestError> {
        macos_coordinator_threat_principal_v1(uid, 20, vec![12, 61, 80])
    }

    fn lineage() -> MacOsCoordinatorLineageReferenceV1 {
        MacOsCoordinatorLineageReferenceV1 {
            reservation_sha256: digest(2),
            intent_sha256: digest(3),
            grant_sha256: digest(4),
            candidate_sha256: digest(5),
            proof_sha256: digest(6),
            executable_sha256: digest(7),
        }
    }

    #[test]
    fn request_identity_binds_peer_principal_lineage_nonce_and_time()
    -> Result<(), MacOsCoordinatorRequestError> {
        let request = prepare_macos_coordinator_request_v1(
            peer(501)?,
            threat(501)?,
            lineage(),
            digest(8),
            1_000,
            31_000,
        )?;
        let changed = prepare_macos_coordinator_request_v1(
            peer(501)?,
            threat(501)?,
            lineage(),
            digest(9),
            1_000,
            31_000,
        )?;

        assert_eq!(request.schema_version(), 1);
        assert_eq!(
            request.operation(),
            MacOsCoordinatorOperationV1::ExecuteReservedLakeCommand
        );
        assert_eq!(
            request.authorization_right(),
            MACOS_COORDINATOR_AUTHORIZATION_RIGHT_V1
        );
        assert_eq!(
            request.decision(),
            MacOsCoordinatorRequestDecisionV1::PendingCoordinatorVerification
        );
        assert_eq!(
            request.execution_authority(),
            PlanExecutionAuthorityV1::Withheld
        );
        assert_eq!(
            request.request_sha256().to_string(),
            "ffcaf2a4cd2d90522bd1f1d357af23558ac623748917ba5d33fae8341fc318e3"
        );
        assert_ne!(request.request_sha256(), changed.request_sha256());
        Ok(())
    }

    #[test]
    fn request_rejects_principal_group_and_deadline_ambiguity()
    -> Result<(), MacOsCoordinatorRequestError> {
        let mismatch = prepare_macos_coordinator_request_v1(
            peer(501)?,
            threat(502)?,
            lineage(),
            digest(8),
            1_000,
            2_000,
        )
        .map(|_| ())
        .map_err(|error| error.rejection);
        assert_eq!(
            mismatch,
            Err(MacOsCoordinatorRequestRejectionV1::PeerPrincipalMismatch)
        );
        let groups = macos_coordinator_threat_principal_v1(501, 20, vec![80, 61])
            .map(|_| ())
            .map_err(|error| error.rejection);
        assert_eq!(
            groups,
            Err(MacOsCoordinatorRequestRejectionV1::InvalidSupplementaryGroups)
        );
        let deadline = prepare_macos_coordinator_request_v1(
            peer(501)?,
            threat(501)?,
            lineage(),
            digest(8),
            1_000,
            61_001,
        )
        .map(|_| ())
        .map_err(|error| error.rejection);
        assert_eq!(
            deadline,
            Err(MacOsCoordinatorRequestRejectionV1::InvalidTimeWindow)
        );
        Ok(())
    }

    #[test]
    fn authorization_blob_is_absent_from_the_persistent_identity_surface() {
        let request_fields = [
            "authorizationRight",
            "peerCodeRequirementSha256",
            "threatUid",
            "reservationSha256",
            "nonceSha256",
        ];
        assert!(request_fields.contains(&"authorizationRight"));
        assert!(!request_fields.contains(&"authorizationExternalForm"));
    }
}

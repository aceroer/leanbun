use crate::{
    MACOS_COORDINATOR_AUTHORIZATION_RIGHT_V1, MacOsCoordinatorLineageReferenceV1,
    MacOsCoordinatorRequestError, MacOsCoordinatorRequestV1,
    macos_coordinator_peer_identity_claim_v1, macos_coordinator_threat_principal_v1,
    prepare_macos_coordinator_request_v1,
};
use core::fmt;
use leanbun_core::Sha256;

const WIRE_MAGIC: &[u8] = b"leanbun-macos-coordinator-wire-v1\0";
const WIRE_FIELD_COUNT: u16 = 21;
const MAX_WIRE_FIELD_BYTES: usize = 256;
pub const MAX_MACOS_COORDINATOR_REQUEST_WIRE_BYTES_V1: usize = 4_096;

const FIELD_SCHEMA_VERSION: u16 = 1;
const FIELD_OPERATION: u16 = 2;
const FIELD_AUTHORIZATION_RIGHT: u16 = 3;
const FIELD_PEER_SIGNING_IDENTIFIER: u16 = 4;
const FIELD_PEER_TEAM_IDENTIFIER: u16 = 5;
const FIELD_PEER_CODE_REQUIREMENT_SHA256: u16 = 6;
const FIELD_PEER_EFFECTIVE_UID: u16 = 7;
const FIELD_PEER_AUDIT_SESSION_ID: u16 = 8;
const FIELD_THREAT_UID: u16 = 9;
const FIELD_THREAT_PRIMARY_GID: u16 = 10;
const FIELD_THREAT_SUPPLEMENTARY_GROUPS: u16 = 11;
const FIELD_RESERVATION_SHA256: u16 = 12;
const FIELD_INTENT_SHA256: u16 = 13;
const FIELD_GRANT_SHA256: u16 = 14;
const FIELD_CANDIDATE_SHA256: u16 = 15;
const FIELD_PROOF_SHA256: u16 = 16;
const FIELD_EXECUTABLE_SHA256: u16 = 17;
const FIELD_NONCE_SHA256: u16 = 18;
const FIELD_ISSUED_AT_UNIX_MS: u16 = 19;
const FIELD_EXPIRES_AT_UNIX_MS: u16 = 20;
const FIELD_REQUEST_SHA256: u16 = 21;

const OPERATION_NAME: &[u8] = b"execute-reserved-lake-command";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsCoordinatorWireRejectionV1 {
    OversizedEnvelope,
    InvalidMagic,
    InvalidFieldCount,
    NonCanonicalFieldOrder,
    OversizedField,
    TruncatedEnvelope,
    TrailingBytes,
    InvalidFieldValue,
    InvalidRequest,
    RequestIdentityMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsCoordinatorWireError {
    pub rejection: MacOsCoordinatorWireRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsCoordinatorWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsCoordinatorWireError {}

#[must_use]
pub fn encode_macos_coordinator_request_wire_v1(request: &MacOsCoordinatorRequestV1) -> Vec<u8> {
    let mut output = Vec::with_capacity(1_024);
    output.extend_from_slice(WIRE_MAGIC);
    output.extend_from_slice(&WIRE_FIELD_COUNT.to_be_bytes());
    wire_field(
        &mut output,
        FIELD_SCHEMA_VERSION,
        &[request.schema_version()],
    );
    wire_field(&mut output, FIELD_OPERATION, OPERATION_NAME);
    wire_field(
        &mut output,
        FIELD_AUTHORIZATION_RIGHT,
        request.authorization_right().as_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_PEER_SIGNING_IDENTIFIER,
        request.peer().signing_identifier().as_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_PEER_TEAM_IDENTIFIER,
        request.peer().team_identifier().as_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_PEER_CODE_REQUIREMENT_SHA256,
        request.peer().code_requirement_sha256().as_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_PEER_EFFECTIVE_UID,
        &request.peer().effective_uid().to_be_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_PEER_AUDIT_SESSION_ID,
        &request.peer().audit_session_id().to_be_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_THREAT_UID,
        &request.threat_principal().uid().to_be_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_THREAT_PRIMARY_GID,
        &request.threat_principal().primary_gid().to_be_bytes(),
    );
    let mut groups =
        Vec::with_capacity(request.threat_principal().supplementary_groups().len() * 4);
    for group in request.threat_principal().supplementary_groups() {
        groups.extend_from_slice(&group.to_be_bytes());
    }
    wire_field(&mut output, FIELD_THREAT_SUPPLEMENTARY_GROUPS, &groups);
    let lineage = request.lineage();
    for (field, digest) in [
        (FIELD_RESERVATION_SHA256, lineage.reservation_sha256),
        (FIELD_INTENT_SHA256, lineage.intent_sha256),
        (FIELD_GRANT_SHA256, lineage.grant_sha256),
        (FIELD_CANDIDATE_SHA256, lineage.candidate_sha256),
        (FIELD_PROOF_SHA256, lineage.proof_sha256),
        (FIELD_EXECUTABLE_SHA256, lineage.executable_sha256),
        (FIELD_NONCE_SHA256, request.nonce_sha256()),
    ] {
        wire_field(&mut output, field, digest.as_bytes());
    }
    wire_field(
        &mut output,
        FIELD_ISSUED_AT_UNIX_MS,
        &request.issued_at_unix_ms().to_be_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_EXPIRES_AT_UNIX_MS,
        &request.expires_at_unix_ms().to_be_bytes(),
    );
    wire_field(
        &mut output,
        FIELD_REQUEST_SHA256,
        request.request_sha256().as_bytes(),
    );
    output
}

pub fn decode_macos_coordinator_request_wire_v1(
    bytes: &[u8],
) -> Result<MacOsCoordinatorRequestV1, MacOsCoordinatorWireError> {
    if bytes.len() > MAX_MACOS_COORDINATOR_REQUEST_WIRE_BYTES_V1 {
        return Err(wire_error(
            MacOsCoordinatorWireRejectionV1::OversizedEnvelope,
            "coordinator request wire envelope exceeds 4096 bytes",
        ));
    }
    let mut cursor = WireCursor::new(bytes);
    if cursor.take(WIRE_MAGIC.len())? != WIRE_MAGIC {
        return Err(wire_error(
            MacOsCoordinatorWireRejectionV1::InvalidMagic,
            "coordinator request wire magic is invalid",
        ));
    }
    if cursor.read_u16()? != WIRE_FIELD_COUNT {
        return Err(wire_error(
            MacOsCoordinatorWireRejectionV1::InvalidFieldCount,
            "coordinator request wire must contain exactly 21 fields",
        ));
    }
    let mut fields = Vec::with_capacity(usize::from(WIRE_FIELD_COUNT));
    for expected_id in 1..=WIRE_FIELD_COUNT {
        let field_id = cursor.read_u16()?;
        if field_id != expected_id {
            return Err(wire_error(
                MacOsCoordinatorWireRejectionV1::NonCanonicalFieldOrder,
                "coordinator request fields must be unique and strictly ordered",
            ));
        }
        let field_length = usize::try_from(cursor.read_u32()?).map_err(|_| {
            wire_error(
                MacOsCoordinatorWireRejectionV1::OversizedField,
                "coordinator request field length is out of range",
            )
        })?;
        if field_length > MAX_WIRE_FIELD_BYTES {
            return Err(wire_error(
                MacOsCoordinatorWireRejectionV1::OversizedField,
                "coordinator request field exceeds 256 bytes",
            ));
        }
        fields.push(cursor.take(field_length)?);
    }
    if cursor.remaining() != 0 {
        return Err(wire_error(
            MacOsCoordinatorWireRejectionV1::TrailingBytes,
            "coordinator request wire has trailing bytes",
        ));
    }

    if fields[0] != [1] || fields[1] != OPERATION_NAME {
        return Err(invalid_field("schema version or operation is invalid"));
    }
    let authorization_right = utf8(fields[2], "authorization right")?;
    if authorization_right != MACOS_COORDINATOR_AUTHORIZATION_RIGHT_V1 {
        return Err(invalid_field("authorization right is invalid"));
    }
    let peer = macos_coordinator_peer_identity_claim_v1(
        utf8(fields[3], "peer signing identifier")?,
        utf8(fields[4], "peer team identifier")?,
        sha256_field(fields[5], "peer code requirement SHA-256")?,
        u32_field(fields[6], "peer effective UID")?,
        u32_field(fields[7], "peer audit session ID")?,
    )
    .map_err(request_invalid)?;
    let threat_uid = u32_field(fields[8], "threat UID")?;
    let threat_primary_gid = u32_field(fields[9], "threat primary GID")?;
    let supplementary_groups = group_field(fields[10])?;
    let threat =
        macos_coordinator_threat_principal_v1(threat_uid, threat_primary_gid, supplementary_groups)
            .map_err(request_invalid)?;
    let lineage = MacOsCoordinatorLineageReferenceV1 {
        reservation_sha256: sha256_field(fields[11], "reservation SHA-256")?,
        intent_sha256: sha256_field(fields[12], "intent SHA-256")?,
        grant_sha256: sha256_field(fields[13], "grant SHA-256")?,
        candidate_sha256: sha256_field(fields[14], "candidate SHA-256")?,
        proof_sha256: sha256_field(fields[15], "proof SHA-256")?,
        executable_sha256: sha256_field(fields[16], "executable SHA-256")?,
    };
    let request = prepare_macos_coordinator_request_v1(
        peer,
        threat,
        lineage,
        sha256_field(fields[17], "nonce SHA-256")?,
        u64_field(fields[18], "issued time")?,
        u64_field(fields[19], "expiry time")?,
    )
    .map_err(request_invalid)?;
    let claimed_request_sha256 = sha256_field(fields[20], "request SHA-256")?;
    if claimed_request_sha256 != request.request_sha256() {
        return Err(wire_error(
            MacOsCoordinatorWireRejectionV1::RequestIdentityMismatch,
            "coordinator request wire identity does not match decoded fields",
        ));
    }
    Ok(request)
}

fn wire_field(output: &mut Vec<u8>, field_id: u16, value: &[u8]) {
    output.extend_from_slice(&field_id.to_be_bytes());
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

struct WireCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WireCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], MacOsCoordinatorWireError> {
        let end = self.position.checked_add(length).ok_or_else(truncated)?;
        let value = self.bytes.get(self.position..end).ok_or_else(truncated)?;
        self.position = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, MacOsCoordinatorWireError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, MacOsCoordinatorWireError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}

fn utf8<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, MacOsCoordinatorWireError> {
    core::str::from_utf8(bytes).map_err(|_| invalid_field(format!("{label} is not UTF-8")))
}

fn sha256_field(bytes: &[u8], label: &str) -> Result<Sha256, MacOsCoordinatorWireError> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_field(format!("{label} must contain exactly 32 bytes")))?;
    Ok(Sha256::from_bytes(value))
}

fn u32_field(bytes: &[u8], label: &str) -> Result<u32, MacOsCoordinatorWireError> {
    let value: [u8; 4] = bytes
        .try_into()
        .map_err(|_| invalid_field(format!("{label} must contain exactly 4 bytes")))?;
    Ok(u32::from_be_bytes(value))
}

fn u64_field(bytes: &[u8], label: &str) -> Result<u64, MacOsCoordinatorWireError> {
    let value: [u8; 8] = bytes
        .try_into()
        .map_err(|_| invalid_field(format!("{label} must contain exactly 8 bytes")))?;
    Ok(u64::from_be_bytes(value))
}

fn group_field(bytes: &[u8]) -> Result<Vec<u32>, MacOsCoordinatorWireError> {
    if !bytes.len().is_multiple_of(4) {
        return Err(invalid_field(
            "supplementary group bytes must be a sequence of 32-bit GIDs",
        ));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|group| u32::from_be_bytes([group[0], group[1], group[2], group[3]]))
        .collect())
}

fn request_invalid(error: MacOsCoordinatorRequestError) -> MacOsCoordinatorWireError {
    wire_error(
        MacOsCoordinatorWireRejectionV1::InvalidRequest,
        format!("decoded coordinator request is invalid: {error}"),
    )
}

fn invalid_field(message: impl Into<String>) -> MacOsCoordinatorWireError {
    wire_error(MacOsCoordinatorWireRejectionV1::InvalidFieldValue, message)
}

fn truncated() -> MacOsCoordinatorWireError {
    wire_error(
        MacOsCoordinatorWireRejectionV1::TruncatedEnvelope,
        "coordinator request wire is truncated",
    )
}

fn wire_error(
    rejection: MacOsCoordinatorWireRejectionV1,
    message: impl Into<String>,
) -> MacOsCoordinatorWireError {
    MacOsCoordinatorWireError {
        rejection,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        macos_coordinator_peer_identity_claim_v1, macos_coordinator_threat_principal_v1,
        prepare_macos_coordinator_request_v1,
    };
    use leanbun_core::Sha256Hasher;

    fn digest(byte: u8) -> Sha256 {
        Sha256::from_bytes([byte; 32])
    }

    fn request() -> Result<MacOsCoordinatorRequestV1, Box<dyn std::error::Error>> {
        let peer = macos_coordinator_peer_identity_claim_v1(
            "com.leanbun.cli",
            "AB12CD34EF",
            digest(1),
            501,
            42,
        )?;
        let threat = macos_coordinator_threat_principal_v1(501, 20, vec![12, 61, 80])?;
        Ok(prepare_macos_coordinator_request_v1(
            peer,
            threat,
            MacOsCoordinatorLineageReferenceV1 {
                reservation_sha256: digest(2),
                intent_sha256: digest(3),
                grant_sha256: digest(4),
                candidate_sha256: digest(5),
                proof_sha256: digest(6),
                executable_sha256: digest(7),
            },
            digest(8),
            1_000,
            31_000,
        )?)
    }

    #[test]
    fn canonical_wire_round_trips_and_recomputes_request_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let wire = encode_macos_coordinator_request_wire_v1(&request);
        let decoded = decode_macos_coordinator_request_wire_v1(&wire)?;

        assert!(wire.len() < MAX_MACOS_COORDINATOR_REQUEST_WIRE_BYTES_V1);
        assert_eq!(decoded.request_sha256(), request.request_sha256());
        assert_eq!(encode_macos_coordinator_request_wire_v1(&decoded), wire);
        let mut hasher = Sha256Hasher::new();
        hasher.update(&wire);
        assert_eq!(
            hasher.finalize().to_string(),
            "a9bc33d754e8dbd2ba8f03da85756c9f0fbea445c70b1af5c9228a6cd2c1ae1f"
        );
        Ok(())
    }

    #[test]
    fn duplicate_unknown_out_of_order_and_trailing_fields_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let wire = encode_macos_coordinator_request_wire_v1(&request()?);
        let first_field = WIRE_MAGIC.len() + 2;
        let first_length = usize::try_from(u32::from_be_bytes(
            wire[first_field + 2..first_field + 6].try_into()?,
        ))?;
        let second_field = first_field + 6 + first_length;

        for replacement in [1_u16, 99_u16] {
            let mut changed = wire.clone();
            changed[second_field..second_field + 2].copy_from_slice(&replacement.to_be_bytes());
            assert_eq!(
                decode_macos_coordinator_request_wire_v1(&changed)
                    .map(|_| ())
                    .map_err(|error| error.rejection),
                Err(MacOsCoordinatorWireRejectionV1::NonCanonicalFieldOrder)
            );
        }
        let mut trailing = wire;
        trailing.push(0);
        assert_eq!(
            decode_macos_coordinator_request_wire_v1(&trailing)
                .map(|_| ())
                .map_err(|error| error.rejection),
            Err(MacOsCoordinatorWireRejectionV1::TrailingBytes)
        );
        Ok(())
    }

    #[test]
    fn truncation_oversize_and_identity_drift_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let wire = encode_macos_coordinator_request_wire_v1(&request()?);
        let mut invalid_magic = wire.clone();
        invalid_magic[0] ^= 1;
        assert_eq!(
            decode_macos_coordinator_request_wire_v1(&invalid_magic)
                .map(|_| ())
                .map_err(|error| error.rejection),
            Err(MacOsCoordinatorWireRejectionV1::InvalidMagic)
        );
        let mut invalid_count = wire.clone();
        invalid_count[WIRE_MAGIC.len()..WIRE_MAGIC.len() + 2]
            .copy_from_slice(&(WIRE_FIELD_COUNT - 1).to_be_bytes());
        assert_eq!(
            decode_macos_coordinator_request_wire_v1(&invalid_count)
                .map(|_| ())
                .map_err(|error| error.rejection),
            Err(MacOsCoordinatorWireRejectionV1::InvalidFieldCount)
        );
        let mut oversized_field = wire.clone();
        let first_field_length = WIRE_MAGIC.len() + 2 + 2;
        oversized_field[first_field_length..first_field_length + 4]
            .copy_from_slice(&257_u32.to_be_bytes());
        assert_eq!(
            decode_macos_coordinator_request_wire_v1(&oversized_field)
                .map(|_| ())
                .map_err(|error| error.rejection),
            Err(MacOsCoordinatorWireRejectionV1::OversizedField)
        );
        let mut truncated_wire = wire.clone();
        let _ = truncated_wire.pop();
        assert_eq!(
            decode_macos_coordinator_request_wire_v1(&truncated_wire)
                .map(|_| ())
                .map_err(|error| error.rejection),
            Err(MacOsCoordinatorWireRejectionV1::TruncatedEnvelope)
        );
        assert_eq!(
            decode_macos_coordinator_request_wire_v1(&vec![
                0;
                MAX_MACOS_COORDINATOR_REQUEST_WIRE_BYTES_V1
                    + 1
            ])
            .map(|_| ())
            .map_err(|error| error.rejection),
            Err(MacOsCoordinatorWireRejectionV1::OversizedEnvelope)
        );
        let mut drift = wire;
        if let Some(last) = drift.last_mut() {
            *last ^= 1;
        }
        assert_eq!(
            decode_macos_coordinator_request_wire_v1(&drift)
                .map(|_| ())
                .map_err(|error| error.rejection),
            Err(MacOsCoordinatorWireRejectionV1::RequestIdentityMismatch)
        );
        Ok(())
    }
}

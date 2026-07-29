use crate::{
    MacOsLakeExecutableObservationRejectionV1, MacOsPathProvenanceDecisionV1,
    MacOsPathProvenanceObservationV1, TrustedLakeLaunchReservationV1,
    launch_reservation::{reobserve_reserved_executable_v1, reservation_integrity_is_valid_v1},
    observe_macos_path_provenance_v1,
};
use core::fmt;
use leanbun_core::Sha256;
use leanbun_plan::PlanExecutionAuthorityV1;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsReservationBoundPathEligibilityDecisionV1 {
    DeniedReservationInvalid,
    DeniedReservationExpired,
    DeniedExecutableIdentityDrift,
    DeniedUserOwnedComponent,
    DeniedEffectiveUidWriteAccess,
    DeniedGroupOrWorldWritable,
    DeniedEffectiveAccessUnverified,
    DeniedAclMutationAllowEntry,
    DeniedAclCoverageUnverified,
    DeniedMountOrWriterContinuityUnverified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsReservationBoundPathEligibilityV1 {
    pub schema_version: u8,
    pub reservation_sha256: Sha256,
    pub intent_sha256: Sha256,
    pub executable_sha256: Sha256,
    pub executable: PathBuf,
    pub assessed_at_unix_ms: u64,
    pub path_provenance: Option<MacOsPathProvenanceObservationV1>,
    pub decision: MacOsReservationBoundPathEligibilityDecisionV1,
    pub execution_authority: PlanExecutionAuthorityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsReservationBoundPathEligibilityRejectionV1 {
    ClockInvalid,
    ExecutableObservationFailed,
    PathObservationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsReservationBoundPathEligibilityError {
    pub rejection: MacOsReservationBoundPathEligibilityRejectionV1,
    pub message: String,
}

impl fmt::Display for MacOsReservationBoundPathEligibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MacOsReservationBoundPathEligibilityError {}

/// Re-observes the exact executable sealed by a durable reservation and then
/// joins it with fresh component provenance. The reservation is only borrowed;
/// this assessment cannot consume its slot or grant launch authority.
pub fn assess_reservation_bound_path_eligibility_v1(
    reservation: &TrustedLakeLaunchReservationV1,
) -> Result<MacOsReservationBoundPathEligibilityV1, MacOsReservationBoundPathEligibilityError> {
    assess_with_clock_v1(reservation, current_unix_ms)
}

pub(crate) fn assess_with_clock_v1(
    reservation: &TrustedLakeLaunchReservationV1,
    mut clock: impl FnMut() -> Result<u64, MacOsReservationBoundPathEligibilityError>,
) -> Result<MacOsReservationBoundPathEligibilityV1, MacOsReservationBoundPathEligibilityError> {
    let started_at_unix_ms = clock()?;
    if !reservation_integrity_is_valid_v1(reservation) {
        return Ok(assessment(
            reservation,
            started_at_unix_ms,
            None,
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedReservationInvalid,
        ));
    }
    if started_at_unix_ms < reservation.reserved_at_unix_ms()
        || started_at_unix_ms >= reservation.expires_at_unix_ms()
    {
        return Ok(assessment(
            reservation,
            started_at_unix_ms,
            None,
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedReservationExpired,
        ));
    }

    let (_, exact_executable_match) = match reobserve_reserved_executable_v1(reservation) {
        Ok(observation) => observation,
        Err(error)
            if error.rejection
                == MacOsLakeExecutableObservationRejectionV1::ReviewedIdentityMismatch =>
        {
            let assessed_at_unix_ms = clock()?;
            let decision = if assessed_at_unix_ms < started_at_unix_ms
                || assessed_at_unix_ms < reservation.reserved_at_unix_ms()
                || assessed_at_unix_ms >= reservation.expires_at_unix_ms()
            {
                MacOsReservationBoundPathEligibilityDecisionV1::DeniedReservationExpired
            } else {
                MacOsReservationBoundPathEligibilityDecisionV1::DeniedExecutableIdentityDrift
            };
            return Ok(assessment(reservation, assessed_at_unix_ms, None, decision));
        }
        Err(error) => {
            return Err(eligibility_error(
                MacOsReservationBoundPathEligibilityRejectionV1::ExecutableObservationFailed,
                format!("cannot re-observe reserved Lake executable: {error}"),
            ));
        }
    };
    if !exact_executable_match {
        let assessed_at_unix_ms = clock()?;
        let decision = if assessed_at_unix_ms < started_at_unix_ms
            || assessed_at_unix_ms < reservation.reserved_at_unix_ms()
            || assessed_at_unix_ms >= reservation.expires_at_unix_ms()
        {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedReservationExpired
        } else {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedExecutableIdentityDrift
        };
        return Ok(assessment(reservation, assessed_at_unix_ms, None, decision));
    }

    let provenance =
        observe_macos_path_provenance_v1(reservation.executable()).map_err(|error| {
            eligibility_error(
                MacOsReservationBoundPathEligibilityRejectionV1::PathObservationFailed,
                format!("cannot observe reserved executable path provenance: {error}"),
            )
        })?;
    let assessed_at_unix_ms = clock()?;
    if assessed_at_unix_ms < started_at_unix_ms
        || assessed_at_unix_ms < reservation.reserved_at_unix_ms()
        || assessed_at_unix_ms >= reservation.expires_at_unix_ms()
    {
        return Ok(assessment(
            reservation,
            assessed_at_unix_ms,
            Some(provenance),
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedReservationExpired,
        ));
    }
    let decision = map_path_decision(provenance.decision);
    Ok(assessment(
        reservation,
        assessed_at_unix_ms,
        Some(provenance),
        decision,
    ))
}

fn map_path_decision(
    decision: MacOsPathProvenanceDecisionV1,
) -> MacOsReservationBoundPathEligibilityDecisionV1 {
    match decision {
        MacOsPathProvenanceDecisionV1::DeniedUserOwnedComponent => {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedUserOwnedComponent
        }
        MacOsPathProvenanceDecisionV1::DeniedEffectiveUidWriteAccess => {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedEffectiveUidWriteAccess
        }
        MacOsPathProvenanceDecisionV1::DeniedGroupOrWorldWritable => {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedGroupOrWorldWritable
        }
        MacOsPathProvenanceDecisionV1::DeniedEffectiveAccessUnverified => {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedEffectiveAccessUnverified
        }
        MacOsPathProvenanceDecisionV1::DeniedAclMutationAllowEntry => {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedAclMutationAllowEntry
        }
        MacOsPathProvenanceDecisionV1::DeniedAclCoverageUnverified => {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedAclCoverageUnverified
        }
        MacOsPathProvenanceDecisionV1::DeniedMountOrWriterContinuityUnverified => {
            MacOsReservationBoundPathEligibilityDecisionV1::DeniedMountOrWriterContinuityUnverified
        }
    }
}

fn assessment(
    reservation: &TrustedLakeLaunchReservationV1,
    assessed_at_unix_ms: u64,
    path_provenance: Option<MacOsPathProvenanceObservationV1>,
    decision: MacOsReservationBoundPathEligibilityDecisionV1,
) -> MacOsReservationBoundPathEligibilityV1 {
    MacOsReservationBoundPathEligibilityV1 {
        schema_version: 1,
        reservation_sha256: reservation.reservation_sha256(),
        intent_sha256: reservation.intent_sha256(),
        executable_sha256: reservation.executable_sha256(),
        executable: reservation.executable().to_path_buf(),
        assessed_at_unix_ms,
        path_provenance,
        decision,
        execution_authority: PlanExecutionAuthorityV1::Withheld,
    }
}

fn current_unix_ms() -> Result<u64, MacOsReservationBoundPathEligibilityError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        eligibility_error(
            MacOsReservationBoundPathEligibilityRejectionV1::ClockInvalid,
            "system clock is before Unix epoch",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        eligibility_error(
            MacOsReservationBoundPathEligibilityRejectionV1::ClockInvalid,
            "system clock is out of range",
        )
    })
}

fn eligibility_error(
    rejection: MacOsReservationBoundPathEligibilityRejectionV1,
    message: impl Into<String>,
) -> MacOsReservationBoundPathEligibilityError {
    MacOsReservationBoundPathEligibilityError {
        rejection,
        message: message.into(),
    }
}

use crate::{
    LakeLaunchEnvironmentEntryV1, MacOsLakeExecutableObservationError,
    TrustedLakeExecutableObservationV1, TrustedLakeLaunchAuthorityV1,
    TrustedLakeLaunchIntentDecisionV1, TrustedLakeLaunchIntentV1,
    launch_intent::launch_intent_sha256, observe_reviewed_lake_executable_v1,
};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use rustix::fs::{FileType, Mode, OFlags};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeLaunchReservationDecisionV1 {
    ReservedOnce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeLaunchReservationAuthorityV1 {
    ReservedOnce,
}

pub struct TrustedLakeLaunchReservationV1 {
    schema_version: u8,
    decision: TrustedLakeLaunchReservationDecisionV1,
    intent: TrustedLakeLaunchIntentV1,
    reserved_at_unix_ms: u64,
    reservation_sha256: Sha256,
    execution_authority: TrustedLakeLaunchReservationAuthorityV1,
}

impl TrustedLakeLaunchReservationV1 {
    #[must_use]
    pub fn schema_version(&self) -> u8 {
        self.schema_version
    }

    #[must_use]
    pub fn decision(&self) -> TrustedLakeLaunchReservationDecisionV1 {
        self.decision
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        self.intent.executable()
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        self.intent.arguments()
    }

    #[must_use]
    pub fn cwd(&self) -> &Path {
        self.intent.cwd()
    }

    #[must_use]
    pub fn environment(&self) -> &[LakeLaunchEnvironmentEntryV1] {
        self.intent.environment()
    }

    #[must_use]
    pub fn intent_sha256(&self) -> Sha256 {
        self.intent.intent_sha256
    }

    #[must_use]
    pub fn reserved_at_unix_ms(&self) -> u64 {
        self.reserved_at_unix_ms
    }

    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.intent.expires_at_unix_ms
    }

    #[must_use]
    pub fn reservation_sha256(&self) -> Sha256 {
        self.reservation_sha256
    }

    #[must_use]
    pub fn executable_sha256(&self) -> Sha256 {
        self.intent.executable.observation.sha256
    }

    #[must_use]
    pub fn execution_authority(&self) -> TrustedLakeLaunchReservationAuthorityV1 {
        self.execution_authority
    }
}

pub(crate) fn reservation_integrity_is_valid_v1(
    reservation: &TrustedLakeLaunchReservationV1,
) -> bool {
    reservation.schema_version == 1
        && reservation.decision == TrustedLakeLaunchReservationDecisionV1::ReservedOnce
        && reservation.execution_authority == TrustedLakeLaunchReservationAuthorityV1::ReservedOnce
        && validate_intent(&reservation.intent, reservation.reserved_at_unix_ms).is_ok()
        && reservation.reservation_sha256
            == sha256(&canonical_reservation_bytes(
                &reservation.intent,
                reservation.reserved_at_unix_ms,
            ))
}

pub(crate) fn reobserve_reserved_executable_v1(
    reservation: &TrustedLakeLaunchReservationV1,
) -> Result<(TrustedLakeExecutableObservationV1, bool), MacOsLakeExecutableObservationError> {
    let executable = reservation.executable();
    let managed_toolchain_root = executable
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(""));
    let fresh = observe_reviewed_lake_executable_v1(
        managed_toolchain_root,
        reservation.intent.grant.plan(),
    )?;
    let exact_match = fresh.observation == reservation.intent.executable.observation;
    Ok((fresh, exact_match))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeLaunchReservationRejectionV1 {
    InvalidRegistryRoot,
    InvalidLaunchIntent,
    ClockInvalid,
    LaunchIntentExpired,
    AlreadyReserved,
    PersistenceUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedLakeLaunchReservationError {
    pub rejection: TrustedLakeLaunchReservationRejectionV1,
    pub message: String,
}

impl fmt::Display for TrustedLakeLaunchReservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TrustedLakeLaunchReservationError {}

pub struct TrustedLakeLaunchReservationRegistryV1 {
    root: OwnedFd,
}

pub fn open_trusted_lake_launch_reservation_registry_v1(
    root: &Path,
) -> Result<TrustedLakeLaunchReservationRegistryV1, TrustedLakeLaunchReservationError> {
    if !root.is_absolute() {
        return Err(reservation_error(
            TrustedLakeLaunchReservationRejectionV1::InvalidRegistryRoot,
            "launch reservation registry root must be absolute",
        ));
    }
    let root = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        reservation_error(
            TrustedLakeLaunchReservationRejectionV1::InvalidRegistryRoot,
            format!("cannot open launch reservation registry root: {error}"),
        )
    })?;
    let stat = rustix::fs::fstat(&root).map_err(|error| {
        reservation_error(
            TrustedLakeLaunchReservationRejectionV1::InvalidRegistryRoot,
            format!("cannot inspect launch reservation registry root: {error}"),
        )
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode) != Mode::RWXU
    {
        return Err(reservation_error(
            TrustedLakeLaunchReservationRejectionV1::InvalidRegistryRoot,
            "launch reservation registry must be a private 0700 directory owned by the effective user",
        ));
    }
    Ok(TrustedLakeLaunchReservationRegistryV1 { root })
}

impl TrustedLakeLaunchReservationRegistryV1 {
    pub fn reserve_launch_intent_v1(
        &self,
        intent: TrustedLakeLaunchIntentV1,
    ) -> Result<TrustedLakeLaunchReservationV1, TrustedLakeLaunchReservationError> {
        let reserved_at_unix_ms = current_unix_ms()?;
        self.reserve_launch_intent_with_clock_v1(intent, reserved_at_unix_ms, current_unix_ms)
    }

    pub(crate) fn reserve_launch_intent_with_clock_v1(
        &self,
        intent: TrustedLakeLaunchIntentV1,
        reserved_at_unix_ms: u64,
        durable_clock: impl FnOnce() -> Result<u64, TrustedLakeLaunchReservationError>,
    ) -> Result<TrustedLakeLaunchReservationV1, TrustedLakeLaunchReservationError> {
        validate_intent(&intent, reserved_at_unix_ms)?;
        let bytes = canonical_reservation_bytes(&intent, reserved_at_unix_ms);
        let reservation_sha256 = sha256(&bytes);
        let filename = reservation_filename(intent.intent_sha256);
        let slot = match rustix::fs::openat(
            &self.root,
            filename.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(slot) => slot,
            Err(error) if error == rustix::io::Errno::EXIST => {
                return Err(reservation_error(
                    TrustedLakeLaunchReservationRejectionV1::AlreadyReserved,
                    "launch intent already has a durable reservation slot",
                ));
            }
            Err(error) => {
                return Err(reservation_error(
                    TrustedLakeLaunchReservationRejectionV1::PersistenceUncertain,
                    format!("cannot atomically reserve launch slot: {error}"),
                ));
            }
        };

        let mut slot: File = slot.into();
        slot.write_all(&bytes)
            .and_then(|()| slot.sync_all())
            .map_err(|error| {
                reservation_error(
                    TrustedLakeLaunchReservationRejectionV1::PersistenceUncertain,
                    format!(
                        "launch slot exists but its durable record is uncertain; it must remain reserved: {error}"
                    ),
                )
            })?;
        rustix::fs::fsync(&self.root).map_err(|error| {
            reservation_error(
                TrustedLakeLaunchReservationRejectionV1::PersistenceUncertain,
                format!(
                    "launch slot exists but directory durability is uncertain; launch remains blocked: {error}"
                ),
            )
        })?;
        let durable_at_unix_ms = durable_clock()?;
        if durable_at_unix_ms < reserved_at_unix_ms {
            return Err(reservation_error(
                TrustedLakeLaunchReservationRejectionV1::ClockInvalid,
                "launch reservation durability time is before reservation time; slot remains reserved",
            ));
        }
        if durable_at_unix_ms >= intent.expires_at_unix_ms {
            return Err(reservation_error(
                TrustedLakeLaunchReservationRejectionV1::LaunchIntentExpired,
                "launch intent expired before reservation became durable; slot remains reserved",
            ));
        }

        Ok(TrustedLakeLaunchReservationV1 {
            schema_version: 1,
            decision: TrustedLakeLaunchReservationDecisionV1::ReservedOnce,
            intent,
            reserved_at_unix_ms,
            reservation_sha256,
            execution_authority: TrustedLakeLaunchReservationAuthorityV1::ReservedOnce,
        })
    }
}

fn validate_intent(
    intent: &TrustedLakeLaunchIntentV1,
    reserved_at_unix_ms: u64,
) -> Result<(), TrustedLakeLaunchReservationError> {
    if intent.schema_version != 1
        || intent.decision != TrustedLakeLaunchIntentDecisionV1::PreparedOnce
        || intent.execution_authority != TrustedLakeLaunchAuthorityV1::PreparedOnce
        || intent.intent_sha256
            != launch_intent_sha256(
                &intent.grant,
                &intent.executable,
                &intent.environment,
                intent.prepared_at_unix_ms,
            )
    {
        return Err(reservation_error(
            TrustedLakeLaunchReservationRejectionV1::InvalidLaunchIntent,
            "launch reservation requires one intact sealed launch intent",
        ));
    }
    if reserved_at_unix_ms < intent.prepared_at_unix_ms {
        return Err(reservation_error(
            TrustedLakeLaunchReservationRejectionV1::ClockInvalid,
            "launch reservation time is before intent preparation time",
        ));
    }
    if reserved_at_unix_ms >= intent.expires_at_unix_ms {
        return Err(reservation_error(
            TrustedLakeLaunchReservationRejectionV1::LaunchIntentExpired,
            "launch intent expired before reservation",
        ));
    }
    Ok(())
}

fn canonical_reservation_bytes(
    intent: &TrustedLakeLaunchIntentV1,
    reserved_at_unix_ms: u64,
) -> Vec<u8> {
    format!(
        "{{\"schemaVersion\":1,\"decision\":\"reserved-once\",\"intentSha256\":\"{}\",\"grantSha256\":\"{}\",\"candidateSha256\":\"{}\",\"proofSha256\":\"{}\",\"executableSha256\":\"{}\",\"preparedAtUnixMs\":{},\"reservedAtUnixMs\":{},\"expiresAtUnixMs\":{},\"executionAuthority\":\"reserved-once\"}}\n",
        intent.intent_sha256,
        intent.grant.grant_sha256,
        intent.grant.candidate.candidate_sha256,
        intent.grant.candidate.proof.proof_sha256,
        intent.executable.observation.sha256,
        intent.prepared_at_unix_ms,
        reserved_at_unix_ms,
        intent.expires_at_unix_ms,
    )
    .into_bytes()
}

fn reservation_filename(intent_sha256: Sha256) -> String {
    format!("{intent_sha256}.launch-reserved-v1")
}

fn sha256(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn current_unix_ms() -> Result<u64, TrustedLakeLaunchReservationError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        reservation_error(
            TrustedLakeLaunchReservationRejectionV1::ClockInvalid,
            "system clock is before Unix epoch",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        reservation_error(
            TrustedLakeLaunchReservationRejectionV1::ClockInvalid,
            "system clock is out of range",
        )
    })
}

fn reservation_error(
    rejection: TrustedLakeLaunchReservationRejectionV1,
    message: impl Into<String>,
) -> TrustedLakeLaunchReservationError {
    TrustedLakeLaunchReservationError {
        rejection,
        message: message.into(),
    }
}

use crate::{
    MacOsLakeExecutableObservationError, TrustedLakeExecutableObservationV1,
    TrustedLakeExecutionAuthorityV1, TrustedLakeExecutionGrantDecisionV1,
    TrustedLakeExecutionGrantV1, execution_grant::grant_sha256,
    observe_reviewed_lake_executable_v1,
};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_evidence::{
    CanonicalDirectory, canonicalize_contained_directory, canonicalize_directory,
};
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PATH_ENTRIES: usize = 16;
const MAX_PATH_BYTES: usize = 4_096;
const ENVIRONMENT_KEYS: [&str; 5] = [
    "ELAN_HOME",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_TERMINAL_PROMPT",
    "HOME",
    "PATH",
];

pub struct LakeLaunchEnvironmentLocationV1<'a> {
    pub isolation_root: &'a Path,
    pub elan_home: &'a Path,
    pub home: &'a Path,
    pub path_entries: &'a [PathBuf],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeLaunchEnvironmentEntryV1 {
    key: String,
    value: String,
}

impl LakeLaunchEnvironmentEntryV1 {
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeLaunchIntentDecisionV1 {
    PreparedOnce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeLaunchAuthorityV1 {
    PreparedOnce,
}

pub struct TrustedLakeLaunchIntentV1 {
    pub(crate) schema_version: u8,
    pub(crate) decision: TrustedLakeLaunchIntentDecisionV1,
    pub(crate) grant: TrustedLakeExecutionGrantV1,
    pub(crate) executable: TrustedLakeExecutableObservationV1,
    pub(crate) environment: Vec<LakeLaunchEnvironmentEntryV1>,
    pub(crate) prepared_at_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) intent_sha256: Sha256,
    pub(crate) execution_authority: TrustedLakeLaunchAuthorityV1,
}

impl TrustedLakeLaunchIntentV1 {
    #[must_use]
    pub fn schema_version(&self) -> u8 {
        self.schema_version
    }

    #[must_use]
    pub fn decision(&self) -> TrustedLakeLaunchIntentDecisionV1 {
        self.decision
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        self.grant.plan().executable.as_path()
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.grant.plan().arguments
    }

    #[must_use]
    pub fn cwd(&self) -> &Path {
        self.grant.plan().cwd.as_path()
    }

    #[must_use]
    pub fn environment(&self) -> &[LakeLaunchEnvironmentEntryV1] {
        &self.environment
    }

    #[must_use]
    pub fn executable_observed_at_unix_ms(&self) -> u64 {
        self.executable.observed_at_unix_ms
    }

    #[must_use]
    pub fn prepared_at_unix_ms(&self) -> u64 {
        self.prepared_at_unix_ms
    }

    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub fn intent_sha256(&self) -> Sha256 {
        self.intent_sha256
    }

    #[must_use]
    pub fn execution_authority(&self) -> TrustedLakeLaunchAuthorityV1 {
        self.execution_authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedLakeLaunchIntentRejectionV1 {
    GrantInvalid,
    ExecutableInvalid,
    EnvironmentInvalid,
    ClockInvalid,
    GrantExpired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedLakeLaunchIntentError {
    pub rejection: TrustedLakeLaunchIntentRejectionV1,
    pub message: String,
}

impl fmt::Display for TrustedLakeLaunchIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TrustedLakeLaunchIntentError {}

pub fn prepare_trusted_lake_launch_intent_v1(
    grant: TrustedLakeExecutionGrantV1,
    managed_toolchain_root: &Path,
    environment_location: LakeLaunchEnvironmentLocationV1<'_>,
) -> Result<TrustedLakeLaunchIntentV1, TrustedLakeLaunchIntentError> {
    verify_grant(&grant)?;
    let executable = observe_reviewed_lake_executable_v1(managed_toolchain_root, grant.plan())
        .map_err(executable_error)?;
    let environment = assemble_environment(grant.plan(), environment_location)?;
    let prepared_at_unix_ms = current_unix_ms()?;
    if executable.observed_at_unix_ms < grant.granted_at_unix_ms
        || prepared_at_unix_ms < executable.observed_at_unix_ms
    {
        return Err(intent_error(
            TrustedLakeLaunchIntentRejectionV1::ClockInvalid,
            "launch preparation time is before grant or executable observation",
        ));
    }
    if prepared_at_unix_ms >= grant.expires_at_unix_ms {
        return Err(intent_error(
            TrustedLakeLaunchIntentRejectionV1::GrantExpired,
            "trusted execution grant expired before launch intent was sealed",
        ));
    }
    let expires_at_unix_ms = grant.expires_at_unix_ms;
    let intent_sha256 =
        launch_intent_sha256(&grant, &executable, &environment, prepared_at_unix_ms);
    Ok(TrustedLakeLaunchIntentV1 {
        schema_version: 1,
        decision: TrustedLakeLaunchIntentDecisionV1::PreparedOnce,
        grant,
        executable,
        environment,
        prepared_at_unix_ms,
        expires_at_unix_ms,
        intent_sha256,
        execution_authority: TrustedLakeLaunchAuthorityV1::PreparedOnce,
    })
}

fn verify_grant(grant: &TrustedLakeExecutionGrantV1) -> Result<(), TrustedLakeLaunchIntentError> {
    if grant.schema_version != 1
        || grant.decision != TrustedLakeExecutionGrantDecisionV1::GrantedOnce
        || grant.execution_authority != TrustedLakeExecutionAuthorityV1::GrantedOnce
        || grant.expires_at_unix_ms != grant.candidate.expires_at_unix_ms
        || grant.grant_sha256 != grant_sha256(&grant.candidate, grant.granted_at_unix_ms)
    {
        return Err(intent_error(
            TrustedLakeLaunchIntentRejectionV1::GrantInvalid,
            "launch intent requires one intact trusted execution grant",
        ));
    }
    Ok(())
}

fn assemble_environment(
    plan: &leanbun_plan::LakeCommandPlanV1,
    location: LakeLaunchEnvironmentLocationV1<'_>,
) -> Result<Vec<LakeLaunchEnvironmentEntryV1>, TrustedLakeLaunchIntentError> {
    if plan.environment_allowlist
        != ENVIRONMENT_KEYS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
        || location.path_entries.is_empty()
        || location.path_entries.len() > MAX_PATH_ENTRIES
    {
        return Err(intent_error(
            TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
            "launch environment keys or PATH entry count are invalid",
        ));
    }
    let root = canonicalize_directory(location.isolation_root).map_err(environment_error)?;
    if !location.isolation_root.is_absolute() || location.isolation_root != root.as_path() {
        return Err(intent_error(
            TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
            "launch isolation root must be its direct canonical path",
        ));
    }
    verify_private_environment_directory(root.as_path())?;
    let elan_home = canonical_environment_directory(&root, location.elan_home)?;
    let home = canonical_environment_directory(&root, location.home)?;
    let mut path_values = Vec::with_capacity(location.path_entries.len());
    let mut unique = BTreeSet::new();
    for entry in location.path_entries {
        let canonical = canonical_environment_directory(&root, entry)?;
        let value = utf8_path(canonical.as_path())?;
        if value.contains(':') || !unique.insert(value.clone()) {
            return Err(intent_error(
                TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
                "PATH entries must be unique canonical directories without separators",
            ));
        }
        path_values.push(value);
    }
    let path = path_values.join(":");
    if path.len() > MAX_PATH_BYTES {
        return Err(intent_error(
            TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
            "launch PATH exceeds the byte limit",
        ));
    }
    Ok(vec![
        environment_entry("ELAN_HOME", utf8_path(elan_home.as_path())?),
        environment_entry("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        environment_entry("GIT_TERMINAL_PROMPT", "0".to_owned()),
        environment_entry("HOME", utf8_path(home.as_path())?),
        environment_entry("PATH", path),
    ])
}

fn canonical_environment_directory(
    root: &CanonicalDirectory,
    candidate: &Path,
) -> Result<CanonicalDirectory, TrustedLakeLaunchIntentError> {
    let requested = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.as_path().join(candidate)
    };
    let canonical = canonicalize_contained_directory(root, candidate).map_err(environment_error)?;
    if requested != canonical.as_path() {
        return Err(intent_error(
            TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
            "launch environment directories must use direct canonical paths without symlinks",
        ));
    }
    verify_private_environment_directory(canonical.as_path())?;
    Ok(canonical)
}

fn verify_private_environment_directory(path: &Path) -> Result<(), TrustedLakeLaunchIntentError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        intent_error(
            TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
            format!("cannot inspect launch environment directory: {error}"),
        )
    })?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(intent_error(
            TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
            "launch environment directories must be user-owned and not group/world writable",
        ));
    }
    Ok(())
}

fn environment_entry(key: &str, value: String) -> LakeLaunchEnvironmentEntryV1 {
    LakeLaunchEnvironmentEntryV1 {
        key: key.to_owned(),
        value,
    }
}

fn utf8_path(path: &Path) -> Result<String, TrustedLakeLaunchIntentError> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        intent_error(
            TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
            "launch environment path is not valid UTF-8",
        )
    })
}

pub(crate) fn launch_intent_sha256(
    grant: &TrustedLakeExecutionGrantV1,
    executable: &TrustedLakeExecutableObservationV1,
    environment: &[LakeLaunchEnvironmentEntryV1],
    prepared_at_unix_ms: u64,
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-trusted-lake-launch-intent-v1\0");
    hash_field(&mut hasher, grant.grant_sha256.as_bytes());
    hash_field(&mut hasher, executable.observation.sha256.as_bytes());
    hash_field(&mut hasher, &executable.observed_at_unix_ms.to_be_bytes());
    hash_field(&mut hasher, &prepared_at_unix_ms.to_be_bytes());
    hash_field(&mut hasher, &grant.expires_at_unix_ms.to_be_bytes());
    for entry in environment {
        hash_field(&mut hasher, entry.key.as_bytes());
        hash_field(&mut hasher, entry.value.as_bytes());
    }
    hasher.finalize()
}

fn hash_field(hasher: &mut Sha256Hasher, value: &[u8]) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn executable_error(error: MacOsLakeExecutableObservationError) -> TrustedLakeLaunchIntentError {
    intent_error(
        TrustedLakeLaunchIntentRejectionV1::ExecutableInvalid,
        format!("pre-launch Lake executable observation failed: {error}"),
    )
}

fn environment_error(error: leanbun_evidence::EvidenceError) -> TrustedLakeLaunchIntentError {
    intent_error(
        TrustedLakeLaunchIntentRejectionV1::EnvironmentInvalid,
        format!("launch environment evidence is invalid: {}", error.message),
    )
}

fn current_unix_ms() -> Result<u64, TrustedLakeLaunchIntentError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        intent_error(
            TrustedLakeLaunchIntentRejectionV1::ClockInvalid,
            "system clock is before Unix epoch",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        intent_error(
            TrustedLakeLaunchIntentRejectionV1::ClockInvalid,
            "system clock is out of range",
        )
    })
}

fn intent_error(
    rejection: TrustedLakeLaunchIntentRejectionV1,
    message: impl Into<String>,
) -> TrustedLakeLaunchIntentError {
    TrustedLakeLaunchIntentError {
        rejection,
        message: message.into(),
    }
}

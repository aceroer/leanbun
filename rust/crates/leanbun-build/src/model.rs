use leanbun_core::{Sha256, Sha256Hasher};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_TARGET_BYTES: usize = 256;
const MAX_ENVIRONMENT: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildErrorKind {
    InvalidField,
    BoundaryViolation,
    ExecutableDrift,
    LockBusy,
    SpawnFailed,
    TimedOut,
    Signalled,
    OutputOverflow,
    LakeNonzero,
    PathDrift,
    InputDrift,
    ArtifactDrift,
    RecordDrift,
    Io,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildError {
    pub kind: BuildErrorKind,
    pub message: String,
}

impl BuildError {
    pub(crate) fn new(kind: BuildErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildInputsV1 {
    pub lock_sha256: Sha256,
    pub graph_sha256: Sha256,
    pub decision_set_sha256: Sha256,
    pub generation_sha256: Sha256,
    pub lean_toolchain: String,
    pub compiler_githash: String,
    pub platform: String,
    pub build_config_sha256: Sha256,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildImageV1 {
    key: Sha256,
    inputs: BuildInputsV1,
    dependency_artifact_sha256: Sha256,
}

impl BuildImageV1 {
    pub fn new(
        inputs: BuildInputsV1,
        dependency_artifact_sha256: Sha256,
    ) -> Result<Self, BuildError> {
        validate_atom(&inputs.lean_toolchain, 512, "Lean toolchain")?;
        validate_atom(&inputs.compiler_githash, 128, "compiler githash")?;
        validate_atom(&inputs.platform, 128, "platform")?;
        validate_atom(&inputs.target, MAX_TARGET_BYTES, "target")?;
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-build-image-v1\0");
        for digest in [
            inputs.lock_sha256,
            inputs.graph_sha256,
            inputs.decision_set_sha256,
            inputs.generation_sha256,
            inputs.build_config_sha256,
        ] {
            hasher.update(digest.as_bytes());
        }
        hash_text(&mut hasher, &inputs.lean_toolchain);
        hash_text(&mut hasher, &inputs.compiler_githash);
        hash_text(&mut hasher, &inputs.platform);
        hash_text(&mut hasher, &inputs.target);
        Ok(Self {
            key: hasher.finalize(),
            inputs,
            dependency_artifact_sha256,
        })
    }

    #[must_use]
    pub const fn key(&self) -> Sha256 {
        self.key
    }
    #[must_use]
    pub fn inputs(&self) -> &BuildInputsV1 {
        &self.inputs
    }
    #[must_use]
    pub const fn dependency_artifact_sha256(&self) -> Sha256 {
        self.dependency_artifact_sha256
    }
}

impl BuildInputsV1 {
    pub fn from_active_generation(
        generation: &leanbun_generation::LeanBunGenerationV1,
        build_config_sha256: Sha256,
        target: impl Into<String>,
    ) -> Self {
        Self {
            lock_sha256: generation.lock_sha256(),
            graph_sha256: generation.graph_sha256(),
            decision_set_sha256: generation.decision_set_sha256(),
            generation_sha256: generation.identity(),
            lean_toolchain: generation.lean_toolchain().to_owned(),
            compiler_githash: generation.compiler_githash().to_owned(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            build_config_sha256,
            target: target.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectBuildOutputV1 {
    pub image_key: Sha256,
    pub project_input_sha256: Sha256,
    pub project_artifact_sha256: Sha256,
}

#[derive(Clone, Debug)]
pub struct SupervisedLakeBuildV1 {
    pub supervisor_executable: PathBuf,
    pub sandbox_executable: PathBuf,
    pub sandbox_profile: PathBuf,
    pub sandbox_profile_sha256: Sha256,
    pub lake_executable: PathBuf,
    pub lake_executable_sha256: Sha256,
    pub cwd: PathBuf,
    pub runtime_packages: PathBuf,
    pub target: String,
    pub allowed_targets: BTreeSet<String>,
    pub environment: BTreeMap<String, String>,
    pub deadline: Duration,
    pub termination_grace: Duration,
    pub maximum_output_bytes: usize,
}

impl SupervisedLakeBuildV1 {
    pub fn validate(&self) -> Result<(), BuildError> {
        for (path, label) in [
            (&self.supervisor_executable, "supervisor"),
            (&self.sandbox_executable, "sandbox"),
            (&self.sandbox_profile, "sandbox profile"),
            (&self.lake_executable, "Lake executable"),
            (&self.runtime_packages, "runtime packages projection"),
        ] {
            if !path.is_absolute() || !path.is_file() {
                return Err(invalid(format!("{label} must be an absolute regular file")));
            }
        }
        if !self.cwd.is_absolute() || !self.cwd.is_dir() {
            return Err(invalid("build cwd must be an absolute directory"));
        }
        validate_atom(&self.target, MAX_TARGET_BYTES, "target")?;
        if !self.allowed_targets.contains(&self.target) || self.allowed_targets.len() > 128 {
            return Err(invalid("build target is not in the fixed allowlist"));
        }
        if self.deadline.is_zero()
            || self.deadline > Duration::from_secs(7_200)
            || self.termination_grace > Duration::from_secs(10)
            || !(1_024..=16 * 1_024 * 1_024).contains(&self.maximum_output_bytes)
        {
            return Err(invalid("deadline, grace, or output bound is invalid"));
        }
        if self.environment.len() > MAX_ENVIRONMENT {
            return Err(invalid("environment allowlist is too large"));
        }
        const ALLOWED: &[&str] = &[
            "PATH",
            "HOME",
            "TMPDIR",
            "ELAN_HOME",
            "LEAN_SYSROOT",
            "DYLD_LIBRARY_PATH",
            "LC_ALL",
            "LANG",
            "DO_NOT_TRACK",
            "LAKE_NO_CACHE",
            "LAKE_ARTIFACT_CACHE",
        ];
        for (key, value) in &self.environment {
            if !ALLOWED.contains(&key.as_str()) || key.is_empty() || value.contains('\0') {
                return Err(invalid("environment contains a non-allowlisted entry"));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn lake_arguments(&self) -> Vec<String> {
        vec![
            format!("--packages={}", self.runtime_packages.display()),
            "--no-cache".to_owned(),
            "--keep-toolchain".to_owned(),
            "--no-ansi".to_owned(),
            "build".to_owned(),
            self.target.clone(),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminationReasonV1 {
    Exit,
    Timeout,
    Signal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildResultV1 {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub termination: TerminationReasonV1,
    pub process_group_id: u32,
    pub output_overflow: bool,
}

fn hash_text(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn validate_atom(value: &str, maximum: usize, label: &str) -> Result<(), BuildError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid(format!("{label} is invalid")));
    }
    Ok(())
}

pub(crate) fn hash_file(path: &Path, maximum: u64) -> Result<Sha256, BuildError> {
    let metadata = std::fs::symlink_metadata(path).map_err(io)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(invalid("bounded regular file required"));
    }
    let bytes = std::fs::read(path).map_err(io)?;
    let mut hasher = Sha256Hasher::new();
    hasher.update(&bytes);
    Ok(hasher.finalize())
}

pub(crate) fn invalid(message: impl Into<String>) -> BuildError {
    BuildError::new(BuildErrorKind::InvalidField, message)
}
pub(crate) fn io(error: std::io::Error) -> BuildError {
    BuildError::new(BuildErrorKind::Io, format!("M36 I/O failed: {error}"))
}

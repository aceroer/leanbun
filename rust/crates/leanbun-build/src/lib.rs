#![forbid(unsafe_code)]

mod acceptance;
mod model;
mod process;
mod regression;
mod reuse;

pub use acceptance::{RepositoryFixtureAcceptanceV1, run_repository_fixture_acceptance_v1};

pub use model::{
    BuildError, BuildErrorKind, BuildImageV1, BuildInputsV1, BuildResultV1, ProjectBuildOutputV1,
    SupervisedLakeBuildV1, TerminationReasonV1,
};
pub use process::{run_supervised_lake_build_v1, verify_lake_workspace_paths_v1};
pub use regression::{FixtureRegressionV1, run_lake_basic_regression_v1};
pub use reuse::{BuildImageFaultV1, BuildImageStoreV1, ReuseOutcomeV1};

use leanbun_core::Sha256;
use leanbun_generation::{LeanBunGenerationV1, LeanGenerationManagerV1};
use leanbun_lake_bridge::LakeRuntimePackagesProjectionV1;
use leanbun_lock::PackagePathDecisionSetV1;
use leanbun_store::{LeanStoreLimitsV1, normalized_directory_tree_sha256_v1};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const MAX_BUILD_ARTIFACT_FILE_BYTES_V1: u64 = 1024 * 1024 * 1024;
const MAX_BUILD_ARTIFACT_TREE_BYTES_V1: u64 = 16 * 1024 * 1024 * 1024;
const MAX_BUILD_ARTIFACT_ENTRIES_V1: usize = 500_000;

/// Hashes project inputs while excluding Lake's controlled `.lake` output.
pub fn protected_project_input_sha256_v1(root: &Path) -> Result<Sha256, BuildError> {
    normalized_directory_tree_sha256_v1(root, LeanStoreLimitsV1::default()).map_err(|error| {
        BuildError::new(
            BuildErrorKind::InputDrift,
            format!("cannot hash protected project input: {error}"),
        )
    })
}

/// Hashes the complete controlled Lake artifact tree for publication/reuse.
pub fn project_artifact_sha256_v1(root: &Path) -> Result<Sha256, BuildError> {
    let root = root.canonicalize().map_err(|error| {
        artifact_error(format!(
            "cannot canonicalize project artifact tree {}: {error}",
            root.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(artifact_error("project artifact root is not a directory"));
    }
    let mut entries = Vec::new();
    collect_artifact_entries(&root, &root, &mut entries)?;
    entries.sort();
    if entries.len() > MAX_BUILD_ARTIFACT_ENTRIES_V1 {
        return Err(artifact_error("project artifact entry count exceeds limit"));
    }

    let mut total_bytes = 0_u64;
    let mut hasher = leanbun_core::Sha256Hasher::new();
    hasher.update(b"leanbun-build-artifact-tree-v1\0");
    for relative in entries {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            artifact_error(format!("cannot inspect artifact {relative}: {error}"))
        })?;
        hash_artifact_text(&mut hasher, &relative);
        if metadata.file_type().is_dir() {
            hasher.update(&[1]);
            continue;
        }
        if !metadata.file_type().is_file() {
            return Err(artifact_error(format!(
                "project artifact is a symlink or special file: {relative}"
            )));
        }
        if metadata.len() > MAX_BUILD_ARTIFACT_FILE_BYTES_V1 {
            return Err(artifact_error(format!(
                "project artifact file exceeds limit: {relative}"
            )));
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| artifact_error("project artifact byte count overflow"))?;
        if total_bytes > MAX_BUILD_ARTIFACT_TREE_BYTES_V1 {
            return Err(artifact_error("project artifact tree exceeds byte limit"));
        }
        hasher.update(&[2]);
        hasher.update(&(metadata.permissions().mode() & 0o111).to_be_bytes());
        hasher.update(&metadata.len().to_be_bytes());
        let mut file = File::open(&path)
            .map_err(|error| artifact_error(format!("cannot open artifact {relative}: {error}")))?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|error| {
                artifact_error(format!("cannot read artifact {relative}: {error}"))
            })?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let after = file.metadata().map_err(|error| {
            artifact_error(format!("cannot re-inspect artifact {relative}: {error}"))
        })?;
        if after.len() != metadata.len()
            || (after.permissions().mode() & 0o111) != (metadata.permissions().mode() & 0o111)
        {
            return Err(artifact_error(format!(
                "project artifact changed while hashing: {relative}"
            )));
        }
    }
    Ok(hasher.finalize())
}

fn collect_artifact_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<String>,
) -> Result<(), BuildError> {
    let directory = fs::read_dir(current).map_err(|error| {
        artifact_error(format!(
            "cannot enumerate artifact directory {}: {error}",
            current.display()
        ))
    })?;
    for entry in directory {
        let entry = entry
            .map_err(|error| artifact_error(format!("cannot read artifact entry: {error}")))?;
        let path = entry.path();
        let relative = artifact_relative(root, &path)?;
        let kind = entry.file_type().map_err(|error| {
            artifact_error(format!("cannot inspect artifact {relative}: {error}"))
        })?;
        entries.push(relative);
        if entries.len() > MAX_BUILD_ARTIFACT_ENTRIES_V1 {
            return Err(artifact_error("project artifact entry count exceeds limit"));
        }
        if kind.is_dir() {
            collect_artifact_entries(root, &path, entries)?;
        } else if !kind.is_file() {
            return Err(artifact_error(format!(
                "project artifact is a symlink or special file: {}",
                artifact_relative(root, &path)?
            )));
        }
    }
    Ok(())
}

fn artifact_relative(root: &Path, path: &Path) -> Result<String, BuildError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| artifact_error("project artifact path escaped its root"))?;
    relative
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| artifact_error("project artifact path is not UTF-8"))
}

fn hash_artifact_text(hasher: &mut leanbun_core::Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn artifact_error(message: impl Into<String>) -> BuildError {
    BuildError::new(BuildErrorKind::ArtifactDrift, message)
}

/// Proves that a Lean/Lake test uses a registered repository template and a
/// repository-owned isolated execution copy before any process is launched.
pub fn verify_registered_test_project_v1(
    repository: &Path,
    template: &Path,
    execution_copy: &Path,
) -> Result<(), BuildError> {
    let repository = repository
        .canonicalize()
        .map_err(|error| boundary_error(format!("cannot canonicalize test repository: {error}")))?;
    let template = template
        .canonicalize()
        .map_err(|error| boundary_error(format!("cannot canonicalize test template: {error}")))?;
    let execution_copy = execution_copy.canonicalize().map_err(|error| {
        boundary_error(format!("cannot canonicalize test execution copy: {error}"))
    })?;
    let registered = ["lake-basic", "lake-lean-config", "mathlib-project"]
        .map(|name| repository.join("test/fixtures").join(name));
    if !registered.iter().any(|path| path == &template) {
        return Err(boundary_error(
            "Lean/Lake test template is not registered in this repository",
        ));
    }
    let allowed_execution_roots = [
        repository.join(".leanbun-dev/tmp"),
        repository.join(".leanbun-dev-rust/test-tmp"),
        repository.join(".leanbun-dev-rust/generation-fixture"),
    ];
    if !allowed_execution_roots
        .iter()
        .any(|root| execution_copy.starts_with(root))
    {
        return Err(boundary_error(
            "Lean/Lake test execution copy escaped repository-owned state",
        ));
    }
    Ok(())
}

fn boundary_error(message: impl Into<String>) -> BuildError {
    BuildError::new(BuildErrorKind::BoundaryViolation, message)
}

/// M36's pre-build authority gate.  It re-verifies the M35 active record and
/// immutable bytes, then binds the supplied M31 decisions and M32 runtime
/// projection to that exact generation before Lake can be launched.
pub fn verify_active_generation_build_gate_v1(
    manager: &LeanGenerationManagerV1,
    generation: &LeanBunGenerationV1,
    decisions: &PackagePathDecisionSetV1,
    runtime: &LakeRuntimePackagesProjectionV1,
) -> Result<Vec<std::path::PathBuf>, BuildError> {
    manager
        .verify_active_generation(generation)
        .map_err(|error| {
            BuildError::new(
                BuildErrorKind::InputDrift,
                format!("active M35 generation failed reverification: {error}"),
            )
        })?;
    if decisions.digest() != generation.decision_set_sha256()
        || runtime.sha256() != generation.runtime_projection_sha256()
        || runtime.package_count() != decisions.decisions().len()
    {
        return Err(BuildError::new(
            BuildErrorKind::InputDrift,
            "M31 decisions or M32 runtime projection differ from active M35 generation",
        ));
    }
    let mut paths = Vec::with_capacity(decisions.decisions().len());
    for decision in decisions.decisions() {
        let path = std::path::PathBuf::from(decision.final_path());
        if !path.is_absolute() || !path.starts_with(generation.generation_root().join("packages")) {
            return Err(BuildError::new(
                BuildErrorKind::PathDrift,
                "Bun final package path escapes active generation",
            ));
        }
        paths.push(path);
    }
    Ok(paths)
}

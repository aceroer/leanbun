use super::{ManagedProjectError, TOOLCHAIN, boundary, input_error, validate_target};
use leanbun_core::{ProjectId, Sha256, project_id};
use leanbun_evidence::{
    ProjectInputState, canonicalize_directory, hash_project_input_tree, read_project_input,
    read_stable_text,
};
use leanbun_lake_bridge::{LakeRootProbeRequestV1, run_lake_root_probe_v1};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalAdoptionDryRunV1 {
    pub project_id: ProjectId,
    pub project_root: PathBuf,
    pub target: String,
    pub input_state: ProjectInputState,
    pub project_tree_sha256: Sha256,
    pub entry_count: u64,
    pub file_count: u64,
    pub byte_count: u64,
    pub config_file: String,
    pub config_sha256: Sha256,
    pub toolchain: String,
    pub toolchain_sha256: Sha256,
    pub manifest_sha256: Sha256,
    pub root_declaration_sha256: Sha256,
    pub direct_dependency_count: usize,
    pub manifest_package_count: usize,
}

impl ExternalAdoptionDryRunV1 {
    #[must_use]
    pub const fn input_state_name(&self) -> &'static str {
        match self.input_state {
            ProjectInputState::DependencyFree => "dependency-free",
            ProjectInputState::Standalone => "standalone",
            ProjectInputState::ProviderBound => "provider-bound",
        }
    }
}

pub fn dry_run_external_adoption_v1(
    repository: impl AsRef<Path>,
    project: impl AsRef<Path>,
    target: &str,
) -> Result<ExternalAdoptionDryRunV1, ManagedProjectError> {
    validate_target(target)?;
    let repository = canonicalize_directory(repository.as_ref()).map_err(evidence_error)?;
    if !repository
        .as_path()
        .join("TEST_PROJECT_BOUNDARY.adoc")
        .is_file()
        || !repository
            .as_path()
            .join("config/upstream-bun.lock.json")
            .is_file()
    {
        return Err(boundary("repository is not a LeanBun source root"));
    }
    let project = canonicalize_directory(project.as_ref()).map_err(evidence_error)?;
    let before = hash_project_input_tree(&project).map_err(evidence_error)?;
    let input = read_project_input(&project, None).map_err(evidence_error)?;
    if input.toolchain != TOOLCHAIN {
        return Err(input_error(
            "external candidate uses an unsupported Lean toolchain",
        ));
    }
    let config_file = select_config(project.as_path())?;
    let config =
        read_stable_text(&project, config_file, 4 * 1024 * 1024).map_err(evidence_error)?;

    let development = canonicalize_directory(repository.as_path().join(".leanbun-dev"))
        .map_err(evidence_error)?;
    let toolchain = development
        .as_path()
        .join("lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
    let staging_parent = development.as_path().join("tmp");
    let staging_parent = canonicalize_directory(&staging_parent).map_err(evidence_error)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| input_error(format!("system clock precedes epoch: {error}")))?
        .as_nanos();
    let staging = staging_parent.as_path().join(format!(
        "m41-adoption-dry-run-{}-{nonce}",
        std::process::id()
    ));
    let cleanup = Cleanup(staging.clone());
    let source_parent = project
        .as_path()
        .parent()
        .ok_or_else(|| boundary("external candidate has no parent"))?;
    let declaration = run_lake_root_probe_v1(&LakeRootProbeRequestV1 {
        source_fixture_root: source_parent.to_path_buf(),
        source_project: project.as_path().to_path_buf(),
        development_root: development.as_path().to_path_buf(),
        staging_directory: staging,
        lean_executable: toolchain.join("bin/lean"),
        elan_home: development.as_path().join("lean/elan-home"),
        sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
        sandbox_profile: repository.as_path().join("config/leanbun-dev.sb"),
        probe_source: repository
            .as_path()
            .join("lean/probes/M32RootDeclarations.lean"),
        lake_source_root: toolchain.join("src/lean/lake"),
    })
    .map_err(|error| input_error(format!("external candidate Lake probe failed: {error}")))?;
    drop(cleanup);

    if declaration.config_file() != config_file {
        return Err(input_error("external candidate config selection drifted"));
    }
    let after = hash_project_input_tree(&project).map_err(evidence_error)?;
    if before != after {
        return Err(input_error("external candidate changed during dry-run"));
    }
    let project_text = project
        .as_path()
        .to_str()
        .ok_or_else(|| boundary("external candidate path is not UTF-8"))?;
    Ok(ExternalAdoptionDryRunV1 {
        project_id: project_id(project_text),
        project_root: project.as_path().to_path_buf(),
        target: target.to_owned(),
        input_state: input.state,
        project_tree_sha256: before.tree_hash,
        entry_count: before.entry_count,
        file_count: before.file_count,
        byte_count: before.byte_count,
        config_file: config_file.to_owned(),
        config_sha256: config.sha256,
        toolchain: input.toolchain,
        toolchain_sha256: input.toolchain_file.sha256,
        manifest_sha256: input.manifest.file.sha256,
        root_declaration_sha256: declaration.identity(),
        direct_dependency_count: declaration.dependencies().len(),
        manifest_package_count: input.manifest.manifest.packages.len(),
    })
}

fn select_config(project: &Path) -> Result<&'static str, ManagedProjectError> {
    match (
        project.join("lakefile.toml").is_file(),
        project.join("lakefile.lean").is_file(),
    ) {
        (true, false) => Ok("lakefile.toml"),
        (false, true) => Ok("lakefile.lean"),
        _ => Err(boundary(
            "external candidate must contain exactly one Lake config",
        )),
    }
}

fn evidence_error(error: leanbun_evidence::EvidenceError) -> ManagedProjectError {
    input_error(format!("external candidate evidence rejected: {error}"))
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

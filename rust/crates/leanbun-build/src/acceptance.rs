use crate::{
    BuildError, BuildErrorKind, BuildImageStoreV1, BuildImageV1, BuildInputsV1, ReuseOutcomeV1,
    SupervisedLakeBuildV1, project_artifact_sha256_v1, run_supervised_lake_build_v1,
    verify_active_generation_build_gate_v1, verify_lake_workspace_paths_v1,
    verify_registered_test_project_v1,
};
use leanbun_core::{ExecutionId, Sha256, Sha256Hasher};
use leanbun_generation::{
    LeanBunGenerationV1, LeanGenerationFaultV1, LeanGenerationManagerV1, LeanGenerationStateV1,
};
use leanbun_lake_bridge::{
    LakeManifestProjectionV1, LakeRootDeclarationV1, LakeRuntimePackagesProjectionV1,
};
use leanbun_lock::{LeanBunLockV1, PackagePathDecisionSetV1};
use leanbun_resolver::{
    LeanResolutionModeV1, LeanResolutionRequestV1, LeanToolchainIdentityV1,
    resolve_lean_dependencies_v1,
};
use leanbun_store::{LeanStoreLimitsV1, normalized_directory_tree_sha256_v1};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const TOOLCHAIN: &str = "leanprover/lean4:v4.32.0";
const COMPILER: &str = "8c9756b28d64dab099da31a4c09229a9e6a2ef35";
const LAKE_VERSION: &str = "5.0.0-src+8c9756b";
const TARGET: &str = "leanbun_lake_fixture";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryFixtureAcceptanceV1 {
    pub baseline_generation_sha256: Sha256,
    pub candidate_generation_sha256: Sha256,
    pub build_image_sha256: Sha256,
    pub project_artifact_sha256: Sha256,
}

/// Runs the M37 transaction/build/failure/reuse/rollback closure through the
/// supplied final supervisor executable. Only the registered `lake-basic`
/// template and a repository-owned execution copy are accepted.
pub fn run_repository_fixture_acceptance_v1(
    repository: &Path,
    supervisor_executable: &Path,
) -> Result<RepositoryFixtureAcceptanceV1, BuildError> {
    let root = repository.join(".leanbun-dev-rust/generation-fixture/m37-acceptance/lake-basic");
    run_repository_fixture_acceptance_at_v1(repository, supervisor_executable, &root)
}

pub(crate) fn run_repository_fixture_acceptance_at_v1(
    repository: &Path,
    supervisor_executable: &Path,
    root: &Path,
) -> Result<RepositoryFixtureAcceptanceV1, BuildError> {
    let repository = repository
        .canonicalize()
        .map_err(|error| failed(format!("cannot canonicalize repository: {error}")))?;
    let supervisor_executable = supervisor_executable
        .canonicalize()
        .map_err(|error| failed(format!("cannot canonicalize supervisor: {error}")))?;
    let development = repository.join(".leanbun-dev-rust");
    let template = repository
        .join("test/fixtures/lake-basic")
        .canonicalize()
        .map_err(|error| failed(format!("registered template missing: {error}")))?;
    let root = root.to_path_buf();
    if !root.starts_with(development.join("generation-fixture")) {
        return Err(failed("fixture acceptance root escaped generation-fixture"));
    }
    if root.exists() {
        return Err(failed("acceptance execution root already exists"));
    }
    fs::create_dir_all(&root).map_err(io_failed)?;
    let cleanup = Cleanup(root.clone());
    let project = root.join("project");
    let state = root.join("state");
    fs::create_dir(&project).map_err(io_failed)?;
    fs::create_dir(&state).map_err(io_failed)?;
    copy_tree(&template, &project)?;
    let project = project
        .canonicalize()
        .map_err(|error| failed(format!("cannot canonicalize execution copy: {error}")))?;
    verify_registered_test_project_v1(&repository, &template, &project)?;

    let template_before =
        normalized_directory_tree_sha256_v1(&template, LeanStoreLimitsV1::default())
            .map_err(|error| failed(format!("cannot hash fixture template: {error}")))?;
    let input_before = fixture_input_digest(&project)?;
    let declaration =
        LakeRootDeclarationV1::new("leanbun_lake_fixture", "lakefile.toml", Vec::new())
            .map_err(|error| failed(error.to_string()))?;
    let lock = LeanBunLockV1::new(
        TOOLCHAIN,
        COMPILER,
        LAKE_VERSION,
        hash_file(&project.join("lakefile.toml"))?,
        declaration.identity(),
        Vec::new(),
    )
    .map_err(|error| failed(error.to_string()))?;
    let resolution = LeanResolutionRequestV1::new(
        declaration.clone(),
        None,
        LeanResolutionModeV1::update(Vec::new()).map_err(|error| failed(error.to_string()))?,
        LeanToolchainIdentityV1::new(TOOLCHAIN, COMPILER, LAKE_VERSION)
            .map_err(|error| failed(error.to_string()))?,
    )
    .map_err(|error| failed(error.to_string()))?;
    let graph = resolve_lean_dependencies_v1(&resolution, Vec::new())
        .map_err(|error| failed(error.to_string()))?;
    let decisions = PackagePathDecisionSetV1::new(&lock, Vec::new())
        .map_err(|error| failed(error.to_string()))?;
    let manifest = LakeManifestProjectionV1::new(&declaration, &lock, Vec::new())
        .map_err(|error| failed(error.to_string()))?;
    let runtime =
        LakeRuntimePackagesProjectionV1::from_bun_decisions(&lock, &decisions, Vec::new())
            .map_err(|error| failed(error.to_string()))?;
    let manager = LeanGenerationManagerV1::open(&development, &state, &project)
        .map_err(|error| failed(error.to_string()))?;

    let baseline = generation(
        &manager,
        "37000000-0000-4000-8000-000000000001",
        &lock,
        &graph,
        &decisions,
        &manifest,
        &runtime,
    )?;
    manager
        .publish(&baseline, LeanGenerationFaultV1::None)
        .map_err(|error| failed(error.to_string()))?;
    let injected = generation(
        &manager,
        "37000000-0000-4000-8000-000000000002",
        &lock,
        &graph,
        &decisions,
        &manifest,
        &runtime,
    )?;
    if manager
        .publish(&injected, LeanGenerationFaultV1::BeforeActiveRename)
        .is_ok()
    {
        return Err(failed(
            "injected publication failure unexpectedly succeeded",
        ));
    }
    if manager
        .active_generation_identity()
        .map_err(|error| failed(error.to_string()))?
        != Some(baseline.identity())
    {
        return Err(failed("failed publication changed the active generation"));
    }
    let recovered = manager
        .recover(&injected)
        .map_err(|error| failed(error.to_string()))?;
    if recovered.state() != LeanGenerationStateV1::Failed || recovered.is_active() {
        return Err(failed(
            "failed transaction recovery did not terminate safely",
        ));
    }

    let candidate = generation(
        &manager,
        "37000000-0000-4000-8000-000000000003",
        &lock,
        &graph,
        &decisions,
        &manifest,
        &runtime,
    )?;
    manager
        .publish(&candidate, LeanGenerationFaultV1::None)
        .map_err(|error| failed(error.to_string()))?;
    let paths = verify_active_generation_build_gate_v1(&manager, &candidate, &decisions, &runtime)?;
    if !paths.is_empty() {
        return Err(failed("empty fixture unexpectedly resolved dependencies"));
    }

    let toolchain =
        repository.join(".leanbun-dev/lean/elan-home/toolchains/leanprover--lean4---v4.32.0");
    let lake = toolchain
        .join("bin/lake")
        .canonicalize()
        .map_err(|error| failed(format!("locked Lake executable missing: {error}")))?;
    let profile = root.join("m37.sb");
    fs::write(
        &profile,
        format!(
            "(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n(allow file-write* (subpath {:?}) (literal \"/dev/null\") (literal \"/dev/stdout\") (literal \"/dev/stderr\"))\n",
            project.to_string_lossy()
        ),
    )
    .map_err(io_failed)?;
    let request = build_request(
        &project,
        &candidate.generation_root().join("runtime-packages.json"),
        &lake,
        &toolchain,
        &profile,
        &supervisor_executable,
    )?;
    verify_lake_workspace_paths_v1(&request, &paths)?;
    let mut missing = request.clone();
    missing.target = "LeanBunIntentionalMissingTarget".to_owned();
    missing.allowed_targets.insert(missing.target.clone());
    if run_supervised_lake_build_v1(&missing).map_err(|error| error.kind)
        != Err(BuildErrorKind::LakeNonzero)
    {
        return Err(failed("intentional missing target did not fail closed"));
    }
    if manager
        .active_generation_identity()
        .map_err(|error| failed(error.to_string()))?
        != Some(candidate.identity())
    {
        return Err(failed("Lake failure changed the active generation"));
    }

    let first = run_supervised_lake_build_v1(&request)?;
    let artifact_first = project_artifact_sha256_v1(&project.join(".lake/build"))?;
    let second = run_supervised_lake_build_v1(&request)?;
    let artifact_second = project_artifact_sha256_v1(&project.join(".lake/build"))?;
    if artifact_first != artifact_second || first.process_group_id == second.process_group_id {
        return Err(failed(
            "repeat build was not stable and independently supervised",
        ));
    }
    if fixture_input_digest(&project)? != input_before {
        return Err(failed("fixture source changed during acceptance"));
    }
    let template_after =
        normalized_directory_tree_sha256_v1(&template, LeanStoreLimitsV1::default())
            .map_err(|error| failed(format!("cannot rehash fixture template: {error}")))?;
    if template_after != template_before {
        return Err(failed(
            "registered fixture template changed during acceptance",
        ));
    }

    let image_root = root.join("images");
    fs::create_dir(&image_root).map_err(io_failed)?;
    let dependency_artifact = image_root.join("empty-dependency-image");
    fs::write(&dependency_artifact, []).map_err(io_failed)?;
    let image = BuildImageV1::new(
        BuildInputsV1::from_active_generation(
            &candidate,
            hash_file(&project.join("lakefile.toml"))?,
            TARGET,
        ),
        hash_file(&dependency_artifact)?,
    )?;
    let images = BuildImageStoreV1::open(&image_root)?;
    if images.publish_or_reuse(&image, &dependency_artifact) != Ok(ReuseOutcomeV1::Published)
        || images.publish_or_reuse(&image, &dependency_artifact) != Ok(ReuseOutcomeV1::Reused)
    {
        return Err(failed(
            "build image did not publish and reuse deterministically",
        ));
    }
    images.verify(&image)?;
    manager
        .rollback_active_generation(&candidate, &baseline)
        .map_err(|error| failed(error.to_string()))?;
    manager
        .verify_active_generation(&baseline)
        .map_err(|error| failed(error.to_string()))?;
    if !candidate.generation_root().is_dir() {
        return Err(failed("rollback deleted retained candidate evidence"));
    }

    let report = RepositoryFixtureAcceptanceV1 {
        baseline_generation_sha256: baseline.identity(),
        candidate_generation_sha256: candidate.identity(),
        build_image_sha256: image.key(),
        project_artifact_sha256: artifact_second,
    };
    drop(cleanup);
    Ok(report)
}

fn generation(
    manager: &LeanGenerationManagerV1,
    transaction: &str,
    lock: &LeanBunLockV1,
    graph: &leanbun_resolver::LeanResolutionGraphV1,
    decisions: &PackagePathDecisionSetV1,
    manifest: &LakeManifestProjectionV1,
    runtime: &LakeRuntimePackagesProjectionV1,
) -> Result<LeanBunGenerationV1, BuildError> {
    let transaction = ExecutionId::parse(transaction).map_err(|error| failed(error.to_string()))?;
    LeanBunGenerationV1::new(
        transaction,
        manager.project_root(),
        manager.generation_root(transaction),
        lock,
        graph,
        decisions,
        manifest,
        runtime,
        Vec::new(),
    )
    .map_err(|error| failed(error.to_string()))
}

fn build_request(
    project: &Path,
    runtime: &Path,
    lake: &Path,
    toolchain: &Path,
    profile: &Path,
    supervisor: &Path,
) -> Result<SupervisedLakeBuildV1, BuildError> {
    Ok(SupervisedLakeBuildV1 {
        supervisor_executable: supervisor.to_path_buf(),
        sandbox_executable: PathBuf::from("/usr/bin/sandbox-exec"),
        sandbox_profile: profile.to_path_buf(),
        sandbox_profile_sha256: hash_file(profile)?,
        lake_executable: lake.to_path_buf(),
        lake_executable_sha256: hash_file(lake)?,
        cwd: project.to_path_buf(),
        runtime_packages: runtime.to_path_buf(),
        target: TARGET.to_owned(),
        allowed_targets: BTreeSet::from([TARGET.to_owned()]),
        environment: BTreeMap::from([
            (
                "PATH".to_owned(),
                format!(
                    "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                    toolchain.join("bin").display()
                ),
            ),
            ("HOME".to_owned(), project.to_string_lossy().into_owned()),
            ("TMPDIR".to_owned(), project.to_string_lossy().into_owned()),
            (
                "LEAN_SYSROOT".to_owned(),
                toolchain.to_string_lossy().into_owned(),
            ),
            (
                "DYLD_LIBRARY_PATH".to_owned(),
                toolchain.join("lib/lean").to_string_lossy().into_owned(),
            ),
            ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
            ("DO_NOT_TRACK".to_owned(), "1".to_owned()),
            ("LAKE_NO_CACHE".to_owned(), "1".to_owned()),
            ("LAKE_ARTIFACT_CACHE".to_owned(), "0".to_owned()),
        ]),
        deadline: Duration::from_secs(120),
        termination_grace: Duration::from_secs(1),
        maximum_output_bytes: 16 * 1024 * 1024,
    })
}

fn fixture_input_digest(project: &Path) -> Result<Sha256, BuildError> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-m37-lake-basic-input-v1\0");
    for relative in [
        "LeanBunLakeFixture.lean",
        "LeanBunLakeFixture/Basic.lean",
        "Main.lean",
        "lake-manifest.json",
        "lakefile.toml",
        "lean-toolchain",
    ] {
        hasher.update(&(relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(hash_file(&project.join(relative))?.as_bytes());
    }
    Ok(hasher.finalize())
}

fn hash_file(path: &Path) -> Result<Sha256, BuildError> {
    let bytes = fs::read(path).map_err(io_failed)?;
    let mut hasher = Sha256Hasher::new();
    hasher.update(&bytes);
    Ok(hasher.finalize())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), BuildError> {
    for entry in fs::read_dir(source).map_err(io_failed)? {
        let entry = entry.map_err(io_failed)?;
        let kind = entry.file_type().map_err(io_failed)?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&target).map_err(io_failed)?;
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target).map_err(io_failed)?;
        } else {
            return Err(failed(
                "registered fixture contains a symlink or special file",
            ));
        }
    }
    Ok(())
}

fn failed(message: impl Into<String>) -> BuildError {
    BuildError::new(BuildErrorKind::InputDrift, message)
}

fn io_failed(error: std::io::Error) -> BuildError {
    BuildError::new(
        BuildErrorKind::Io,
        format!("fixture acceptance I/O failed: {error}"),
    )
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        make_writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_writable(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_writable(&entry.path());
            }
        }
    } else if metadata.file_type().is_file() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

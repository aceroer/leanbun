use super::{
    ManagedProjectControllerV1, ManagedProjectError, ensure_private_directory, input_error,
    io_error, sync_directory,
};
use crate::dry_run_external_adoption_v1;
use crate::external_acceptance::{copy_tree, publish_immutable_record};
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_evidence::{canonicalize_directory, hash_project_input_tree};
use leanbun_generation::LeanGenerationFaultV1;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static RUN_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct RegressionSpec {
    fixture: &'static str,
    target: &'static str,
    update_package: &'static str,
    expected_package_count: usize,
    forbidden_source_cache: Option<&'static str>,
}

const MANAGED_DEPENDENCY: RegressionSpec = RegressionSpec {
    fixture: "lake-managed-dependency",
    target: "leanbun_managed_dependency_fixture",
    update_package: "managed_dep",
    expected_package_count: 1,
    forbidden_source_cache: Some("vendor/managed_dep/.lake"),
};

const MATHLIB_PROJECT: RegressionSpec = RegressionSpec {
    fixture: "mathlib-project",
    target: "LeanBunMathlibFixture",
    update_package: "mathlib",
    expected_package_count: 9,
    forbidden_source_cache: None,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedDependencyRegressionV1 {
    pub run_id: Sha256,
    pub fixture: &'static str,
    pub explicit_update_package: &'static str,
    pub package_count: usize,
    pub record: PathBuf,
    pub record_sha256: Sha256,
    pub project_id: leanbun_core::ProjectId,
    pub baseline_generation_sha256: Sha256,
    pub updated_generation_sha256: Sha256,
    pub rollback_generation_sha256: Sha256,
    pub project_artifact_sha256: Sha256,
}

pub fn run_managed_dependency_regression_v1(
    repository: &Path,
    supervisor: &Path,
) -> Result<ManagedDependencyRegressionV1, ManagedProjectError> {
    run_managed_fixture_regression_v1(repository, supervisor, MANAGED_DEPENDENCY)
}

pub fn run_mathlib_regression_v1(
    repository: &Path,
    supervisor: &Path,
) -> Result<ManagedDependencyRegressionV1, ManagedProjectError> {
    run_managed_fixture_regression_v1(repository, supervisor, MATHLIB_PROJECT)
}

fn run_managed_fixture_regression_v1(
    repository: &Path,
    supervisor: &Path,
    spec: RegressionSpec,
) -> Result<ManagedDependencyRegressionV1, ManagedProjectError> {
    let repository = canonicalize_directory(repository).map_err(evidence_error)?;
    let supervisor = supervisor.canonicalize().map_err(|error| {
        input_error(format!(
            "cannot canonicalize managed regression supervisor: {error}"
        ))
    })?;
    let template = canonicalize_directory(
        repository
            .as_path()
            .join("test/fixtures")
            .join(spec.fixture),
    )
    .map_err(evidence_error)?;
    let template_tree = hash_project_input_tree(&template).map_err(evidence_error)?;
    let development = repository.as_path().join(".leanbun-dev-rust");
    let records = development.join("regression/records");
    let runs = development.join("managed-fixture/m42-regression/runs");
    ensure_private_directory(&development, &records)?;
    ensure_private_directory(&development, &runs)?;

    let run_id = allocate_run_id(repository.as_path(), &records, &runs, spec.fixture)?;
    let run_root = runs.join(run_id.to_string());
    fs::create_dir(&run_root).map_err(io_error)?;
    let mut cleanup = RegressionCleanup::new(run_root.clone());
    let project = run_root.join("project");
    fs::create_dir(&project).map_err(io_error)?;
    copy_tree(template.as_path(), &project)?;
    let project = project.canonicalize().map_err(|error| {
        input_error(format!(
            "cannot canonicalize managed regression project: {error}"
        ))
    })?;
    let copied = canonicalize_directory(&project).map_err(evidence_error)?;
    if hash_project_input_tree(&copied).map_err(evidence_error)? != template_tree {
        return Err(input_error(
            "managed regression copy differs from registered template",
        ));
    }

    let dry_run = dry_run_external_adoption_v1(repository.as_path(), &project, spec.target)?;
    let authority = development.join("managed-projects");
    let project_id = dry_run.project_id;
    let state_paths = [
        authority
            .join("registry")
            .join(format!("{project_id}.record")),
        authority
            .join("generation-state/projects")
            .join(project_id.to_string()),
        authority
            .join("project-control")
            .join(project_id.to_string()),
        development
            .join("store-fixture/m40-managed")
            .join(project_id.to_string()),
    ];
    if state_paths.iter().any(|path| path.exists()) {
        return Err(input_error(
            "managed regression project identity already has controller state",
        ));
    }
    cleanup.extend(state_paths.iter().cloned());

    let controller = ManagedProjectControllerV1::open(repository.as_path(), &project, &supervisor)?;
    let adopted = controller.adopt(spec.target)?;
    if adopted.package_count != spec.expected_package_count {
        return Err(input_error(
            "managed regression adopted an unexpected package count",
        ));
    }
    let baseline_build = controller.build()?;
    let updated = controller.update_packages(&[spec.update_package.to_owned()])?;
    if updated.package_count != spec.expected_package_count {
        return Err(input_error(
            "managed regression update changed the package count",
        ));
    }
    let updated_build = controller.build()?;
    if controller
        .update_with_fault(LeanGenerationFaultV1::BeforeActiveRename)
        .is_ok()
    {
        return Err(input_error(
            "managed regression fault injection unexpectedly succeeded",
        ));
    }
    let pending = controller.status()?;
    if pending.pending_transaction.is_none()
        || pending.active_transaction != updated.active_transaction
    {
        return Err(input_error(
            "managed regression fault changed active update state",
        ));
    }
    let recovered = controller.recover()?;
    if recovered.active_transaction != updated.active_transaction
        || recovered.pending_transaction.is_some()
    {
        return Err(input_error(
            "managed regression recovery did not restore updated state",
        ));
    }
    let rolled_back = controller.rollback()?;
    let rollback_build = controller.build()?;
    if rolled_back.active_transaction != adopted.active_transaction
        || baseline_build.project_artifact_sha256 != updated_build.project_artifact_sha256
        || baseline_build.project_artifact_sha256 != rollback_build.project_artifact_sha256
    {
        return Err(input_error(
            "managed regression did not form a reproducible rollback closure",
        ));
    }
    if hash_project_input_tree(&copied).map_err(evidence_error)? != template_tree
        || spec
            .forbidden_source_cache
            .is_some_and(|relative| project.join(relative).exists())
    {
        return Err(input_error(
            "managed regression changed registered source inputs",
        ));
    }
    let generation_state = &state_paths[1];
    if contains_active_temp(generation_state)? {
        return Err(input_error(
            "managed regression recovery left an active temporary record",
        ));
    }

    let bytes = record_bytes(
        run_id,
        project_id,
        adopted.active_transaction.as_str(),
        updated.active_transaction.as_str(),
        baseline_build.generation_sha256,
        updated_build.generation_sha256,
        rollback_build.generation_sha256,
        baseline_build.project_artifact_sha256,
        template_tree.tree_hash,
        spec,
    );
    cleanup.clean()?;
    if run_root.exists() || state_paths.iter().any(|path| path.exists()) {
        return Err(input_error(
            "managed regression did not clean all project-scoped state",
        ));
    }
    let record = records.join(format!("{run_id}.record"));
    let record_sha256 = hash_bytes(&bytes);
    publish_immutable_record(&record, &bytes)?;
    publish_latest(
        &development.join("regression/latest.record"),
        run_id,
        record_sha256,
        spec.fixture,
    )?;
    Ok(ManagedDependencyRegressionV1 {
        run_id,
        fixture: spec.fixture,
        explicit_update_package: spec.update_package,
        package_count: spec.expected_package_count,
        record,
        record_sha256,
        project_id,
        baseline_generation_sha256: baseline_build.generation_sha256,
        updated_generation_sha256: updated_build.generation_sha256,
        rollback_generation_sha256: rollback_build.generation_sha256,
        project_artifact_sha256: baseline_build.project_artifact_sha256,
    })
}

fn allocate_run_id(
    repository: &Path,
    records: &Path,
    runs: &Path,
    fixture: &str,
) -> Result<Sha256, ManagedProjectError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| input_error(format!("system clock precedes epoch: {error}")))?;
    for _ in 0..32 {
        let nonce = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-managed-fixture-regression-run-v1\0");
        hasher.update(repository.to_string_lossy().as_bytes());
        hasher.update(&(fixture.len() as u64).to_be_bytes());
        hasher.update(fixture.as_bytes());
        hasher.update(&now.as_nanos().to_be_bytes());
        hasher.update(&std::process::id().to_be_bytes());
        hasher.update(&nonce.to_be_bytes());
        let candidate = hasher.finalize();
        if !records.join(format!("{candidate}.record")).exists()
            && !runs.join(candidate.to_string()).exists()
        {
            return Ok(candidate);
        }
    }
    Err(input_error(
        "cannot allocate a unique managed regression run id",
    ))
}

#[allow(clippy::too_many_arguments)]
fn record_bytes(
    run_id: Sha256,
    project_id: leanbun_core::ProjectId,
    baseline_transaction: &str,
    updated_transaction: &str,
    baseline_generation: Sha256,
    updated_generation: Sha256,
    rollback_generation: Sha256,
    artifact: Sha256,
    template_tree: Sha256,
    spec: RegressionSpec,
) -> Vec<u8> {
    format!(
        "leanbun-fixture-regression-v1\t1\nrun-id\t{run_id}\nfixture\t{}\nstatus\tpassed\nproject-id\t{project_id}\ntemplate-tree-sha256\t{template_tree}\npackage-count\t{}\nbaseline-transaction\t{baseline_transaction}\nupdated-transaction\t{updated_transaction}\nbaseline-generation-sha256\t{baseline_generation}\nupdated-generation-sha256\t{updated_generation}\nrollback-generation-sha256\t{rollback_generation}\nproject-artifact-sha256\t{artifact}\nexplicit-update-package\t{}\nfault-recovery\tpassed\nexecution-copy\tcleaned\nproject-controller-state\tcleaned\nproject-local-store\tcleaned\nregistered-template\tunchanged\nend-fixture-regression\n",
        spec.fixture, spec.expected_package_count, spec.update_package,
    )
    .into_bytes()
}

fn publish_latest(
    path: &Path,
    run_id: Sha256,
    record_sha256: Sha256,
    fixture: &str,
) -> Result<(), ManagedProjectError> {
    let bytes = format!(
        "leanbun-fixture-regression-latest-v1\t1\nrun-id\t{run_id}\nfixture\t{fixture}\nrecord-sha256\t{record_sha256}\nend-fixture-regression-latest\n"
    )
    .into_bytes();
    let parent = path
        .parent()
        .ok_or_else(|| input_error("regression latest record has no parent"))?;
    let temp = parent.join(format!(
        ".latest-managed-{}-{}.next",
        std::process::id(),
        RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    super::create_bytes(&temp, &bytes)?;
    fs::rename(&temp, path).map_err(io_error)?;
    sync_directory(parent)?;
    if fs::read(path).map_err(io_error)? != bytes {
        return Err(input_error("managed regression latest pointer changed"));
    }
    Ok(())
}

fn contains_active_temp(root: &Path) -> Result<bool, ManagedProjectError> {
    for entry in fs::read_dir(root).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".active-") && name.ends_with(".tmp"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn hash_bytes(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

struct RegressionCleanup {
    paths: Vec<PathBuf>,
    armed: bool,
}

impl RegressionCleanup {
    fn new(run_root: PathBuf) -> Self {
        Self {
            paths: vec![run_root],
            armed: true,
        }
    }

    fn extend(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        self.paths.extend(paths);
    }

    fn clean(&mut self) -> Result<(), ManagedProjectError> {
        for path in &self.paths {
            remove_exact_tree(path)?;
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for RegressionCleanup {
    fn drop(&mut self) {
        if self.armed {
            for path in &self.paths {
                let _ = remove_exact_tree(path);
            }
        }
    }
}

pub(super) fn remove_exact_tree(path: &Path) -> Result<(), ManagedProjectError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_dir() {
        make_writable(path)?;
        fs::remove_dir_all(path).map_err(io_error)?;
    } else if metadata.file_type().is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
        fs::remove_file(path).map_err(io_error)?;
    } else {
        return Err(input_error(
            "managed regression cleanup target is a link or special file",
        ));
    }
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn make_writable(path: &Path) -> Result<(), ManagedProjectError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        for entry in fs::read_dir(path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            make_writable(&entry.path())?;
        }
    } else if metadata.file_type().is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    } else {
        return Err(input_error(
            "managed regression state contains a link or special file",
        ));
    }
    Ok(())
}

fn evidence_error(error: leanbun_evidence::EvidenceError) -> ManagedProjectError {
    input_error(format!("managed regression evidence rejected: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_regression_record_binds_update_recovery_and_cleanup() {
        let digest = |digit: char| {
            Sha256::parse(&digit.to_string().repeat(64))
                .unwrap_or_else(|error| panic!("digest failed: {error}"))
        };
        let project = leanbun_core::ProjectId::from_digest(digest('2'));
        let record = record_bytes(
            digest('1'),
            project,
            "10000000-0000-4000-8000-000000000001",
            "20000000-0000-4000-8000-000000000002",
            digest('3'),
            digest('4'),
            digest('3'),
            digest('5'),
            digest('6'),
            MANAGED_DEPENDENCY,
        );
        let text = String::from_utf8(record).unwrap_or_else(|error| panic!("{error}"));
        assert!(text.contains("fixture\tlake-managed-dependency\n"));
        assert!(text.contains("explicit-update-package\tmanaged_dep\n"));
        assert!(text.contains("package-count\t1\n"));
        assert!(text.contains("fault-recovery\tpassed\n"));
        assert!(text.contains("project-controller-state\tcleaned\n"));
        assert!(text.ends_with("end-fixture-regression\n"));
    }
}

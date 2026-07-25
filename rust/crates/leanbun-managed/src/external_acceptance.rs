use super::{
    ManagedProjectControllerV1, ManagedProjectError, create_bytes, ensure_private_directory,
    input_error, io_error, path_text, stable_read, sync_directory,
};
use crate::{ExternalAdoptionDryRunV1, dry_run_external_adoption_v1};
use leanbun_core::Sha256;
use leanbun_evidence::{canonicalize_directory, hash_project_input_tree};
use leanbun_generation::LeanGenerationFaultV1;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const TARGET: &str = "leanbun_managed_dependency_fixture";
const PACKAGE: &str = "managed_dep";
const MAX_ACCEPTANCE_RECORD_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalFixtureAcceptanceV1 {
    pub dry_run: ExternalAdoptionDryRunV1,
    pub dry_run_record: PathBuf,
    pub acceptance_record: PathBuf,
    pub baseline_generation_sha256: Sha256,
    pub updated_generation_sha256: Sha256,
    pub rollback_generation_sha256: Sha256,
    pub project_artifact_sha256: Sha256,
}

pub fn run_external_fixture_acceptance_v1(
    repository: &Path,
    supervisor: &Path,
) -> Result<ExternalFixtureAcceptanceV1, ManagedProjectError> {
    let repository = canonicalize_directory(repository).map_err(evidence_error)?;
    let supervisor = supervisor
        .canonicalize()
        .map_err(|error| input_error(format!("cannot canonicalize M41 supervisor: {error}")))?;
    let template = canonicalize_directory(
        repository
            .as_path()
            .join("test/fixtures/lake-managed-dependency"),
    )
    .map_err(evidence_error)?;
    let template_tree = hash_project_input_tree(&template).map_err(evidence_error)?;

    let development = repository.as_path().join(".leanbun-dev-rust");
    let fixture_parent = development.join("external-acceptance-fixture");
    ensure_private_directory(&development, &fixture_parent)?;
    let project = fixture_parent.join("m41-small-project");
    if project.exists() {
        return Err(input_error(
            "M41 external acceptance fixture already exists",
        ));
    }
    fs::create_dir(&project).map_err(io_error)?;
    copy_tree(template.as_path(), &project)?;
    let project = project
        .canonicalize()
        .map_err(|error| input_error(format!("cannot canonicalize M41 project copy: {error}")))?;
    let copied_root = canonicalize_directory(&project).map_err(evidence_error)?;
    if hash_project_input_tree(&copied_root).map_err(evidence_error)? != template_tree {
        return Err(input_error(
            "M41 candidate copy differs from registered template",
        ));
    }

    let dry_run = dry_run_external_adoption_v1(repository.as_path(), &project, TARGET)?;
    let records = development.join("external-acceptance/records");
    ensure_private_directory(&development, &records)?;
    let dry_run_record = records.join(format!("{}.dry-run.record", dry_run.project_id));
    let acceptance_record = records.join(format!("{}.acceptance.record", dry_run.project_id));
    if dry_run_record.exists() || acceptance_record.exists() {
        return Err(input_error("M41 external acceptance record already exists"));
    }
    let dry_bytes = dry_run_record_bytes(&dry_run)?;
    publish_immutable_record(&dry_run_record, &dry_bytes)?;

    let controller = ManagedProjectControllerV1::open(repository.as_path(), &project, &supervisor)?;
    let adopted = controller.adopt(TARGET)?;
    let baseline_build = controller.build()?;
    let updated = controller.update_packages(&[PACKAGE.to_owned()])?;
    let updated_build = controller.build()?;
    if controller
        .update_with_fault(LeanGenerationFaultV1::BeforeActiveRename)
        .is_ok()
    {
        return Err(input_error("M41 fault injection unexpectedly succeeded"));
    }
    let pending = controller.status()?;
    if pending.pending_transaction.is_none()
        || pending.active_transaction != updated.active_transaction
    {
        return Err(input_error(
            "M41 fault did not preserve active update state",
        ));
    }
    let recovered = controller.recover()?;
    if recovered.active_transaction != updated.active_transaction
        || recovered.pending_transaction.is_some()
    {
        return Err(input_error(
            "M41 recovery did not restore updated generation",
        ));
    }
    let rolled_back = controller.rollback()?;
    let rollback_build = controller.build()?;
    if rolled_back.active_transaction != adopted.active_transaction
        || baseline_build.project_artifact_sha256 != updated_build.project_artifact_sha256
        || baseline_build.project_artifact_sha256 != rollback_build.project_artifact_sha256
    {
        return Err(input_error(
            "M41 acceptance generations do not form a reproducible rollback closure",
        ));
    }
    if hash_project_input_tree(&copied_root).map_err(evidence_error)? != template_tree
        || project.join("vendor/managed_dep/.lake").exists()
    {
        return Err(input_error(
            "M41 acceptance changed candidate source inputs",
        ));
    }

    let acceptance_bytes = acceptance_record_bytes(
        &dry_run,
        adopted.active_transaction.as_str(),
        updated.active_transaction.as_str(),
        baseline_build.generation_sha256,
        updated_build.generation_sha256,
        rollback_build.generation_sha256,
        baseline_build.project_artifact_sha256,
    )?;
    publish_immutable_record(&acceptance_record, &acceptance_bytes)?;
    Ok(ExternalFixtureAcceptanceV1 {
        dry_run,
        dry_run_record,
        acceptance_record,
        baseline_generation_sha256: baseline_build.generation_sha256,
        updated_generation_sha256: updated_build.generation_sha256,
        rollback_generation_sha256: rollback_build.generation_sha256,
        project_artifact_sha256: baseline_build.project_artifact_sha256,
    })
}

fn dry_run_record_bytes(report: &ExternalAdoptionDryRunV1) -> Result<Vec<u8>, ManagedProjectError> {
    Ok(format!(
        "leanbun-external-dry-run-v1\t1\nproject-id\t{}\nproject-root\t{}\ntarget\t{}\nstatus\teligible-not-adopted\ninput-state\t{}\nproject-tree-sha256\t{}\nentry-count\t{}\nfile-count\t{}\nbyte-count\t{}\nconfig-file\t{}\nconfig-sha256\t{}\ntoolchain\t{}\ntoolchain-sha256\t{}\nmanifest-sha256\t{}\nroot-declaration-sha256\t{}\ndirect-dependency-count\t{}\nmanifest-package-count\t{}\nadoption-authority\twithheld\nend-external-dry-run\n",
        report.project_id,
        path_text(&report.project_root)?,
        report.target,
        report.input_state_name(),
        report.project_tree_sha256,
        report.entry_count,
        report.file_count,
        report.byte_count,
        report.config_file,
        report.config_sha256,
        report.toolchain,
        report.toolchain_sha256,
        report.manifest_sha256,
        report.root_declaration_sha256,
        report.direct_dependency_count,
        report.manifest_package_count,
    )
    .into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn acceptance_record_bytes(
    report: &ExternalAdoptionDryRunV1,
    baseline_transaction: &str,
    updated_transaction: &str,
    baseline_generation: Sha256,
    updated_generation: Sha256,
    rollback_generation: Sha256,
    artifact: Sha256,
) -> Result<Vec<u8>, ManagedProjectError> {
    Ok(format!(
        "leanbun-external-acceptance-v1\t1\nproject-id\t{}\nproject-root\t{}\ntarget\t{}\ndry-run-project-tree-sha256\t{}\nbaseline-transaction\t{}\nupdated-transaction\t{}\nbaseline-generation-sha256\t{}\nupdated-generation-sha256\t{}\nrollback-generation-sha256\t{}\nproject-artifact-sha256\t{}\nexplicit-update-package\t{}\nfault-recovery\tpassed\nrollback-build\tpassed\nsource-inputs-after\tmatched\nresult\tpassed\nend-external-acceptance\n",
        report.project_id,
        path_text(&report.project_root)?,
        report.target,
        report.project_tree_sha256,
        baseline_transaction,
        updated_transaction,
        baseline_generation,
        updated_generation,
        rollback_generation,
        artifact,
        PACKAGE,
    )
    .into_bytes())
}

pub(crate) fn publish_immutable_record(
    path: &Path,
    bytes: &[u8],
) -> Result<(), ManagedProjectError> {
    if bytes.len() as u64 > MAX_ACCEPTANCE_RECORD_BYTES {
        return Err(input_error("M41 acceptance record exceeds byte limit"));
    }
    create_bytes(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).map_err(io_error)?;
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| input_error("M41 acceptance record has no parent"))?,
    )?;
    if stable_read(path, MAX_ACCEPTANCE_RECORD_BYTES)? != bytes {
        return Err(input_error(
            "M41 acceptance record changed after publication",
        ));
    }
    Ok(())
}

pub(crate) fn copy_tree(source: &Path, destination: &Path) -> Result<(), ManagedProjectError> {
    let source_metadata = fs::symlink_metadata(source).map_err(io_error)?;
    if !source_metadata.file_type().is_dir() {
        return Err(input_error("M41 template root is not a directory"));
    }
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(source_metadata.permissions().mode() & 0o777),
    )
    .map_err(io_error)?;
    for entry in fs::read_dir(source).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(io_error)?;
        let target = destination.join(entry.file_name());
        if metadata.file_type().is_dir() {
            fs::create_dir(&target).map_err(io_error)?;
            copy_tree(&entry.path(), &target)?;
        } else if metadata.file_type().is_file() {
            fs::copy(entry.path(), &target).map_err(io_error)?;
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(metadata.permissions().mode() & 0o777),
            )
            .map_err(io_error)?;
        } else {
            return Err(input_error("M41 template contains a link or special file"));
        }
    }
    Ok(())
}

fn evidence_error(error: leanbun_evidence::EvidenceError) -> ManagedProjectError {
    input_error(format!("M41 acceptance evidence rejected: {error}"))
}

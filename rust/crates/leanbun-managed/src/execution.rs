use super::{
    ManagedBuildResultV1, ManagedLibraryStateV1, ManagedProjectControllerV1, ManagedProjectError,
    input_error, managed_library_status_v1,
};
use leanbun_build::ProgramRunResultV1;
use leanbun_core::{ProjectId, Sha256};
use leanbun_evidence::canonicalize_directory;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedExecutionSelectionV1 {
    pub project_id: ProjectId,
    pub project_root: PathBuf,
    pub target: String,
    pub active_generation_sha256: Sha256,
    pub package_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedBuildFrontDoorResultV1 {
    pub selection: ManagedExecutionSelectionV1,
    pub build: ManagedBuildResultV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRunFrontDoorResultV1 {
    pub selection: ManagedExecutionSelectionV1,
    pub build: ManagedBuildResultV1,
    pub executable: PathBuf,
    pub executable_sha256: Sha256,
    pub program: ProgramRunResultV1,
}

pub fn prepare_managed_execution_v1(
    repository: impl AsRef<Path>,
    query: impl AsRef<Path>,
) -> Result<ManagedExecutionSelectionV1, ManagedProjectError> {
    let repository = repository.as_ref();
    let first = managed_library_status_v1(repository, query.as_ref())?;
    let reread_id = first
        .project_id
        .ok_or_else(|| input_error("managed execution selection lacks ProjectId"))?;
    let second = managed_library_status_v1(repository, reread_id.to_string())?;
    selection_from_observations(first, second)
}

pub fn run_managed_build_front_door_v1(
    repository: impl AsRef<Path>,
    query: impl AsRef<Path>,
    supervisor: impl AsRef<Path>,
) -> Result<ManagedBuildFrontDoorResultV1, ManagedProjectError> {
    let repository = repository.as_ref();
    let selection = prepare_managed_execution_v1(repository, query)?;
    let controller =
        ManagedProjectControllerV1::open(repository, &selection.project_root, supervisor)?;
    let build = controller.build_expected(Some(selection.active_generation_sha256))?;
    if build.generation_sha256 != selection.active_generation_sha256 {
        return Err(input_error(
            "managed build completed against a generation other than its selection",
        ));
    }
    let after = prepare_managed_execution_v1(repository, selection.project_id.to_string())?;
    if after != selection {
        return Err(input_error(
            "managed registry or generation changed across supervised build",
        ));
    }
    Ok(ManagedBuildFrontDoorResultV1 { selection, build })
}

pub fn run_managed_program_front_door_v1(
    repository: impl AsRef<Path>,
    query: impl AsRef<Path>,
    supervisor: impl AsRef<Path>,
    arguments: &[String],
) -> Result<ManagedRunFrontDoorResultV1, ManagedProjectError> {
    validate_program_arguments(arguments)?;
    let repository = repository.as_ref();
    let selection = prepare_managed_execution_v1(repository, query)?;
    let controller =
        ManagedProjectControllerV1::open(repository, &selection.project_root, supervisor)?;
    let (build, executable, program) =
        controller.run_expected(selection.active_generation_sha256, arguments)?;
    if build.generation_sha256 != selection.active_generation_sha256 {
        return Err(input_error(
            "managed run completed against a generation other than its selection",
        ));
    }
    let after = prepare_managed_execution_v1(repository, selection.project_id.to_string())?;
    if after != selection {
        return Err(input_error(
            "managed registry or generation changed across supervised run",
        ));
    }
    Ok(ManagedRunFrontDoorResultV1 {
        selection,
        build,
        executable: executable.path,
        executable_sha256: executable.sha256,
        program,
    })
}

fn validate_program_arguments(arguments: &[String]) -> Result<(), ManagedProjectError> {
    if arguments.len() > 64 {
        return Err(input_error("managed run argument count exceeds limit"));
    }
    let mut bytes = 0_usize;
    for argument in arguments {
        if argument.len() > 4096 || argument.contains('\0') {
            return Err(input_error(
                "managed run argument is invalid or exceeds limit",
            ));
        }
        bytes = bytes
            .checked_add(argument.len())
            .ok_or_else(|| input_error("managed run argument byte count overflow"))?;
    }
    if bytes > 16 * 1024 {
        return Err(input_error("managed run argument bytes exceed limit"));
    }
    Ok(())
}

fn selection_from_observations(
    first: super::ManagedLibraryStatusV1,
    second: super::ManagedLibraryStatusV1,
) -> Result<ManagedExecutionSelectionV1, ManagedProjectError> {
    if first.state != ManagedLibraryStateV1::Healthy || !first.diagnostics.is_empty() {
        return Err(input_error(format!(
            "managed execution requires healthy status, observed {}",
            first.state.as_str()
        )));
    }
    let project_id = first
        .project_id
        .ok_or_else(|| input_error("healthy managed status lacks ProjectId"))?;
    let project_root = first
        .project_root
        .clone()
        .ok_or_else(|| input_error("healthy managed status lacks project path"))?;
    let canonical = canonicalize_directory(&project_root)
        .map_err(|error| input_error(format!("managed execution path rejected: {error}")))?;
    if canonical.as_path() != project_root {
        return Err(input_error(
            "healthy managed execution path is not canonical",
        ));
    }
    if first != second {
        return Err(input_error(
            "managed registry or generation changed during execution selection",
        ));
    }
    Ok(ManagedExecutionSelectionV1 {
        project_id,
        project_root,
        target: first
            .target
            .ok_or_else(|| input_error("healthy managed status lacks target"))?,
        active_generation_sha256: first
            .active_generation_sha256
            .ok_or_else(|| input_error("healthy managed status lacks active generation"))?,
        package_count: first
            .package_count
            .ok_or_else(|| input_error("healthy managed status lacks package count"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ManagedLibraryDiagnosticV1, ManagedLibraryStatusV1};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    fn healthy_status(project_root: PathBuf) -> ManagedLibraryStatusV1 {
        let id =
            ProjectId::parse("5000000000000000000000000000000000000000000000000000000000000001")
                .unwrap_or_else(|error| panic!("ProjectId fixture failed: {error}"));
        ManagedLibraryStatusV1 {
            project_id: Some(id),
            project_root: Some(project_root),
            target: Some("Main".to_owned()),
            toolchain: Some("leanprover/lean4:v4.32.0".to_owned()),
            state: ManagedLibraryStateV1::Healthy,
            active_generation_sha256: Some(
                Sha256::parse("5000000000000000000000000000000000000000000000000000000000000002")
                    .unwrap_or_else(|error| panic!("generation fixture failed: {error}")),
            ),
            package_count: Some(1),
            pending_transaction: None,
            previous_transaction: None,
            rollback_available: false,
            exact_package_source_keys: Vec::new(),
            active_package_build_keys: Vec::new(),
            source_reference_count: None,
            artifact_reference_count: None,
            artifact_cache_hits: None,
            artifact_publications: None,
            artifact_reuses: None,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn m50a_selection_rejects_every_nonhealthy_state_and_observation_race() {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("leanbun-m50-selection-{}-{id}", std::process::id()));
        fs::create_dir(&root).unwrap_or_else(|error| panic!("fixture create failed: {error}"));
        let root = root
            .canonicalize()
            .unwrap_or_else(|error| panic!("fixture canonicalization failed: {error}"));
        let healthy = healthy_status(root.clone());
        assert_eq!(
            selection_from_observations(healthy.clone(), healthy.clone())
                .unwrap_or_else(|error| panic!("healthy selection failed: {error}"))
                .project_root,
            root
        );
        for state in [
            ManagedLibraryStateV1::InvalidRecord,
            ManagedLibraryStateV1::Missing,
            ManagedLibraryStateV1::PendingRecovery,
            ManagedLibraryStateV1::Unsupported,
            ManagedLibraryStateV1::Drifted,
            ManagedLibraryStateV1::Unmanaged,
        ] {
            let mut rejected = healthy.clone();
            rejected.state = state;
            rejected.diagnostics = vec![ManagedLibraryDiagnosticV1 {
                code: "M50_REJECTED_FIXTURE".to_owned(),
                message: "nonhealthy fixture".to_owned(),
            }];
            assert!(selection_from_observations(rejected.clone(), rejected).is_err());
        }
        let mut changed = healthy.clone();
        changed.active_generation_sha256 = Some(
            Sha256::parse("5000000000000000000000000000000000000000000000000000000000000003")
                .unwrap_or_else(|error| panic!("changed generation fixture failed: {error}")),
        );
        assert!(selection_from_observations(healthy, changed).is_err());
        fs::remove_dir(&root).unwrap_or_else(|error| panic!("fixture cleanup failed: {error}"));
    }

    #[test]
    fn m50c_program_argument_limits_fail_before_execution_selection() {
        assert!(validate_program_arguments(&[]).is_ok());
        assert!(validate_program_arguments(&["x".repeat(4096)]).is_ok());
        assert!(validate_program_arguments(&vec!["x".to_owned(); 65]).is_err());
        assert!(validate_program_arguments(&["x".repeat(4097)]).is_err());
        assert!(validate_program_arguments(&["x".repeat(16 * 1024 + 1)]).is_err());
        assert!(validate_program_arguments(&["nul\0byte".to_owned()]).is_err());
    }
}

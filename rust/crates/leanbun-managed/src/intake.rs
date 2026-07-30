use super::{
    ManagedProjectControllerV1, ManagedProjectError, ManagedProjectErrorKind, TOOLCHAIN, boundary,
    error, input_error, validate_target,
};
use leanbun_core::{ProjectId, Sha256, project_id};
use leanbun_evidence::{
    CanonicalDirectory, ProjectInputState, ProjectInputTreeHash, StableProjectInput,
    canonicalize_directory, hash_project_input_tree, read_project_input, read_stable_text,
};
use leanbun_generation::LeanGenerationFaultV1;
use leanbun_lake_bridge::{LakeDependencySourceV1, LakeRootDeclarationV1, LakeRootDependencyV1};
use leanbun_lock::PackageKeyV1;
use std::path::{Component, Path, PathBuf};
use std::{fs, os::unix::fs::PermissionsExt};

const CONFIRMATION: &str = "--explicit-managed-project";
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedIntakePolicyV1 {
    RegisteredFixtureCopy,
    UserSelectedLocal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntakeSnapshotV1 {
    tree: ProjectInputTreeHash,
    input: StableProjectInput,
    declaration: LakeRootDeclarationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedIntakePlanV1 {
    pub project_id: ProjectId,
    pub project_root: PathBuf,
    pub target: String,
    pub policy: ManagedIntakePolicyV1,
    pub input_state: ProjectInputState,
    pub project_tree_sha256: Sha256,
    pub root_declaration_sha256: Sha256,
    pub direct_dependency_count: usize,
    pub mutation: &'static str,
    repository: PathBuf,
    snapshot: IntakeSnapshotV1,
}

impl ManagedIntakePlanV1 {
    #[must_use]
    pub const fn input_state_name(&self) -> &'static str {
        match self.input_state {
            ProjectInputState::DependencyFree => "dependency-free",
            ProjectInputState::Standalone => "standalone",
            ProjectInputState::ProviderBound => "provider-bound",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedIntakeResultV1 {
    pub project_id: ProjectId,
    pub project_root: PathBuf,
    pub target: String,
    pub generation_sha256: Sha256,
    pub package_count: usize,
}

pub fn prepare_managed_intake_v1(
    repository: impl AsRef<Path>,
    project: impl AsRef<Path>,
    target: &str,
    policy: ManagedIntakePolicyV1,
) -> Result<ManagedIntakePlanV1, ManagedProjectError> {
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
    let authority = repository
        .as_path()
        .join(".leanbun-dev-rust/managed-projects");
    if project.as_path().starts_with(&authority) {
        return Err(boundary(
            "managed project cannot live inside its state authority root",
        ));
    }
    let registry = super::read_managed_registry_v1(repository.as_path())?;
    if registry
        .projects
        .iter()
        .any(|status| status.state == super::ManagedLibraryStateV1::Missing)
    {
        return Err(boundary(
            "managed registry contains a missing project path; implicit move or rebind is not authorized",
        ));
    }
    let snapshot = snapshot(project.as_path())?;
    if snapshot.input.toolchain != TOOLCHAIN {
        return Err(error(
            ManagedProjectErrorKind::UnsupportedDependencyGraph,
            "managed intake candidate uses an unsupported Lean toolchain",
        ));
    }
    preflight_dependencies(&snapshot)?;
    if policy == ManagedIntakePolicyV1::RegisteredFixtureCopy {
        let template = canonicalize_directory(
            repository
                .as_path()
                .join("test/fixtures/lake-managed-dependency"),
        )
        .map_err(evidence_error)?;
        if project == template {
            return Err(boundary(
                "M49C intake requires an isolated copy, not the fixture template",
            ));
        }
        let template_tree = hash_project_input_tree(&template).map_err(evidence_error)?;
        if snapshot.tree != template_tree {
            return Err(boundary(
                "M49C intake accepts only an exact registered fixture copy",
            ));
        }
    }
    let path = project
        .as_path()
        .to_str()
        .ok_or_else(|| boundary("managed intake path is not UTF-8"))?;
    Ok(ManagedIntakePlanV1 {
        project_id: project_id(path),
        project_root: project.as_path().to_path_buf(),
        target: target.to_owned(),
        policy,
        input_state: snapshot.input.state,
        project_tree_sha256: snapshot.tree.tree_hash,
        root_declaration_sha256: snapshot.declaration.identity(),
        direct_dependency_count: snapshot.declaration.dependencies().len(),
        mutation: "pending-record-generation-activation-v1",
        repository: repository.as_path().to_path_buf(),
        snapshot,
    })
}

pub fn commit_managed_intake_v1(
    plan: &ManagedIntakePlanV1,
    supervisor: impl AsRef<Path>,
    confirmation: &str,
) -> Result<ManagedIntakeResultV1, ManagedProjectError> {
    commit_managed_intake_with_fault_v1(plan, supervisor, confirmation, LeanGenerationFaultV1::None)
}

pub(crate) fn commit_managed_intake_with_fault_v1(
    plan: &ManagedIntakePlanV1,
    supervisor: impl AsRef<Path>,
    confirmation: &str,
    fault: LeanGenerationFaultV1,
) -> Result<ManagedIntakeResultV1, ManagedProjectError> {
    if confirmation != CONFIRMATION {
        return Err(boundary(
            "managed intake requires the exact --explicit-managed-project confirmation",
        ));
    }
    let confirmed = snapshot(&plan.project_root)?;
    if confirmed != plan.snapshot {
        return Err(input_error(
            "managed intake candidate changed after plan confirmation",
        ));
    }
    let controller =
        ManagedProjectControllerV1::open(&plan.repository, &plan.project_root, supervisor)?;
    let status = controller.adopt_declaration_with_fault(
        &plan.target,
        plan.snapshot.declaration.clone(),
        plan.project_tree_sha256,
        fault,
    )?;
    let observed = super::managed_library_status_v1(&plan.repository, &plan.project_root)?;
    if observed.state != super::ManagedLibraryStateV1::Healthy
        || observed.project_id != Some(plan.project_id)
        || observed.active_generation_sha256 != Some(status.generation_sha256)
    {
        return Err(input_error(
            "managed intake activation did not survive authoritative reread",
        ));
    }
    Ok(ManagedIntakeResultV1 {
        project_id: status.project_id,
        project_root: status.project_root,
        target: status.target,
        generation_sha256: status.generation_sha256,
        package_count: status.package_count,
    })
}

pub fn select_macos_managed_state_root_v1(
    home: impl AsRef<Path>,
) -> Result<PathBuf, ManagedProjectError> {
    let home = home.as_ref();
    if !home.is_absolute()
        || home
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(boundary("macOS home path must be normalized and absolute"));
    }
    Ok(home.join("Library/Application Support/LeanBun/managed-projects"))
}

pub fn review_macos_managed_state_root_v1(
    root: impl AsRef<Path>,
) -> Result<(), ManagedProjectError> {
    let root = root.as_ref();
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(boundary(
            "managed state root must be normalized and absolute",
        ));
    }
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            boundary("managed state root must exist before permissions review")
        } else {
            input_error(format!("cannot inspect managed state root: {error}"))
        }
    })?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(boundary(
            "managed state root must be a private 0700 directory and not a symlink",
        ));
    }
    Ok(())
}

fn preflight_dependencies(snapshot: &IntakeSnapshotV1) -> Result<(), ManagedProjectError> {
    let dependencies = snapshot.declaration.dependencies();
    if dependencies.is_empty() {
        return Ok(());
    }
    let path_count = dependencies
        .iter()
        .filter(|dependency| matches!(dependency.source(), LakeDependencySourceV1::Path { .. }))
        .count();
    let git_count = dependencies
        .iter()
        .filter(|dependency| matches!(dependency.source(), LakeDependencySourceV1::Git { .. }))
        .count();
    if path_count == dependencies.len() && snapshot.input.path_packages.len() == dependencies.len()
    {
        return Ok(());
    }
    if git_count == dependencies.len()
        && snapshot.input.manifest.manifest.packages.len() >= dependencies.len()
    {
        return Ok(());
    }
    Err(error(
        ManagedProjectErrorKind::UnsupportedDependencyGraph,
        "managed intake dependency preflight rejects mixed, unresolved, or unsupported providers",
    ))
}

fn snapshot(project: &Path) -> Result<IntakeSnapshotV1, ManagedProjectError> {
    let project = canonicalize_directory(project).map_err(evidence_error)?;
    let before = hash_project_input_tree(&project).map_err(evidence_error)?;
    let input = read_project_input(&project, None).map_err(evidence_error)?;
    let declaration = parse_declaration(&project)?;
    let after = hash_project_input_tree(&project).map_err(evidence_error)?;
    if before != after {
        return Err(input_error(
            "managed intake candidate changed during stable snapshot",
        ));
    }
    Ok(IntakeSnapshotV1 {
        tree: before,
        input,
        declaration,
    })
}

pub(crate) fn parse_filesystem_declaration_v1(
    project: &Path,
) -> Result<LakeRootDeclarationV1, ManagedProjectError> {
    let project = canonicalize_directory(project).map_err(evidence_error)?;
    parse_declaration(&project)
}

pub(crate) fn require_executable_target_v1(
    project: &Path,
    target: &str,
) -> Result<(), ManagedProjectError> {
    validate_target(target)?;
    let project = canonicalize_directory(project).map_err(evidence_error)?;
    let config =
        read_stable_text(&project, "lakefile.toml", MAX_CONFIG_BYTES).map_err(evidence_error)?;
    let mut section = String::new();
    let mut name = None::<String>;
    let mut root = None::<String>;
    let mut matches = 0_usize;
    let finish = |name: &mut Option<String>,
                  root: &mut Option<String>,
                  matches: &mut usize|
     -> Result<(), ManagedProjectError> {
        if let Some(name) = name.take() {
            root.take()
                .ok_or_else(|| input_error("managed executable target lacks an explicit root"))?;
            if name == target {
                *matches += 1;
            }
        } else if root.take().is_some() {
            return Err(input_error("managed executable root lacks a target name"));
        }
        Ok(())
    };
    for raw in config.text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("[[") && line.ends_with("]]") {
            if section == "lean_exe" {
                finish(&mut name, &mut root, &mut matches)?;
            }
            section = line[2..line.len() - 2].trim().to_owned();
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if section == "lean_exe" {
                finish(&mut name, &mut root, &mut matches)?;
            }
            section = line[1..line.len() - 1].trim().to_owned();
            continue;
        }
        if section != "lean_exe" {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| input_error("unsupported managed executable declaration"))?;
        let slot = match key.trim() {
            "name" => &mut name,
            "root" => &mut root,
            _ => return Err(input_error("unsupported [[lean_exe]] field")),
        };
        if slot.replace(basic_string(value)?).is_some() {
            return Err(input_error("managed executable field is repeated"));
        }
    }
    if section == "lean_exe" {
        finish(&mut name, &mut root, &mut matches)?;
    }
    if matches != 1 {
        return Err(input_error(
            "managed run requires exactly one matching [[lean_exe]] target",
        ));
    }
    Ok(())
}

fn parse_declaration(
    project: &CanonicalDirectory,
) -> Result<LakeRootDeclarationV1, ManagedProjectError> {
    let toml = project.as_path().join("lakefile.toml");
    let lean = project.as_path().join("lakefile.lean");
    match (toml.is_file(), lean.is_file()) {
        (true, false) => {}
        (false, true) => {
            return Err(error(
                ManagedProjectErrorKind::UnsupportedDependencyGraph,
                "filesystem-only M49 intake does not execute lakefile.lean",
            ));
        }
        _ => return Err(boundary("managed intake requires exactly one Lake config")),
    }
    let config =
        read_stable_text(project, "lakefile.toml", MAX_CONFIG_BYTES).map_err(evidence_error)?;
    parse_supported_lakefile_toml(&config.text)
}

#[derive(Default)]
struct RequireFields {
    name: Option<String>,
    scope: Option<String>,
    path: Option<String>,
    git: Option<String>,
    rev: Option<String>,
    subdir: Option<String>,
    version: Option<String>,
}

fn parse_supported_lakefile_toml(text: &str) -> Result<LakeRootDeclarationV1, ManagedProjectError> {
    let mut root_name = None;
    let mut section = String::new();
    let mut current = None::<RequireFields>;
    let mut dependencies = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("[[") && line.ends_with("]]") {
            if let Some(fields) = current.take() {
                dependencies.push(finish_requirement(fields)?);
            }
            section = line[2..line.len() - 2].trim().to_owned();
            if section == "require" {
                current = Some(RequireFields::default());
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(fields) = current.take() {
                dependencies.push(finish_requirement(fields)?);
            }
            section = line[1..line.len() - 1].trim().to_owned();
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            return Err(input_error("unsupported lakefile.toml statement"));
        };
        let key = key.trim();
        if section.is_empty() && key == "name" {
            if root_name.replace(basic_string(raw_value)?).is_some() {
                return Err(input_error("lakefile.toml repeats the root name"));
            }
        } else if section == "require" {
            let fields = current
                .as_mut()
                .ok_or_else(|| input_error("require fields lack a section"))?;
            let value = basic_string(raw_value)?;
            let slot = match key {
                "name" => &mut fields.name,
                "scope" => &mut fields.scope,
                "path" => &mut fields.path,
                "git" => &mut fields.git,
                "rev" => &mut fields.rev,
                "subDir" => &mut fields.subdir,
                "version" => &mut fields.version,
                _ => return Err(input_error("unsupported [[require]] field")),
            };
            if slot.replace(value).is_some() {
                return Err(input_error("lakefile.toml repeats a require field"));
            }
        }
    }
    if let Some(fields) = current {
        dependencies.push(finish_requirement(fields)?);
    }
    LakeRootDeclarationV1::new(
        root_name.ok_or_else(|| input_error("lakefile.toml root name is missing"))?,
        "lakefile.toml",
        dependencies,
    )
    .map_err(|error| input_error(error.to_string()))
}

fn finish_requirement(fields: RequireFields) -> Result<LakeRootDependencyV1, ManagedProjectError> {
    let key = PackageKeyV1::new(
        fields.scope.unwrap_or_default(),
        fields
            .name
            .ok_or_else(|| input_error("lakefile.toml require name is missing"))?,
    )
    .map_err(|error| input_error(error.to_string()))?;
    let source = match (fields.path, fields.git) {
        (Some(directory), None) if fields.rev.is_none() && fields.subdir.is_none() => {
            LakeDependencySourceV1::Path { directory }
        }
        (None, Some(url)) => LakeDependencySourceV1::Git {
            url,
            revision: fields.rev.clone(),
            subdir: fields.subdir,
        },
        _ => {
            return Err(input_error(
                "require must select exactly one supported source",
            ));
        }
    };
    let version = fields
        .version
        .or_else(|| fields.rev.map(|rev| format!("git#{rev}")));
    LakeRootDependencyV1::new(key, version, source).map_err(|error| input_error(error.to_string()))
}

fn basic_string(value: &str) -> Result<String, ManagedProjectError> {
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| input_error("M49 lakefile.toml accepts only basic string values"))?;
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_control() || character == '"' || character == '\\')
    {
        return Err(input_error("lakefile.toml basic string is invalid"));
    }
    Ok(value.to_owned())
}

fn evidence_error(error: leanbun_evidence::EvidenceError) -> ManagedProjectError {
    input_error(format!("managed intake evidence rejected: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ManagedLibraryStateV1, ManagedProjectControllerV1, managed_library_status_v1,
        prepare_managed_execution_v1, read_managed_registry_v1,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier, Mutex, OnceLock};
    use std::thread;

    static INTAKE_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn intake_test_guard() -> std::sync::MutexGuard<'static, ()> {
        INTAKE_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    struct FixtureCopy {
        repository: PathBuf,
        root: PathBuf,
        project: PathBuf,
        development_root_created: bool,
    }

    impl FixtureCopy {
        fn new(label: &str, template: &str) -> Self {
            let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(3)
                .and_then(|path| path.canonicalize().ok())
                .unwrap_or_else(|| panic!("repository root missing"));
            let development = repository.join(".leanbun-dev");
            let development_root_created = !development.exists();
            if development_root_created {
                fs::create_dir(&development)
                    .unwrap_or_else(|error| panic!("M49 development root failed: {error}"));
            }
            let root = repository
                .join(".leanbun-dev-rust/m49-intake-tests")
                .join(format!("{}-{label}", std::process::id()));
            if root.exists() {
                make_writable(&root);
                fs::remove_dir_all(&root)
                    .unwrap_or_else(|error| panic!("stale M49 fixture cleanup failed: {error}"));
            }
            fs::create_dir_all(&root)
                .unwrap_or_else(|error| panic!("M49 fixture root failed: {error}"));
            let project = root.join("project");
            fs::create_dir(&project)
                .unwrap_or_else(|error| panic!("M49 project root failed: {error}"));
            copy_tree(&repository.join("test/fixtures").join(template), &project);
            let project = project
                .canonicalize()
                .unwrap_or_else(|error| panic!("M49 project canonicalization failed: {error}"));
            Self {
                repository,
                root,
                project,
                development_root_created,
            }
        }

        fn cleanup_state(&self) {
            let id = project_id(
                self.project
                    .to_str()
                    .unwrap_or_else(|| panic!("M49 project path is not UTF-8")),
            );
            for path in [
                self.repository
                    .join(".leanbun-dev-rust/managed-projects/registry")
                    .join(format!("{id}.record")),
                self.repository
                    .join(".leanbun-dev-rust/managed-projects/generation-state/projects")
                    .join(id.to_string()),
                self.repository
                    .join(".leanbun-dev-rust/managed-projects/project-control")
                    .join(id.to_string()),
                self.repository
                    .join(".leanbun-dev/store-fixture/m40-managed")
                    .join(id.to_string()),
            ] {
                if path.is_dir() {
                    make_writable(&path);
                    fs::remove_dir_all(&path)
                        .unwrap_or_else(|error| panic!("M49 state cleanup failed: {error}"));
                } else if path.is_file() {
                    fs::remove_file(&path)
                        .unwrap_or_else(|error| panic!("M49 record cleanup failed: {error}"));
                }
            }
        }
    }

    impl Drop for FixtureCopy {
        fn drop(&mut self) {
            self.cleanup_state();
            make_writable(&self.root);
            let _ = fs::remove_dir_all(&self.root);
            if self.development_root_created {
                let _ = fs::remove_dir(self.repository.join(".leanbun-dev"));
            }
        }
    }

    #[test]
    fn m49c_fixture_intake_is_exact_restartable_and_duplicate_safe() {
        let _guard = intake_test_guard();
        let fixture = FixtureCopy::new("fixture-intake", "lake-managed-dependency");
        let source = canonicalize_directory(&fixture.project)
            .unwrap_or_else(|error| panic!("source boundary failed: {error}"));
        let before = hash_project_input_tree(&source)
            .unwrap_or_else(|error| panic!("source snapshot failed: {error}"));
        let plan = prepare_managed_intake_v1(
            &fixture.repository,
            &fixture.project,
            "leanbun_managed_dependency_fixture",
            ManagedIntakePolicyV1::RegisteredFixtureCopy,
        )
        .unwrap_or_else(|error| panic!("M49C prepare failed: {error}"));
        assert_eq!(plan.direct_dependency_count, 1);
        assert!(commit_managed_intake_v1(&plan, "/usr/bin/true", "--wrong-confirmation").is_err());
        let result = commit_managed_intake_v1(&plan, "/usr/bin/true", "--explicit-managed-project")
            .unwrap_or_else(|error| panic!("M49C commit failed: {error}"));
        assert_eq!(result.package_count, 1);
        assert!(!fixture.project.join(".lake").exists());
        assert_eq!(
            hash_project_input_tree(&source)
                .unwrap_or_else(|error| panic!("source resnapshot failed: {error}")),
            before
        );
        let restarted =
            managed_library_status_v1(&fixture.repository, result.project_id.to_string())
                .unwrap_or_else(|error| panic!("restart status failed: {error}"));
        assert_eq!(restarted.state, ManagedLibraryStateV1::Healthy);
        assert!(
            commit_managed_intake_v1(&plan, "/usr/bin/true", "--explicit-managed-project").is_err()
        );
        let retarget = prepare_managed_intake_v1(
            &fixture.repository,
            &fixture.project,
            "another_target",
            ManagedIntakePolicyV1::RegisteredFixtureCopy,
        )
        .unwrap_or_else(|error| panic!("retarget planning failed: {error}"));
        assert!(
            commit_managed_intake_v1(&retarget, "/usr/bin/true", "--explicit-managed-project")
                .is_err()
        );
        assert_eq!(
            read_managed_registry_v1(&fixture.repository)
                .unwrap_or_else(|error| panic!("registry reread failed: {error}"))
                .projects
                .iter()
                .filter(|status| status.project_id == Some(result.project_id))
                .count(),
            1
        );
        let moved = fixture.root.join("moved-project");
        fs::rename(&fixture.project, &moved)
            .unwrap_or_else(|error| panic!("fixture move failed: {error}"));
        assert!(
            prepare_managed_intake_v1(
                &fixture.repository,
                &moved,
                "leanbun_managed_dependency_fixture",
                ManagedIntakePolicyV1::RegisteredFixtureCopy,
            )
            .is_err()
        );
        fs::rename(&moved, &fixture.project)
            .unwrap_or_else(|error| panic!("fixture move restoration failed: {error}"));
    }

    #[test]
    fn m49c_fault_recovery_and_concurrent_add_fail_closed() {
        let _guard = intake_test_guard();
        let failed = FixtureCopy::new("fault-recovery", "lake-managed-dependency");
        let failed_plan = prepare_managed_intake_v1(
            &failed.repository,
            &failed.project,
            "leanbun_managed_dependency_fixture",
            ManagedIntakePolicyV1::RegisteredFixtureCopy,
        )
        .unwrap_or_else(|error| panic!("fault plan failed: {error}"));
        assert!(
            commit_managed_intake_with_fault_v1(
                &failed_plan,
                "/usr/bin/true",
                "--explicit-managed-project",
                LeanGenerationFaultV1::BeforeActiveRename,
            )
            .is_err()
        );
        assert_eq!(
            managed_library_status_v1(&failed.repository, &failed.project)
                .unwrap_or_else(|error| panic!("pending status failed: {error}"))
                .state,
            ManagedLibraryStateV1::PendingRecovery
        );
        assert!(prepare_managed_execution_v1(&failed.repository, &failed.project).is_err());
        let restarted =
            ManagedProjectControllerV1::open(&failed.repository, &failed.project, "/usr/bin/true")
                .unwrap_or_else(|error| panic!("restart controller failed: {error}"));
        assert!(matches!(
            restarted.recover(),
            Err(error) if error.kind == ManagedProjectErrorKind::NotAdopted
        ));
        assert_eq!(
            managed_library_status_v1(&failed.repository, &failed.project)
                .unwrap_or_else(|error| panic!("recovered status failed: {error}"))
                .state,
            ManagedLibraryStateV1::Unmanaged
        );

        let concurrent = FixtureCopy::new("concurrent", "lake-managed-dependency");
        let plan = prepare_managed_intake_v1(
            &concurrent.repository,
            &concurrent.project,
            "leanbun_managed_dependency_fixture",
            ManagedIntakePolicyV1::RegisteredFixtureCopy,
        )
        .unwrap_or_else(|error| panic!("concurrent plan failed: {error}"));
        let barrier = Arc::new(Barrier::new(2));
        let results = thread::scope(|scope| {
            (0..2)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let plan = plan.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        commit_managed_intake_v1(
                            &plan,
                            "/usr/bin/true",
                            "--explicit-managed-project",
                        )
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| panic!("intake worker panicked"))
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    }

    #[test]
    fn m49d_user_selected_project_completes_lifecycle_without_observing_others() {
        let _guard = intake_test_guard();
        let fixture = FixtureCopy::new("user-selected", "lake-managed-dependency");
        let unrelated = FixtureCopy::new("unrelated", "lake-basic");
        let source = canonicalize_directory(&fixture.project)
            .unwrap_or_else(|error| panic!("M49D source boundary failed: {error}"));
        let before = hash_project_input_tree(&source)
            .unwrap_or_else(|error| panic!("M49D source snapshot failed: {error}"));
        let plan = prepare_managed_intake_v1(
            &fixture.repository,
            &fixture.project,
            "leanbun_managed_dependency_fixture",
            ManagedIntakePolicyV1::UserSelectedLocal,
        )
        .unwrap_or_else(|error| panic!("M49D prepare failed: {error}"));
        commit_managed_intake_v1(&plan, "/usr/bin/true", "--explicit-managed-project")
            .unwrap_or_else(|error| panic!("M49D intake failed: {error}"));
        let selected = prepare_managed_execution_v1(&fixture.repository, &fixture.project)
            .unwrap_or_else(|error| panic!("M50A path selection failed: {error}"));
        assert_eq!(
            prepare_managed_execution_v1(&fixture.repository, selected.project_id.to_string())
                .unwrap_or_else(|error| panic!("M50A ProjectId selection failed: {error}")),
            selected
        );
        assert!(prepare_managed_execution_v1(&fixture.repository, &unrelated.project).is_err());
        let controller = ManagedProjectControllerV1::open(
            &fixture.repository,
            &fixture.project,
            "/usr/bin/true",
        )
        .unwrap_or_else(|error| panic!("M49D restart failed: {error}"));
        let baseline = controller
            .status()
            .unwrap_or_else(|error| panic!("M49D status failed: {error}"));
        let operation = controller
            .acquire_operation_lease()
            .unwrap_or_else(|error| panic!("M50B operation lease failed: {error}"));
        let competing = ManagedProjectControllerV1::open(
            &fixture.repository,
            &fixture.project,
            "/usr/bin/true",
        )
        .unwrap_or_else(|error| panic!("M50B competing controller failed: {error}"));
        assert!(matches!(
            competing.update_packages(&["managed_dep".to_owned()]),
            Err(error) if error.kind == ManagedProjectErrorKind::PendingTransaction
        ));
        drop(operation);
        assert_eq!(
            controller
                .status()
                .unwrap_or_else(|error| panic!("M50B post-contention status failed: {error}"))
                .pending_transaction,
            None
        );
        assert!(
            controller
                .update_with_fault(LeanGenerationFaultV1::BeforeActiveRename)
                .is_err()
        );
        let recovered = controller
            .recover()
            .unwrap_or_else(|error| panic!("M49D recovery failed: {error}"));
        assert_eq!(recovered.active_transaction, baseline.active_transaction);
        let updated = controller
            .update_packages(&["managed_dep".to_owned()])
            .unwrap_or_else(|error| panic!("M49D update failed: {error}"));
        assert!(
            controller
                .build_expected(Some(selected.active_generation_sha256))
                .is_err()
        );
        let rolled_back = controller
            .rollback()
            .unwrap_or_else(|error| panic!("M49D rollback failed: {error}"));
        assert_eq!(rolled_back.active_transaction, baseline.active_transaction);
        assert_eq!(
            rolled_back.previous_transaction,
            Some(updated.active_transaction)
        );
        assert_eq!(
            managed_library_status_v1(&fixture.repository, &unrelated.project)
                .unwrap_or_else(|error| panic!("unrelated status failed: {error}"))
                .state,
            ManagedLibraryStateV1::Unmanaged
        );
        assert!(!unrelated.project.join(".lake").exists());
        assert_eq!(
            hash_project_input_tree(&source)
                .unwrap_or_else(|error| panic!("M49D final snapshot failed: {error}")),
            before
        );
        assert_eq!(
            select_macos_managed_state_root_v1(Path::new("/private/tmp/m49-home"))
                .unwrap_or_else(|error| panic!("state root selection failed: {error}")),
            PathBuf::from(
                "/private/tmp/m49-home/Library/Application Support/LeanBun/managed-projects"
            )
        );
        assert!(select_macos_managed_state_root_v1(Path::new("relative-home")).is_err());
        let state_root = fixture.root.join("production-state-root-review");
        fs::create_dir(&state_root)
            .unwrap_or_else(|error| panic!("state root fixture failed: {error}"));
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("state root permission setup failed: {error}"));
        review_macos_managed_state_root_v1(&state_root)
            .unwrap_or_else(|error| panic!("private state root review failed: {error}"));
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|error| panic!("state root public mode setup failed: {error}"));
        assert!(review_macos_managed_state_root_v1(&state_root).is_err());
    }

    #[test]
    fn m50c_executable_target_classification_is_exact() {
        let _guard = intake_test_guard();
        let fixture = FixtureCopy::new("m50-target", "lake-managed-dependency");
        assert!(
            require_executable_target_v1(&fixture.project, "leanbun_managed_dependency_fixture")
                .is_ok()
        );
        assert!(
            require_executable_target_v1(&fixture.project, "LeanBunManagedDependencyFixture")
                .is_err()
        );
        let config = fixture.project.join("lakefile.toml");
        let mut text = fs::read_to_string(&config)
            .unwrap_or_else(|error| panic!("M50C config read failed: {error}"));
        text.push_str(
            "\n[[lean_exe]]\nname = \"leanbun_managed_dependency_fixture\"\nroot = \"Main\"\n",
        );
        fs::write(&config, text)
            .unwrap_or_else(|error| panic!("M50C duplicate config failed: {error}"));
        assert!(
            require_executable_target_v1(&fixture.project, "leanbun_managed_dependency_fixture")
                .is_err()
        );
    }

    #[test]
    fn m50c_executable_observer_rejects_missing_writable_symlink_and_detects_drift() {
        let _guard = intake_test_guard();
        let fixture = FixtureCopy::new("m50-executable", "lake-managed-dependency");
        let controller = ManagedProjectControllerV1::open(
            &fixture.repository,
            &fixture.project,
            "/usr/bin/true",
        )
        .unwrap_or_else(|error| panic!("M50C observer controller failed: {error}"));
        let target = "leanbun_managed_dependency_fixture";
        assert!(controller.observe_managed_executable(target).is_err());
        let bin = fixture.project.join(".lake/build/bin");
        fs::create_dir_all(&bin)
            .unwrap_or_else(|error| panic!("M50C observer bin failed: {error}"));
        let executable = bin.join(target);
        fs::write(&executable, b"first")
            .unwrap_or_else(|error| panic!("M50C observer executable failed: {error}"));
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|error| panic!("M50C observer chmod failed: {error}"));
        let first = controller
            .observe_managed_executable(target)
            .unwrap_or_else(|error| panic!("M50C observer positive failed: {error}"));
        fs::write(&executable, b"other")
            .unwrap_or_else(|error| panic!("M50C observer drift failed: {error}"));
        let second = controller
            .observe_managed_executable(target)
            .unwrap_or_else(|error| panic!("M50C observer drift read failed: {error}"));
        assert_ne!(first, second);
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o775))
            .unwrap_or_else(|error| panic!("M50C observer writable chmod failed: {error}"));
        assert!(controller.observe_managed_executable(target).is_err());
        fs::remove_file(&executable)
            .unwrap_or_else(|error| panic!("M50C observer removal failed: {error}"));
        std::os::unix::fs::symlink("/usr/bin/true", &executable)
            .unwrap_or_else(|error| panic!("M50C observer symlink failed: {error}"));
        assert!(controller.observe_managed_executable(target).is_err());
    }

    fn copy_tree(source: &Path, destination: &Path) {
        for entry in fs::read_dir(source)
            .unwrap_or_else(|error| panic!("fixture directory read failed: {error}"))
        {
            let entry = entry.unwrap_or_else(|error| panic!("fixture entry failed: {error}"));
            let target = destination.join(entry.file_name());
            let metadata = entry
                .metadata()
                .unwrap_or_else(|error| panic!("fixture metadata failed: {error}"));
            if metadata.is_dir() {
                fs::create_dir(&target)
                    .unwrap_or_else(|error| panic!("fixture directory copy failed: {error}"));
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), &target)
                    .unwrap_or_else(|error| panic!("fixture file copy failed: {error}"));
            }
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
}

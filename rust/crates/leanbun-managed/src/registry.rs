use super::{
    MAX_INPUT_FILE_BYTES, MAX_RECORD_BYTES, ManagedProjectError, ManagedProjectErrorKind,
    ManagedRecordV1, TOOLCHAIN, input_error, parse_record, path_text,
};
use crate::references::read_generation_reference_summary_v1;
use leanbun_core::{ExecutionId, ProjectId, Sha256, Sha256Hasher, project_id};
use leanbun_lock::LeanBunLockV1;
use leanbun_lock::PackageSourceKeyV1;
use leanbun_store::{
    LeanStoreLimitsV1, normalized_directory_tree_sha256_excluding_exact_files_v1,
    normalized_directory_tree_sha256_v1,
};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_REGISTRY_ENTRIES: usize = 10_000;
const MAX_GENERATION_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ManagedLibraryStateV1 {
    InvalidRecord,
    Missing,
    PendingRecovery,
    Unsupported,
    Drifted,
    Healthy,
    Unmanaged,
}

impl ManagedLibraryStateV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRecord => "invalid-record",
            Self::Missing => "missing",
            Self::PendingRecovery => "pending-recovery",
            Self::Unsupported => "unsupported",
            Self::Drifted => "drifted",
            Self::Healthy => "healthy",
            Self::Unmanaged => "unmanaged",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedLibraryDiagnosticV1 {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedLibraryStatusV1 {
    pub project_id: Option<ProjectId>,
    pub project_root: Option<PathBuf>,
    pub target: Option<String>,
    pub toolchain: Option<String>,
    pub state: ManagedLibraryStateV1,
    pub active_generation_sha256: Option<Sha256>,
    pub package_count: Option<usize>,
    pub pending_transaction: Option<ExecutionId>,
    pub previous_transaction: Option<ExecutionId>,
    pub rollback_available: bool,
    pub exact_package_source_keys: Vec<Sha256>,
    pub active_package_build_keys: Vec<Sha256>,
    pub source_reference_count: Option<usize>,
    pub artifact_reference_count: Option<usize>,
    pub artifact_cache_hits: Option<usize>,
    pub artifact_publications: Option<usize>,
    pub artifact_reuses: Option<usize>,
    pub diagnostics: Vec<ManagedLibraryDiagnosticV1>,
}

impl ManagedLibraryStatusV1 {
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let project_id =
            optional_json_string(self.project_id.map(|value| value.to_string()).as_deref());
        let project_path =
            optional_json_string(self.project_root.as_ref().and_then(|path| path.to_str()));
        let target = optional_json_string(self.target.as_deref());
        let toolchain = optional_json_string(self.toolchain.as_deref());
        let generation = optional_json_string(
            self.active_generation_sha256
                .map(|value| value.to_string())
                .as_deref(),
        );
        let package_count = self
            .package_count
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let pending = optional_json_string(
            self.pending_transaction
                .map(|value| value.to_string())
                .as_deref(),
        );
        let previous = optional_json_string(
            self.previous_transaction
                .map(|value| value.to_string())
                .as_deref(),
        );
        let source_keys = json_sha_array(&self.exact_package_source_keys);
        let build_keys = json_sha_array(&self.active_package_build_keys);
        let state = json_string(self.state.as_str());
        let rollback = self.rollback_available;
        let source_references = optional_json_usize(self.source_reference_count);
        let artifact_references = optional_json_usize(self.artifact_reference_count);
        let artifact_hits = optional_json_usize(self.artifact_cache_hits);
        let artifact_publications = optional_json_usize(self.artifact_publications);
        let artifact_reuses = optional_json_usize(self.artifact_reuses);
        let diagnostics = self
            .diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{{\"code\":{},\"message\":{}}}",
                    json_string(&diagnostic.code),
                    json_string(&diagnostic.message)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schemaVersion\":2,\"projectId\":{project_id},\"projectPath\":{project_path},\"target\":{target},\"toolchain\":{toolchain},\"status\":{state},\"activeGenerationSha256\":{generation},\"packageCount\":{package_count},\"pendingTransaction\":{pending},\"previousTransaction\":{previous},\"rollbackAvailable\":{rollback},\"exactPackageSourceKeys\":{source_keys},\"activePackageBuildKeys\":{build_keys},\"sourceReferenceCount\":{source_references},\"artifactReferenceCount\":{artifact_references},\"artifactCacheHits\":{artifact_hits},\"artifactPublications\":{artifact_publications},\"artifactReuses\":{artifact_reuses},\"automaticDeletion\":false,\"diagnostics\":[{diagnostics}]}}"
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRegistryReportV1 {
    pub projects: Vec<ManagedLibraryStatusV1>,
}

impl ManagedRegistryReportV1 {
    #[must_use]
    pub fn all_healthy(&self) -> bool {
        self.projects
            .iter()
            .all(|project| project.state == ManagedLibraryStateV1::Healthy)
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let projects = self
            .projects
            .iter()
            .map(ManagedLibraryStatusV1::to_canonical_json)
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"schemaVersion\":2,\"projects\":[{projects}]}}")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GenerationSummaryV1 {
    transaction: ExecutionId,
    project_id: ProjectId,
    project_root: PathBuf,
    generation_root: PathBuf,
    lock_sha256: Sha256,
    graph_sha256: Sha256,
    decision_set_sha256: Sha256,
    manifest_projection_sha256: Sha256,
    runtime_projection_sha256: Sha256,
    reservoir_bindings_sha256: Option<Sha256>,
    toolchain: String,
    compiler_githash: String,
    lake_version: String,
    package_count: usize,
    packages: Vec<GenerationPackageSummaryV1>,
    identity: Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GenerationPackageSummaryV1 {
    scope: String,
    name: String,
    final_path: PathBuf,
    store_object_sha256: Sha256,
    source_tree_sha256: Sha256,
}

pub fn read_managed_registry_v1(
    repository: impl AsRef<Path>,
) -> Result<ManagedRegistryReportV1, ManagedProjectError> {
    let repository = canonical_repository(repository.as_ref())?;
    let state_root = repository.join(".leanbun-dev-rust");
    let authority = state_root.join("managed-projects");
    let registry = authority.join("registry");
    if !existing_directory(&state_root, None, "development state root")? {
        return Ok(ManagedRegistryReportV1 {
            projects: Vec::new(),
        });
    }
    if !existing_directory(&authority, Some(0o700), "managed authority")? {
        return Ok(ManagedRegistryReportV1 {
            projects: Vec::new(),
        });
    }
    let before = match fs::symlink_metadata(&registry) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ManagedRegistryReportV1 {
                projects: Vec::new(),
            });
        }
        Err(error) => return Err(mapped_error(error)),
    };
    if !before.file_type().is_dir() || before.permissions().mode() & 0o777 != 0o700 {
        return Err(input_error("managed registry is not a private directory"));
    }
    if before.nlink() == 0 {
        return Err(input_error("managed registry directory is unlinked"));
    }
    let mut paths = fs::read_dir(&registry)
        .map_err(mapped_error)?
        .map(|entry| entry.map(|entry| entry.path()).map_err(mapped_error))
        .collect::<Result<Vec<_>, _>>()?;
    if paths.len() > MAX_REGISTRY_ENTRIES {
        return Err(input_error("managed registry entry count exceeds limit"));
    }
    paths.sort_by(|left, right| {
        left.as_os_str()
            .as_encoded_bytes()
            .cmp(right.as_os_str().as_encoded_bytes())
    });
    let mut projects = paths
        .iter()
        .map(|path| inspect_registry_entry(&repository, &authority, path))
        .collect::<Vec<_>>();
    let after = fs::symlink_metadata(&registry).map_err(mapped_error)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.permissions().mode() & 0o777 != after.permissions().mode() & 0o777
    {
        return Err(input_error("managed registry changed during enumeration"));
    }
    projects.sort_by_key(status_sort_key);
    Ok(ManagedRegistryReportV1 { projects })
}

pub fn managed_library_status_v1(
    repository: impl AsRef<Path>,
    query: impl AsRef<Path>,
) -> Result<ManagedLibraryStatusV1, ManagedProjectError> {
    let query = query.as_ref();
    let report = read_managed_registry_v1(repository)?;
    let parsed_id = query
        .to_str()
        .and_then(|value| ProjectId::parse(value).ok());
    let absolute = if parsed_id.is_some() {
        None
    } else {
        Some(normalized_absolute(query)?)
    };
    if let Some(status) = report.projects.into_iter().find(|status| {
        parsed_id.is_some() && status.project_id == parsed_id
            || absolute
                .as_ref()
                .is_some_and(|path| status.project_root.as_ref() == Some(path))
    }) {
        return Ok(status);
    }
    let project_root = absolute;
    let project_id = parsed_id.or_else(|| {
        project_root
            .as_ref()
            .and_then(|path| path.to_str())
            .map(project_id)
    });
    Ok(ManagedLibraryStatusV1 {
        project_id,
        project_root,
        target: None,
        toolchain: None,
        state: ManagedLibraryStateV1::Unmanaged,
        active_generation_sha256: None,
        package_count: None,
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
        diagnostics: vec![diagnostic(
            "MANAGED_PROJECT_UNMANAGED",
            "project has no managed registry record",
        )],
    })
}

fn inspect_registry_entry(
    repository: &Path,
    authority: &Path,
    path: &Path,
) -> ManagedLibraryStatusV1 {
    match inspect_registry_entry_result(repository, authority, path) {
        Ok(status) => status,
        Err(error) => invalid_status(
            path.file_name().and_then(|name| name.to_str()),
            "MANAGED_RECORD_INVALID",
            &error.to_string(),
        ),
    }
}

fn inspect_registry_entry_result(
    _repository: &Path,
    authority: &Path,
    path: &Path,
) -> Result<ManagedLibraryStatusV1, ManagedProjectError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| input_error("managed registry filename is not UTF-8"))?;
    let encoded_id = file_name
        .strip_suffix(".record")
        .ok_or_else(|| input_error("managed registry contains a non-record entry"))?;
    let filename_id = ProjectId::parse(encoded_id)
        .map_err(|_| input_error("managed record filename is not a ProjectId"))?;
    let record = parse_record(&stable_read_file(
        path,
        MAX_RECORD_BYTES,
        Some(0o600),
        "managed record",
    )?)?;
    if record.project_id != filename_id
        || path_text(&record.project_root).ok().map(project_id) != Some(record.project_id)
    {
        return Err(input_error(
            "managed record filename, path, and ProjectId do not agree",
        ));
    }
    if !record.project_root.is_absolute()
        || record
            .project_root
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || record.project_root.starts_with(authority)
    {
        return Err(input_error(
            "managed project path is outside its authority contract",
        ));
    }
    let base = status_from_record(&record);
    let project_metadata = match fs::symlink_metadata(&record.project_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(with_state(
                base,
                ManagedLibraryStateV1::Missing,
                "MANAGED_PROJECT_MISSING",
                "registered project path no longer exists",
            ));
        }
        Err(error) => {
            return Ok(with_state(
                base,
                ManagedLibraryStateV1::Drifted,
                "MANAGED_PROJECT_UNREADABLE",
                &error.to_string(),
            ));
        }
    };
    if !project_metadata.file_type().is_dir()
        || record.project_root.canonicalize().ok().as_ref() != Some(&record.project_root)
    {
        return Ok(with_state(
            base,
            ManagedLibraryStateV1::Drifted,
            "MANAGED_PROJECT_PATH_DRIFT",
            "registered project path is not the same canonical directory",
        ));
    }
    if record.pending_transaction.is_some() {
        return Ok(with_state(
            base,
            ManagedLibraryStateV1::PendingRecovery,
            "MANAGED_PROJECT_PENDING_RECOVERY",
            "managed project has an unfinished transaction",
        ));
    }
    match verify_registered_generation(authority, &record) {
        Ok((summary, lock)) => {
            let mut status = status_from_record(&record);
            status.toolchain = Some(summary.toolchain);
            status.active_generation_sha256 = Some(summary.identity);
            status.package_count = Some(summary.package_count);
            status.exact_package_source_keys = lock
                .packages()
                .iter()
                .filter_map(PackageSourceKeyV1::from_locked_package)
                .map(PackageSourceKeyV1::digest)
                .collect();
            status.exact_package_source_keys.sort();
            let project_control = authority
                .join("project-control")
                .join(record.project_id.to_string());
            if let Some(references) =
                read_generation_reference_summary_v1(&project_control, summary.identity)?
            {
                status.active_package_build_keys = references.build_keys;
                status.active_package_build_keys.sort();
                status.source_reference_count = Some(references.source_references);
                status.artifact_reference_count = Some(references.artifact_references);
                status.artifact_cache_hits = Some(references.artifact_cache_hits);
                status.artifact_publications = Some(references.artifact_publications);
                status.artifact_reuses = Some(references.artifact_reuses);
                let mut recorded_sources = references.source_keys;
                recorded_sources.sort();
                if references.source_references != status.exact_package_source_keys.len()
                    || recorded_sources.iter().any(|source| {
                        status
                            .exact_package_source_keys
                            .binary_search(source)
                            .is_err()
                    })
                {
                    return Err(input_error(
                        "active generation source references differ from exact lock",
                    ));
                }
            }
            if lock.lean_toolchain() != TOOLCHAIN
                || lock.lean_compiler_githash() != super::COMPILER
                || lock.lake_version() != super::LAKE_VERSION
            {
                return Ok(with_state(
                    status,
                    ManagedLibraryStateV1::Unsupported,
                    "MANAGED_PROJECT_TOOLCHAIN_UNSUPPORTED",
                    "managed project toolchain is not supported by this binary",
                ));
            }
            status.state = ManagedLibraryStateV1::Healthy;
            Ok(status)
        }
        Err(error) if error.kind == ManagedProjectErrorKind::UnsupportedDependencyGraph => {
            Ok(with_state(
                base,
                ManagedLibraryStateV1::Unsupported,
                "MANAGED_PROJECT_UNSUPPORTED",
                &error.to_string(),
            ))
        }
        Err(error) => Ok(with_state(
            base,
            ManagedLibraryStateV1::Drifted,
            "MANAGED_PROJECT_DRIFT",
            &error.to_string(),
        )),
    }
}

fn verify_registered_generation(
    authority: &Path,
    record: &ManagedRecordV1,
) -> Result<(GenerationSummaryV1, LeanBunLockV1), ManagedProjectError> {
    let project_state = authority
        .join("generation-state/projects")
        .join(record.project_id.to_string());
    let active_path = project_state.join("active.record");
    let (active_transaction, active_generation, active_root) =
        parse_active_record(&stable_read_file(
            &active_path,
            MAX_RECORD_BYTES,
            Some(0o444),
            "active generation record",
        )?)?;
    let expected_root = project_state
        .join("generations")
        .join(record.active_transaction.as_str());
    if active_transaction != record.active_transaction || active_root != expected_root {
        return Err(input_error(
            "active generation record differs from managed record",
        ));
    }
    let transaction_path = project_state
        .join("transactions")
        .join(format!("{}.record", record.active_transaction));
    verify_published_transaction(
        &stable_read_file(
            &transaction_path,
            MAX_RECORD_BYTES,
            Some(0o444),
            "generation transaction record",
        )?,
        record,
        active_generation,
    )?;
    let metadata_path = active_root.join("generation.meta");
    let summary = parse_generation_metadata(&stable_read_file(
        &metadata_path,
        MAX_GENERATION_METADATA_BYTES,
        Some(0o444),
        "generation metadata",
    )?)?;
    if summary.transaction != record.active_transaction
        || summary.project_id != record.project_id
        || summary.project_root != record.project_root
        || summary.generation_root != active_root
        || summary.identity != active_generation
    {
        return Err(input_error(
            "generation metadata differs from active authority",
        ));
    }
    let expected_identity = generation_identity(&summary)?;
    if expected_identity != summary.identity {
        return Err(input_error("generation metadata identity is invalid"));
    }
    let lock_path = active_root.join("leanbun.lock");
    let lock_bytes = stable_read_file(
        &lock_path,
        MAX_GENERATION_METADATA_BYTES,
        Some(0o444),
        "generation lock",
    )?;
    let lock_text = std::str::from_utf8(&lock_bytes)
        .map_err(|_| input_error("generation lock is not UTF-8"))?;
    if !lock_text.starts_with("leanbun-lock-v1\t1\n") {
        return Err(unsupported_error("generation lock schema is unsupported"));
    }
    let lock = LeanBunLockV1::from_canonical_text(lock_text)
        .map_err(|error| input_error(error.to_string()))?;
    if lock_bytes_sha256(&lock_bytes) != summary.lock_sha256
        || lock.packages().len() != summary.package_count
    {
        return Err(input_error(
            "generation lock identity or package count drifted",
        ));
    }
    verify_project_inputs(record, &lock, &summary)?;
    verify_generation_files(&summary)?;
    Ok((summary, lock))
}

fn verify_project_inputs(
    record: &ManagedRecordV1,
    lock: &LeanBunLockV1,
    summary: &GenerationSummaryV1,
) -> Result<(), ManagedProjectError> {
    let toml = existing_regular_file(&record.project_root.join("lakefile.toml"), "lakefile.toml")?;
    let lean = existing_regular_file(&record.project_root.join("lakefile.lean"), "lakefile.lean")?;
    let config = match (toml, lean) {
        (true, false) => "lakefile.toml",
        (false, true) => "lakefile.lean",
        _ => return Err(input_error("managed project config selection drifted")),
    };
    let config_bytes = stable_read_file(
        &record.project_root.join(config),
        MAX_INPUT_FILE_BYTES,
        None,
        "managed root config",
    )?;
    if sha256_bytes(&config_bytes) != lock.root_config_sha256() {
        return Err(input_error("managed root config hash drifted"));
    }
    let toolchain_bytes = stable_read_file(
        &record.project_root.join("lean-toolchain"),
        MAX_INPUT_FILE_BYTES,
        None,
        "managed Lean toolchain",
    )?;
    let toolchain = std::str::from_utf8(&toolchain_bytes)
        .map_err(|_| input_error("managed Lean toolchain is not UTF-8"))?;
    if toolchain.trim() != lock.lean_toolchain()
        || summary.toolchain != lock.lean_toolchain()
        || summary.compiler_githash != lock.lean_compiler_githash()
        || summary.lake_version != lock.lake_version()
    {
        return Err(input_error("managed Lean toolchain drifted"));
    }
    let manifest_path = record.project_root.join("lake-manifest.json");
    let manifest_bytes = if existing_regular_file(&manifest_path, "lake-manifest.json")? {
        Some(stable_read_file(
            &manifest_path,
            MAX_INPUT_FILE_BYTES,
            None,
            "managed Lake manifest",
        )?)
    } else {
        None
    };
    let expected_management = management_input_sha256_from_bytes(
        config,
        &config_bytes,
        &toolchain_bytes,
        manifest_bytes.as_deref(),
        lock.root_declaration_sha256(),
    );
    if expected_management != record.management_input_sha256 {
        return Err(input_error("managed input identity drifted"));
    }
    Ok(())
}

fn verify_generation_files(summary: &GenerationSummaryV1) -> Result<(), ManagedProjectError> {
    for (relative, expected) in [
        ("lake-manifest.json", summary.manifest_projection_sha256),
        ("runtime-packages.json", summary.runtime_projection_sha256),
    ] {
        let path = summary.generation_root.join(relative);
        let bytes = stable_read_file(&path, MAX_GENERATION_METADATA_BYTES, Some(0o444), relative)?;
        if sha256_bytes(&bytes) != expected {
            return Err(input_error(format!("generation {relative} hash drifted")));
        }
    }
    for package in &summary.packages {
        if !package
            .final_path
            .starts_with(summary.generation_root.join("packages"))
            || !package.final_path.is_dir()
        {
            return Err(input_error("generation package final path drifted"));
        }
        let limits = LeanStoreLimitsV1::registered_provider();
        let observed = if package.scope == "leanprover-community" && package.name == "proofwidgets"
        {
            normalized_directory_tree_sha256_excluding_exact_files_v1(
                &package.final_path,
                limits,
                &["widget/package-lock.json.hash"],
            )
        } else {
            normalized_directory_tree_sha256_v1(&package.final_path, limits)
        }
        .map_err(|error| input_error(error.to_string()))?;
        if observed != package.source_tree_sha256 {
            return Err(input_error("generation package source tree drifted"));
        }
    }
    Ok(())
}

fn lock_bytes_sha256(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-lock-bytes-v1\0");
    hasher.update(bytes);
    hasher.finalize()
}

fn sha256_bytes(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn management_input_sha256_from_bytes(
    config_name: &str,
    config: &[u8],
    toolchain: &[u8],
    manifest: Option<&[u8]>,
    declaration: Sha256,
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-managed-input-v1\0");
    hasher.update(declaration.as_bytes());
    for (relative, bytes) in [
        (config_name, Some(config)),
        ("lean-toolchain", Some(toolchain)),
        ("lake-manifest.json", manifest),
    ] {
        let Some(bytes) = bytes else {
            continue;
        };
        let digest = sha256_bytes(bytes);
        hasher.update(&(relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(digest.as_bytes());
    }
    hasher.finalize()
}

fn parse_active_record(
    bytes: &[u8],
) -> Result<(ExecutionId, Sha256, PathBuf), ManagedProjectError> {
    let text = std::str::from_utf8(bytes).map_err(|_| input_error("active record is not UTF-8"))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 5 || lines[0] != "leanbun-active-generation-v1\t1" || lines[4] != "end-active"
    {
        return Err(input_error("active record shape is invalid"));
    }
    let transaction = ExecutionId::parse(field(lines[1], "transaction")?)
        .map_err(|error| input_error(error.to_string()))?;
    let generation = Sha256::parse(field(lines[2], "generation")?)
        .map_err(|error| input_error(error.to_string()))?;
    let path = PathBuf::from(field(lines[3], "path")?);
    let canonical = format!(
        "leanbun-active-generation-v1\t1\ntransaction\t{transaction}\ngeneration\t{generation}\npath\t{}\nend-active\n",
        path_text(&path)?
    );
    if canonical.as_bytes() != bytes {
        return Err(input_error("active record is not canonical"));
    }
    Ok((transaction, generation, path))
}

fn verify_published_transaction(
    bytes: &[u8],
    record: &ManagedRecordV1,
    generation: Sha256,
) -> Result<(), ManagedProjectError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| input_error("generation transaction is not UTF-8"))?;
    let expected = format!(
        "leanbun-generation-transaction-v1\t1\ntransaction\t{}\nproject-id\t{}\ngeneration\t{generation}\nstate\tpublished\nend-transaction\n",
        record.active_transaction, record.project_id
    );
    if text != expected {
        return Err(input_error(
            "active generation transaction is not published",
        ));
    }
    Ok(())
}

fn parse_generation_metadata(bytes: &[u8]) -> Result<GenerationSummaryV1, ManagedProjectError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| input_error("generation metadata is not UTF-8"))?;
    let lines = text.lines().collect::<Vec<_>>();
    let version_two = lines.first() == Some(&"leanbun-generation-v2\t2");
    if !version_two && lines.first() != Some(&"leanbun-generation-v1\t1") {
        return Err(unsupported_error(
            "generation metadata schema is unsupported",
        ));
    }
    let mut index = 1;
    let transaction = ExecutionId::parse(take_field(&lines, &mut index, "transaction")?)
        .map_err(|error| input_error(error.to_string()))?;
    let project_id = ProjectId::parse(take_field(&lines, &mut index, "project-id")?)
        .map_err(|error| input_error(error.to_string()))?;
    let project_root = PathBuf::from(take_field(&lines, &mut index, "project-root")?);
    let generation_root = PathBuf::from(take_field(&lines, &mut index, "generation-root")?);
    let lock_sha256 = parse_sha(take_field(&lines, &mut index, "lock-sha256")?)?;
    let graph_sha256 = parse_sha(take_field(&lines, &mut index, "graph-sha256")?)?;
    let decision_set_sha256 = parse_sha(take_field(&lines, &mut index, "decision-set-sha256")?)?;
    let manifest_projection_sha256 = parse_sha(take_field(
        &lines,
        &mut index,
        "manifest-projection-sha256",
    )?)?;
    let runtime_projection_sha256 =
        parse_sha(take_field(&lines, &mut index, "runtime-projection-sha256")?)?;
    let reservoir_bindings_sha256 = if version_two {
        Some(parse_sha(take_field(
            &lines,
            &mut index,
            "reservoir-bindings-sha256",
        )?)?)
    } else {
        None
    };
    let toolchain = decode_hex(take_field(&lines, &mut index, "lean-toolchain")?)?;
    let compiler_githash = take_field(&lines, &mut index, "compiler-githash")?.to_owned();
    let lake_version = decode_hex(take_field(&lines, &mut index, "lake-version")?)?;
    let package_count = take_field(&lines, &mut index, "package-count")?
        .parse::<usize>()
        .map_err(|_| input_error("generation package count is invalid"))?;
    if package_count > 10_000 {
        return Err(input_error("generation package count exceeds limit"));
    }
    let mut packages = Vec::with_capacity(package_count);
    for _ in 0..package_count {
        let line = lines
            .get(index)
            .ok_or_else(|| input_error("generation package entry is missing"))?;
        index += 1;
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 6 || fields[0] != "package" {
            return Err(input_error("generation package entry is invalid"));
        }
        packages.push(GenerationPackageSummaryV1 {
            scope: decode_hex(fields[1])?,
            name: decode_hex(fields[2])?,
            final_path: PathBuf::from(fields[3]),
            store_object_sha256: parse_sha(fields[4])?,
            source_tree_sha256: parse_sha(fields[5])?,
        });
    }
    let identity = parse_sha(take_field(&lines, &mut index, "generation-sha256")?)?;
    if lines.get(index) != Some(&"end-generation") || index + 1 != lines.len() {
        return Err(input_error(
            "generation metadata has trailing or missing fields",
        ));
    }
    let summary = GenerationSummaryV1 {
        transaction,
        project_id,
        project_root,
        generation_root,
        lock_sha256,
        graph_sha256,
        decision_set_sha256,
        manifest_projection_sha256,
        runtime_projection_sha256,
        reservoir_bindings_sha256,
        toolchain,
        compiler_githash,
        lake_version,
        package_count,
        packages,
        identity,
    };
    if canonical_generation_metadata(&summary).as_bytes() != bytes {
        return Err(input_error("generation metadata is not canonical"));
    }
    Ok(summary)
}

fn canonical_generation_metadata(summary: &GenerationSummaryV1) -> String {
    let mut output = if summary.reservoir_bindings_sha256.is_some() {
        String::from("leanbun-generation-v2\t2\n")
    } else {
        String::from("leanbun-generation-v1\t1\n")
    };
    output.push_str(&format!(
        "transaction\t{}\nproject-id\t{}\nproject-root\t{}\ngeneration-root\t{}\nlock-sha256\t{}\ngraph-sha256\t{}\ndecision-set-sha256\t{}\nmanifest-projection-sha256\t{}\nruntime-projection-sha256\t{}\n",
        summary.transaction,
        summary.project_id,
        summary.project_root.display(),
        summary.generation_root.display(),
        summary.lock_sha256,
        summary.graph_sha256,
        summary.decision_set_sha256,
        summary.manifest_projection_sha256,
        summary.runtime_projection_sha256,
    ));
    if let Some(identity) = summary.reservoir_bindings_sha256 {
        output.push_str(&format!("reservoir-bindings-sha256\t{identity}\n"));
    }
    output.push_str(&format!(
        "lean-toolchain\t{}\ncompiler-githash\t{}\nlake-version\t{}\npackage-count\t{}\n",
        encode_hex(summary.toolchain.as_bytes()),
        summary.compiler_githash,
        encode_hex(summary.lake_version.as_bytes()),
        summary.package_count,
    ));
    for package in &summary.packages {
        output.push_str(&format!(
            "package\t{}\t{}\t{}\t{}\t{}\n",
            encode_hex(package.scope.as_bytes()),
            encode_hex(package.name.as_bytes()),
            package.final_path.display(),
            package.store_object_sha256,
            package.source_tree_sha256,
        ));
    }
    output.push_str(&format!(
        "generation-sha256\t{}\nend-generation\n",
        summary.identity
    ));
    output
}

fn generation_identity(summary: &GenerationSummaryV1) -> Result<Sha256, ManagedProjectError> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(if summary.reservoir_bindings_sha256.is_some() {
        b"leanbun-generation-identity-v2\0"
    } else {
        b"leanbun-generation-identity-v1\0"
    });
    hasher.update(summary.transaction.as_str().as_bytes());
    hasher.update(summary.project_id.digest().as_bytes());
    hash_text(&mut hasher, path_text(&summary.generation_root)?);
    for digest in [
        summary.lock_sha256,
        summary.graph_sha256,
        summary.decision_set_sha256,
        summary.manifest_projection_sha256,
        summary.runtime_projection_sha256,
    ] {
        hasher.update(digest.as_bytes());
    }
    if let Some(identity) = summary.reservoir_bindings_sha256 {
        hasher.update(identity.as_bytes());
    }
    hasher.update(&(summary.packages.len() as u64).to_be_bytes());
    for package in &summary.packages {
        hash_text(&mut hasher, &package.scope);
        hash_text(&mut hasher, &package.name);
        hash_text(&mut hasher, path_text(&package.final_path)?);
        hasher.update(package.store_object_sha256.as_bytes());
        hasher.update(package.source_tree_sha256.as_bytes());
    }
    Ok(hasher.finalize())
}

fn status_from_record(record: &ManagedRecordV1) -> ManagedLibraryStatusV1 {
    ManagedLibraryStatusV1 {
        project_id: Some(record.project_id),
        project_root: Some(record.project_root.clone()),
        target: Some(record.target.clone()),
        toolchain: None,
        state: ManagedLibraryStateV1::Drifted,
        active_generation_sha256: None,
        package_count: None,
        pending_transaction: record.pending_transaction,
        previous_transaction: record.previous_transaction,
        rollback_available: record.previous_transaction.is_some(),
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

fn with_state(
    mut status: ManagedLibraryStatusV1,
    state: ManagedLibraryStateV1,
    code: &str,
    message: &str,
) -> ManagedLibraryStatusV1 {
    status.state = state;
    status.diagnostics.push(diagnostic(code, message));
    status
}

fn invalid_status(filename: Option<&str>, code: &str, message: &str) -> ManagedLibraryStatusV1 {
    let project_id = filename
        .and_then(|name| name.strip_suffix(".record"))
        .and_then(|value| ProjectId::parse(value).ok());
    ManagedLibraryStatusV1 {
        project_id,
        project_root: None,
        target: None,
        toolchain: None,
        state: ManagedLibraryStateV1::InvalidRecord,
        active_generation_sha256: None,
        package_count: None,
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
        diagnostics: vec![diagnostic(code, message)],
    }
}

fn diagnostic(code: &str, message: &str) -> ManagedLibraryDiagnosticV1 {
    let mut message = message.replace(['\n', '\r', '\t'], " ");
    if message.len() > MAX_DIAGNOSTIC_BYTES {
        let mut boundary = MAX_DIAGNOSTIC_BYTES;
        while !message.is_char_boundary(boundary) {
            boundary -= 1;
        }
        message.truncate(boundary);
    }
    ManagedLibraryDiagnosticV1 {
        code: code.to_owned(),
        message,
    }
}

fn canonical_repository(path: &Path) -> Result<PathBuf, ManagedProjectError> {
    let repository = path.canonicalize().map_err(mapped_error)?;
    if !repository.join("TEST_PROJECT_BOUNDARY.adoc").is_file()
        || !repository.join("config/upstream-bun.lock.json").is_file()
    {
        return Err(input_error("repository is not a LeanBun source root"));
    }
    Ok(repository)
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, ManagedProjectError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(input_error(
            "managed project query must be normalized and absolute",
        ));
    }
    Ok(path.to_path_buf())
}

fn existing_directory(
    path: &Path,
    mode: Option<u32>,
    label: &str,
) -> Result<bool, ManagedProjectError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(mapped_error(error)),
    };
    if !metadata.file_type().is_dir()
        || mode.is_some_and(|expected| metadata.permissions().mode() & 0o777 != expected)
    {
        return Err(input_error(format!("{label} is not a trusted directory")));
    }
    Ok(true)
}

fn existing_regular_file(path: &Path, label: &str) -> Result<bool, ManagedProjectError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(input_error(format!("{label} is not a regular file"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(mapped_error(error)),
    }
}

fn stable_read_file(
    path: &Path,
    maximum: u64,
    mode: Option<u32>,
    label: &str,
) -> Result<Vec<u8>, ManagedProjectError> {
    let before = fs::symlink_metadata(path).map_err(mapped_error)?;
    if !before.file_type().is_file()
        || before.len() > maximum
        || mode.is_some_and(|expected| before.permissions().mode() & 0o777 != expected)
    {
        return Err(input_error(format!(
            "{label} is not a bounded trusted file"
        )));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(mapped_error)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(mapped_error)?;
    let after = fs::symlink_metadata(path).map_err(mapped_error)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.permissions().mode() & 0o777 != after.permissions().mode() & 0o777
        || bytes.len() as u64 != before.len()
    {
        return Err(input_error(format!("{label} changed while reading")));
    }
    Ok(bytes)
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str, ManagedProjectError> {
    line.strip_prefix(name)
        .and_then(|value| value.strip_prefix('\t'))
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| input_error(format!("managed generation field is invalid: {name}")))
}

fn take_field<'a>(
    lines: &'a [&'a str],
    index: &mut usize,
    name: &str,
) -> Result<&'a str, ManagedProjectError> {
    let line = lines
        .get(*index)
        .ok_or_else(|| input_error(format!("managed generation field is missing: {name}")))?;
    *index += 1;
    field(line, name)
}

fn parse_sha(value: &str) -> Result<Sha256, ManagedProjectError> {
    Sha256::parse(value).map_err(|error| input_error(error.to_string()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(TABLE[usize::from(byte >> 4)]));
        output.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Result<String, ManagedProjectError> {
    if !value.len().is_multiple_of(2) {
        return Err(input_error("hex field has odd length"));
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(mapped_error)?;
            u8::from_str_radix(pair, 16).map_err(mapped_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(mapped_error)
}

fn mapped_error(error: impl std::fmt::Display) -> ManagedProjectError {
    input_error(error.to_string())
}

fn unsupported_error(message: impl Into<String>) -> ManagedProjectError {
    ManagedProjectError {
        kind: ManagedProjectErrorKind::UnsupportedDependencyGraph,
        message: message.into(),
    }
}

fn hash_text(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn status_sort_key(status: &ManagedLibraryStatusV1) -> (u8, String) {
    match status.project_id {
        Some(id) => (0, id.to_string()),
        None => (
            1,
            status
                .diagnostics
                .first()
                .map_or_else(String::new, |value| value.message.clone()),
        ),
    }
}

fn optional_json_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), json_string)
}

fn optional_json_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn json_sha_array(values: &[Sha256]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| json_string(&value.to_string()))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value < '\u{20}' => output.push_str(&format!("\\u{:04x}", u32::from(value))),
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{COMPILER, LAKE_VERSION, ManagedRecordV1, record_bytes};
    use leanbun_codec::parse_strict_json;
    use leanbun_lake_bridge::{
        LakeManifestProjectionV1, LakeRootDeclarationV1, LakeRuntimePackagesProjectionV1,
    };
    use leanbun_lock::PackagePathDecisionSetV1;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        project: PathBuf,
        authority: PathBuf,
        record: ManagedRecordV1,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "leanbun-managed-registry-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&root)?;
            let root = root.canonicalize()?;
            fs::write(root.join("TEST_PROJECT_BOUNDARY.adoc"), "fixture\n")?;
            fs::create_dir(root.join("config"))?;
            fs::write(root.join("config/upstream-bun.lock.json"), "{}\n")?;
            let project = root.join("project");
            fs::create_dir(&project)?;
            fs::write(
                project.join("lakefile.toml"),
                "name = \"registry_fixture\"\nversion = \"0.1.0\"\n",
            )?;
            fs::write(project.join("lean-toolchain"), format!("{TOOLCHAIN}\n"))?;
            fs::write(
                project.join("lake-manifest.json"),
                "{\"version\":\"1.2.0\",\"packages\":[]}\n",
            )?;
            let project = project.canonicalize()?;
            let project_id = project_id(path_text(&project)?);
            let authority = root.join(".leanbun-dev-rust/managed-projects");
            let registry = authority.join("registry");
            let project_state = authority
                .join("generation-state/projects")
                .join(project_id.to_string());
            let transaction = ExecutionId::parse("49000000-0000-4000-8000-000000000001")?;
            let generation_root = project_state.join("generations").join(transaction.as_str());
            fs::create_dir_all(&registry)?;
            fs::create_dir_all(project_state.join("transactions"))?;
            fs::create_dir_all(&generation_root)?;
            for path in [
                authority.clone(),
                registry.clone(),
                authority.join("generation-state"),
                authority.join("generation-state/projects"),
                project_state.clone(),
                project_state.join("generations"),
                project_state.join("transactions"),
                generation_root.clone(),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            let declaration =
                LakeRootDeclarationV1::new("registry_fixture", "lakefile.toml", Vec::new())?;
            let config_bytes = fs::read(project.join("lakefile.toml"))?;
            let toolchain_bytes = fs::read(project.join("lean-toolchain"))?;
            let manifest_bytes = fs::read(project.join("lake-manifest.json"))?;
            let lock = LeanBunLockV1::new(
                TOOLCHAIN,
                COMPILER,
                LAKE_VERSION,
                sha256_bytes(&config_bytes),
                declaration.identity(),
                Vec::new(),
            )?;
            let decisions = PackagePathDecisionSetV1::new(&lock, Vec::new())?;
            let manifest = LakeManifestProjectionV1::new(&declaration, &lock, Vec::new())?;
            let runtime =
                LakeRuntimePackagesProjectionV1::from_bun_decisions(&lock, &decisions, Vec::new())?;
            let management_input_sha256 = management_input_sha256_from_bytes(
                "lakefile.toml",
                &config_bytes,
                &toolchain_bytes,
                Some(&manifest_bytes),
                declaration.identity(),
            );
            let mut summary = GenerationSummaryV1 {
                transaction,
                project_id,
                project_root: project.clone(),
                generation_root: generation_root.clone(),
                lock_sha256: lock_bytes_sha256(lock.to_canonical_text().as_bytes()),
                graph_sha256: digest(b"graph"),
                decision_set_sha256: decisions.digest(),
                manifest_projection_sha256: manifest.sha256(),
                runtime_projection_sha256: runtime.sha256(),
                reservoir_bindings_sha256: None,
                toolchain: TOOLCHAIN.to_owned(),
                compiler_githash: COMPILER.to_owned(),
                lake_version: LAKE_VERSION.to_owned(),
                package_count: 0,
                packages: Vec::new(),
                identity: digest(b"pending-generation"),
            };
            summary.identity = generation_identity(&summary)?;
            write_mode(
                &generation_root.join("generation.meta"),
                canonical_generation_metadata(&summary).as_bytes(),
                0o444,
            )?;
            write_mode(
                &generation_root.join("leanbun.lock"),
                lock.to_canonical_text().as_bytes(),
                0o444,
            )?;
            write_mode(
                &generation_root.join("lake-manifest.json"),
                manifest.as_str().as_bytes(),
                0o444,
            )?;
            write_mode(
                &generation_root.join("runtime-packages.json"),
                runtime.as_str().as_bytes(),
                0o444,
            )?;
            write_mode(
                &project_state.join("active.record"),
                format!(
                    "leanbun-active-generation-v1\t1\ntransaction\t{transaction}\ngeneration\t{}\npath\t{}\nend-active\n",
                    summary.identity,
                    generation_root.display()
                )
                .as_bytes(),
                0o444,
            )?;
            write_mode(
                &project_state
                    .join("transactions")
                    .join(format!("{transaction}.record")),
                format!(
                    "leanbun-generation-transaction-v1\t1\ntransaction\t{transaction}\nproject-id\t{project_id}\ngeneration\t{}\nstate\tpublished\nend-transaction\n",
                    summary.identity
                )
                .as_bytes(),
                0o444,
            )?;
            let record = ManagedRecordV1 {
                project_id,
                project_root: project.clone(),
                target: "registry_fixture".to_owned(),
                management_input_sha256,
                baseline_transaction: transaction,
                active_transaction: transaction,
                previous_transaction: None,
                pending_transaction: None,
            };
            write_mode(
                &registry.join(format!("{project_id}.record")),
                &record_bytes(&record)?,
                0o600,
            )?;
            Ok(Self {
                root,
                project,
                authority,
                record,
            })
        }

        fn record_path(&self) -> PathBuf {
            self.authority
                .join("registry")
                .join(format!("{}.record", self.record.project_id))
        }

        fn replace_record(
            &self,
            record: &ManagedRecordV1,
        ) -> Result<(), Box<dyn std::error::Error>> {
            fs::set_permissions(self.record_path(), fs::Permissions::from_mode(0o600))?;
            fs::write(self.record_path(), record_bytes(record)?)?;
            Ok(())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = make_writable(&self.root);
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn healthy_registry_is_read_only_sorted_and_strict_json()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let report = read_managed_registry_v1(&fixture.root)?;
        assert!(report.all_healthy(), "{report:#?}");
        assert_eq!(report.projects.len(), 1);
        let status = &report.projects[0];
        assert_eq!(status.state, ManagedLibraryStateV1::Healthy);
        assert_eq!(status.project_id, Some(fixture.record.project_id));
        assert_eq!(status.package_count, Some(0));
        parse_strict_json(&report.to_canonical_json())?;
        parse_strict_json(&status.to_canonical_json())?;
        Ok(())
    }

    #[test]
    fn status_precedence_covers_pending_missing_unsupported_and_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let pending = Fixture::new()?;
        let mut pending_record = pending.record.clone();
        pending_record.pending_transaction =
            Some(ExecutionId::parse("49000000-0000-4000-8000-000000000002")?);
        pending.replace_record(&pending_record)?;
        assert_eq!(
            read_managed_registry_v1(&pending.root)?.projects[0].state,
            ManagedLibraryStateV1::PendingRecovery
        );

        let missing = Fixture::new()?;
        make_writable(&missing.project)?;
        fs::remove_dir_all(&missing.project)?;
        assert_eq!(
            read_managed_registry_v1(&missing.root)?.projects[0].state,
            ManagedLibraryStateV1::Missing
        );

        let drifted = Fixture::new()?;
        fs::write(
            drifted.project.join("lakefile.toml"),
            "name = \"changed\"\n",
        )?;
        assert_eq!(
            read_managed_registry_v1(&drifted.root)?.projects[0].state,
            ManagedLibraryStateV1::Drifted
        );

        let unsupported = Fixture::new()?;
        let metadata = unsupported
            .authority
            .join("generation-state/projects")
            .join(unsupported.record.project_id.to_string())
            .join("generations")
            .join(unsupported.record.active_transaction.as_str())
            .join("generation.meta");
        fs::set_permissions(&metadata, fs::Permissions::from_mode(0o600))?;
        let unsupported_text = fs::read_to_string(&metadata)?.replacen(
            "leanbun-generation-v1\t1",
            "leanbun-generation-v3\t3",
            1,
        );
        fs::write(&metadata, unsupported_text)?;
        fs::set_permissions(&metadata, fs::Permissions::from_mode(0o444))?;
        assert_eq!(
            read_managed_registry_v1(&unsupported.root)?.projects[0].state,
            ManagedLibraryStateV1::Unsupported
        );
        Ok(())
    }

    #[test]
    fn invalid_entry_is_visible_and_unmanaged_query_is_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let registry = fixture.authority.join("registry");
        fs::write(registry.join("abandoned.next"), b"partial")?;
        let report = read_managed_registry_v1(&fixture.root)?;
        assert_eq!(report.projects.len(), 2);
        assert!(
            report
                .projects
                .iter()
                .any(|status| status.state == ManagedLibraryStateV1::Healthy),
            "{report:#?}"
        );
        assert!(
            report
                .projects
                .iter()
                .any(|status| status.state == ManagedLibraryStateV1::InvalidRecord)
        );
        let unmanaged = managed_library_status_v1(&fixture.root, fixture.root.join("other"))?;
        assert_eq!(unmanaged.state, ManagedLibraryStateV1::Unmanaged);
        let unknown_id = ProjectId::parse(&"2".repeat(64))?;
        let unmanaged_id = managed_library_status_v1(&fixture.root, unknown_id.to_string())?;
        assert_eq!(unmanaged_id.project_id, Some(unknown_id));
        assert_eq!(unmanaged_id.state, ManagedLibraryStateV1::Unmanaged);
        assert!(managed_library_status_v1(&fixture.root, Path::new("relative-project")).is_err());

        let outside = fixture.root.join("outside.record");
        fs::write(&outside, b"outside")?;
        symlink(
            &outside,
            registry.join(format!("{}.record", "1".repeat(64))),
        )?;
        let report = read_managed_registry_v1(&fixture.root)?;
        assert_eq!(
            report
                .projects
                .iter()
                .filter(|status| status.state == ManagedLibraryStateV1::InvalidRecord)
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn unsafe_registry_mode_is_not_reported_as_empty() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::set_permissions(
            fixture.authority.join("registry"),
            fs::Permissions::from_mode(0o755),
        )?;
        assert!(read_managed_registry_v1(&fixture.root).is_err());

        let linked_registry = Fixture::new()?;
        let registry = linked_registry.authority.join("registry");
        fs::rename(&registry, linked_registry.authority.join("registry-backup"))?;
        symlink(linked_registry.root.join("missing-registry"), &registry)?;
        assert!(read_managed_registry_v1(&linked_registry.root).is_err());

        let linked_authority = Fixture::new()?;
        fs::rename(
            &linked_authority.authority,
            linked_authority.root.join("managed-projects-backup"),
        )?;
        symlink(
            linked_authority.root.join("missing-authority"),
            &linked_authority.authority,
        )?;
        assert!(read_managed_registry_v1(&linked_authority.root).is_err());

        let bounded = diagnostic("UNICODE", &"界".repeat(1_000));
        assert!(bounded.message.len() <= MAX_DIAGNOSTIC_BYTES);
        parse_strict_json(&format!(
            "{{\"message\":{}}}",
            json_string(&bounded.message)
        ))?;
        Ok(())
    }

    fn digest(bytes: &[u8]) -> Sha256 {
        let mut hasher = Sha256Hasher::new();
        hasher.update(bytes);
        hasher.finalize()
    }

    fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    fn make_writable(path: &Path) -> std::io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_dir() {
                make_writable(&entry.path())?;
            }
            if metadata.file_type().is_file() || metadata.file_type().is_dir() {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700))?;
            }
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }
}

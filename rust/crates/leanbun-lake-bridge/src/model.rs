use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher};
use leanbun_evidence::{StrictJson, parse_strict_json};
use leanbun_package::{
    LeanBunLockV1, PackageKeyV1, PackagePathDecisionSetV1, RequestedPackageSourceV1,
    ResolvedPackageSourceV1,
};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ROOT_DEPENDENCIES_V1: usize = 4_096;
const MAX_SHORT_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LakeBridgeErrorKind {
    InvalidField,
    LimitExceeded,
    MalformedProbeOutput,
    DuplicateDependency,
    DuplicatePackage,
    MissingPackage,
    ExtraPackage,
    SourceKindDrift,
    SourceValueDrift,
    NonBunRuntimeOverride,
    DuplicateObservedPath,
    MissingObservedPath,
    ExtraObservedPath,
    WorkspacePathMismatch,
    ProjectionParseFailed,
    ProbeBoundaryViolation,
    ProbeFailed,
    EvidenceChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeBridgeError {
    pub kind: LakeBridgeErrorKind,
    pub message: String,
}

impl LakeBridgeError {
    pub(crate) fn new(kind: LakeBridgeErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for LakeBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LakeBridgeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LakeDependencySourceV1 {
    Git {
        url: String,
        revision: Option<String>,
        subdir: Option<String>,
    },
    Path {
        directory: String,
    },
    Reservoir,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeRootDependencyV1 {
    key: PackageKeyV1,
    version: Option<String>,
    source: LakeDependencySourceV1,
}

impl LakeRootDependencyV1 {
    pub fn new(
        key: PackageKeyV1,
        version: Option<String>,
        source: LakeDependencySourceV1,
    ) -> Result<Self, LakeBridgeError> {
        if let Some(value) = version.as_deref() {
            validate_text(value, MAX_TEXT_BYTES, false, "dependency version")?;
        }
        match &source {
            LakeDependencySourceV1::Git {
                url,
                revision,
                subdir,
            } => {
                validate_https_url(url)?;
                if let Some(value) = revision.as_deref() {
                    validate_text(value, MAX_TEXT_BYTES, false, "dependency Git revision")?;
                }
                if let Some(value) = subdir.as_deref() {
                    validate_relative_path(value, "dependency Git subdir")?;
                }
            }
            LakeDependencySourceV1::Path { directory } => {
                validate_relative_path(directory, "dependency path")?;
            }
            LakeDependencySourceV1::Reservoir => {}
        }
        Ok(Self {
            key,
            version,
            source,
        })
    }

    #[must_use]
    pub fn key(&self) -> &PackageKeyV1 {
        &self.key
    }
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    #[must_use]
    pub const fn source(&self) -> &LakeDependencySourceV1 {
        &self.source
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeRootDeclarationV1 {
    root_name: String,
    config_file: String,
    dependencies: Vec<LakeRootDependencyV1>,
    identity: Sha256,
}

impl LakeRootDeclarationV1 {
    pub fn new(
        root_name: impl Into<String>,
        config_file: impl Into<String>,
        mut dependencies: Vec<LakeRootDependencyV1>,
    ) -> Result<Self, LakeBridgeError> {
        let root_name = root_name.into();
        let config_file = config_file.into();
        validate_text(&root_name, MAX_SHORT_BYTES, false, "root package name")?;
        if !matches!(config_file.as_str(), "lakefile.toml" | "lakefile.lean") {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::InvalidField,
                "root config file must be lakefile.toml or lakefile.lean",
            ));
        }
        if dependencies.len() > MAX_ROOT_DEPENDENCIES_V1 {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::LimitExceeded,
                "root dependency count exceeds limit",
            ));
        }
        dependencies.sort_by(|left, right| left.key.cmp(&right.key));
        if dependencies
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key)
        {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::DuplicateDependency,
                "root declaration contains a duplicate package key",
            ));
        }
        let identity = declaration_identity(&root_name, &config_file, &dependencies);
        Ok(Self {
            root_name,
            config_file,
            dependencies,
            identity,
        })
    }

    #[must_use]
    pub fn root_name(&self) -> &str {
        &self.root_name
    }
    #[must_use]
    pub fn config_file(&self) -> &str {
        &self.config_file
    }
    #[must_use]
    pub fn dependencies(&self) -> &[LakeRootDependencyV1] {
        &self.dependencies
    }
    #[must_use]
    pub const fn identity(&self) -> Sha256 {
        self.identity
    }
}

pub fn parse_root_declaration_probe_v1(
    text: &str,
) -> Result<LakeRootDeclarationV1, LakeBridgeError> {
    let value = parse_strict_json(text).map_err(|error| {
        LakeBridgeError::new(LakeBridgeErrorKind::MalformedProbeOutput, error.to_string())
    })?;
    let root = object(&value, "probe root")?;
    exact_fields(
        root,
        &["configFile", "dependencies", "rootName", "schemaVersion"],
        "probe root",
    )?;
    if integer(root.get("schemaVersion"), "schemaVersion")? != 1 {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::MalformedProbeOutput,
            "unsupported root probe schema",
        ));
    }
    let root_name = string(root.get("rootName"), MAX_SHORT_BYTES, false, "rootName")?;
    let config_file = string(root.get("configFile"), MAX_SHORT_BYTES, false, "configFile")?;
    let values = array(root.get("dependencies"), "dependencies")?;
    if values.len() > MAX_ROOT_DEPENDENCIES_V1 {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::LimitExceeded,
            "root probe dependency count exceeds limit",
        ));
    }
    let mut dependencies = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let label = format!("dependency {index}");
        let item = object(value, &label)?;
        exact_fields(item, &["name", "scope", "source", "version"], &label)?;
        let key = PackageKeyV1::new(
            string(item.get("scope"), MAX_SHORT_BYTES, true, "dependency scope")?,
            string(item.get("name"), MAX_SHORT_BYTES, false, "dependency name")?,
        )
        .map_err(|error| {
            LakeBridgeError::new(LakeBridgeErrorKind::MalformedProbeOutput, error.to_string())
        })?;
        let version = nullable_string(item.get("version"), MAX_TEXT_BYTES, "dependency version")?;
        let source_object = object(
            item.get("source")
                .ok_or_else(|| malformed("dependency source missing"))?,
            "dependency source",
        )?;
        let kind = string(
            source_object.get("kind"),
            MAX_SHORT_BYTES,
            false,
            "source kind",
        )?;
        let source = match kind.as_str() {
            "git" => {
                exact_fields(
                    source_object,
                    &["kind", "revision", "subDir", "url"],
                    "Git source",
                )?;
                LakeDependencySourceV1::Git {
                    url: string(source_object.get("url"), MAX_TEXT_BYTES, false, "Git URL")?,
                    revision: nullable_string(
                        source_object.get("revision"),
                        MAX_TEXT_BYTES,
                        "Git revision",
                    )?,
                    subdir: nullable_string(
                        source_object.get("subDir"),
                        MAX_TEXT_BYTES,
                        "Git subdir",
                    )?,
                }
            }
            "path" => {
                exact_fields(source_object, &["directory", "kind"], "path source")?;
                LakeDependencySourceV1::Path {
                    directory: string(
                        source_object.get("directory"),
                        MAX_TEXT_BYTES,
                        false,
                        "path directory",
                    )?,
                }
            }
            "reservoir" => {
                exact_fields(source_object, &["kind"], "reservoir source")?;
                LakeDependencySourceV1::Reservoir
            }
            _ => return Err(malformed("unknown dependency source kind")),
        };
        dependencies.push(LakeRootDependencyV1::new(key, version, source)?);
    }
    LakeRootDeclarationV1::new(root_name, config_file, dependencies)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakePackageProjectionMetadataV1 {
    key: PackageKeyV1,
    inherited: bool,
    config_file: String,
    manifest_file: Option<String>,
    input_revision: Option<String>,
}

impl LakePackageProjectionMetadataV1 {
    pub fn new(
        key: PackageKeyV1,
        inherited: bool,
        config_file: impl Into<String>,
        manifest_file: Option<String>,
        input_revision: Option<String>,
    ) -> Result<Self, LakeBridgeError> {
        let config_file = config_file.into();
        validate_relative_path(&config_file, "package config file")?;
        if let Some(value) = manifest_file.as_deref() {
            validate_relative_path(value, "package manifest file")?;
        }
        if let Some(value) = input_revision.as_deref() {
            validate_text(value, MAX_TEXT_BYTES, false, "package input revision")?;
        }
        Ok(Self {
            key,
            inherited,
            config_file,
            manifest_file,
            input_revision,
        })
    }

    #[must_use]
    pub fn key(&self) -> &PackageKeyV1 {
        &self.key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeManifestProjectionV1 {
    canonical_json: String,
    sha256: Sha256,
}

impl LakeManifestProjectionV1 {
    pub fn new(
        declaration: &LakeRootDeclarationV1,
        lock: &LeanBunLockV1,
        metadata: Vec<LakePackageProjectionMetadataV1>,
    ) -> Result<Self, LakeBridgeError> {
        validate_root_dependencies(declaration, lock)?;
        let metadata = validate_metadata(lock, metadata)?;
        let canonical_json = encode_manifest(declaration.root_name(), lock, &metadata, false)?;
        let sha256 = sha256(canonical_json.as_bytes());
        Ok(Self {
            canonical_json,
            sha256,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical_json
    }
    #[must_use]
    pub const fn sha256(&self) -> Sha256 {
        self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeRuntimePackagesProjectionV1 {
    canonical_json: String,
    sha256: Sha256,
    package_count: usize,
}

impl LakeRuntimePackagesProjectionV1 {
    pub fn from_bun_decisions(
        lock: &LeanBunLockV1,
        decisions: &PackagePathDecisionSetV1,
        metadata: Vec<LakePackageProjectionMetadataV1>,
    ) -> Result<Self, LakeBridgeError> {
        let metadata = validate_metadata(lock, metadata)?;
        if decisions.decisions().len() != lock.packages().len() {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::NonBunRuntimeOverride,
                "runtime projection must be a Bun decision for the complete locked closure",
            ));
        }
        let canonical_json = encode_runtime(lock, decisions, &metadata)?;
        let sha256 = sha256(canonical_json.as_bytes());
        Ok(Self {
            canonical_json,
            sha256,
            package_count: lock.packages().len(),
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical_json
    }
    #[must_use]
    pub const fn sha256(&self) -> Sha256 {
        self.sha256
    }
    #[must_use]
    pub const fn package_count(&self) -> usize {
        self.package_count
    }
}

pub fn validate_managed_runtime_package_files_v1(
    total_files: usize,
    bun_generated_files: usize,
) -> Result<(), LakeBridgeError> {
    if total_files != 1 || bun_generated_files != 1 {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::NonBunRuntimeOverride,
            "managed Lake invocation requires exactly one Bun-generated --packages file and no other runtime override",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeObservedPackagePathV1 {
    key: PackageKeyV1,
    path: String,
}

impl LakeObservedPackagePathV1 {
    pub fn new(key: PackageKeyV1, path: impl Into<String>) -> Result<Self, LakeBridgeError> {
        let path = path.into();
        if !valid_absolute_path(&path) {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::InvalidField,
                "observed Lake package path must be normalized and absolute",
            ));
        }
        Ok(Self { key, path })
    }
    #[must_use]
    pub fn key(&self) -> &PackageKeyV1 {
        &self.key
    }
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LakeWorkspacePathObservationV1 {
    paths: Vec<LakeObservedPackagePathV1>,
    digest: Sha256,
}

impl LakeWorkspacePathObservationV1 {
    pub fn compare(
        decisions: &PackagePathDecisionSetV1,
        mut paths: Vec<LakeObservedPackagePathV1>,
    ) -> Result<Self, LakeBridgeError> {
        paths.sort_by(|left, right| left.key.cmp(&right.key));
        if paths.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::DuplicateObservedPath,
                "Lake reported a package path more than once",
            ));
        }
        let expected = decisions
            .decisions()
            .iter()
            .map(|decision| decision.package())
            .collect::<BTreeSet<_>>();
        let observed = paths.iter().map(|path| &path.key).collect::<BTreeSet<_>>();
        if let Some(key) = expected.difference(&observed).next() {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::MissingObservedPath,
                format!("Lake did not report {}/{}", key.scope(), key.name()),
            ));
        }
        if let Some(key) = observed.difference(&expected).next() {
            return Err(LakeBridgeError::new(
                LakeBridgeErrorKind::ExtraObservedPath,
                format!("Lake reported unknown {}/{}", key.scope(), key.name()),
            ));
        }
        for (decision, observed) in decisions.decisions().iter().zip(&paths) {
            if decision.package() != &observed.key || decision.final_path() != observed.path {
                return Err(LakeBridgeError::new(
                    LakeBridgeErrorKind::WorkspacePathMismatch,
                    format!(
                        "Lake path differs from Bun decision for {}/{}",
                        observed.key.scope(),
                        observed.key.name()
                    ),
                ));
            }
        }
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"leanbun-lake-workspace-paths-v1\0");
        for path in &paths {
            hash_string(&mut hasher, path.key.scope());
            hash_string(&mut hasher, path.key.name());
            hash_string(&mut hasher, &path.path);
        }
        Ok(Self {
            paths,
            digest: hasher.finalize(),
        })
    }

    #[must_use]
    pub fn paths(&self) -> &[LakeObservedPackagePathV1] {
        &self.paths
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256 {
        self.digest
    }
}

fn validate_root_dependencies(
    declaration: &LakeRootDeclarationV1,
    lock: &LeanBunLockV1,
) -> Result<(), LakeBridgeError> {
    let packages = lock
        .packages()
        .iter()
        .map(|package| (package.key(), package))
        .collect::<BTreeMap<_, _>>();
    for dependency in declaration.dependencies() {
        let package = packages.get(dependency.key()).ok_or_else(|| {
            LakeBridgeError::new(
                LakeBridgeErrorKind::MissingPackage,
                format!(
                    "root dependency absent from lock: {}/{}",
                    dependency.key().scope(),
                    dependency.key().name()
                ),
            )
        })?;
        match (
            dependency.source(),
            package.requested_source(),
            package.resolved_source(),
        ) {
            (
                LakeDependencySourceV1::Git {
                    url,
                    revision,
                    subdir,
                },
                RequestedPackageSourceV1::Git { url: requested, .. },
                ResolvedPackageSourceV1::Git {
                    url: resolved,
                    exact_revision,
                    subdir: locked_subdir,
                },
            ) => {
                if url != requested.as_str()
                    || url != resolved.as_str()
                    || revision
                        .as_deref()
                        .is_some_and(|value| value != exact_revision)
                    || subdir != locked_subdir
                {
                    return Err(LakeBridgeError::new(
                        LakeBridgeErrorKind::SourceValueDrift,
                        "root Git declaration differs from locked source",
                    ));
                }
            }
            (
                LakeDependencySourceV1::Path { directory },
                RequestedPackageSourceV1::PathSnapshot {
                    portable_path_token,
                },
                ResolvedPackageSourceV1::PathSnapshot {
                    portable_path_token: resolved,
                },
            ) => {
                if directory != portable_path_token || directory != resolved {
                    return Err(LakeBridgeError::new(
                        LakeBridgeErrorKind::SourceValueDrift,
                        "root path declaration differs from locked source",
                    ));
                }
            }
            (LakeDependencySourceV1::Reservoir, _, _) => {}
            _ => {
                return Err(LakeBridgeError::new(
                    LakeBridgeErrorKind::SourceKindDrift,
                    "root declaration and lock source kinds differ",
                ));
            }
        }
    }
    Ok(())
}

fn validate_metadata(
    lock: &LeanBunLockV1,
    mut metadata: Vec<LakePackageProjectionMetadataV1>,
) -> Result<BTreeMap<PackageKeyV1, LakePackageProjectionMetadataV1>, LakeBridgeError> {
    metadata.sort_by(|left, right| left.key.cmp(&right.key));
    if metadata.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::DuplicatePackage,
            "duplicate projection package metadata",
        ));
    }
    let locked = lock
        .packages()
        .iter()
        .map(|package| package.key())
        .collect::<BTreeSet<_>>();
    let supplied = metadata
        .iter()
        .map(|item| &item.key)
        .collect::<BTreeSet<_>>();
    if let Some(key) = locked.difference(&supplied).next() {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::MissingPackage,
            format!(
                "missing projection metadata for {}/{}",
                key.scope(),
                key.name()
            ),
        ));
    }
    if let Some(key) = supplied.difference(&locked).next() {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::ExtraPackage,
            format!(
                "extra projection metadata for {}/{}",
                key.scope(),
                key.name()
            ),
        ));
    }
    Ok(metadata
        .into_iter()
        .map(|item| (item.key.clone(), item))
        .collect())
}

fn encode_manifest(
    root_name: &str,
    lock: &LeanBunLockV1,
    metadata: &BTreeMap<PackageKeyV1, LakePackageProjectionMetadataV1>,
    runtime: bool,
) -> Result<String, LakeBridgeError> {
    let mut output = String::from("{\"version\":\"1.2.0\",\"fixedToolchain\":true,\"name\":");
    json_string(&mut output, root_name);
    output.push_str(",\"lakeDir\":\".lake\",\"packagesDir\":\".lake/packages\",\"packages\":[");
    encode_entries(&mut output, lock, metadata, None, runtime)?;
    output.push_str("]}\n");
    Ok(output)
}

fn encode_runtime(
    lock: &LeanBunLockV1,
    decisions: &PackagePathDecisionSetV1,
    metadata: &BTreeMap<PackageKeyV1, LakePackageProjectionMetadataV1>,
) -> Result<String, LakeBridgeError> {
    let mut output = String::from("{\"version\":\"1.2.0\",\"packages\":[");
    encode_entries(&mut output, lock, metadata, Some(decisions), true)?;
    output.push_str("]}\n");
    Ok(output)
}

fn encode_entries(
    output: &mut String,
    lock: &LeanBunLockV1,
    metadata: &BTreeMap<PackageKeyV1, LakePackageProjectionMetadataV1>,
    decisions: Option<&PackagePathDecisionSetV1>,
    runtime: bool,
) -> Result<(), LakeBridgeError> {
    for (index, package) in lock.packages().iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let meta = metadata.get(package.key()).ok_or_else(|| {
            LakeBridgeError::new(
                LakeBridgeErrorKind::MissingPackage,
                "projection metadata missing after validation",
            )
        })?;
        output.push('{');
        field_string(output, "name", package.key().name());
        output.push(',');
        field_string(output, "scope", package.key().scope());
        output.push_str(",\"inherited\":");
        output.push_str(if meta.inherited { "true" } else { "false" });
        output.push(',');
        field_string(output, "configFile", &meta.config_file);
        output.push_str(",\"manifestFile\":");
        optional_json_string(output, meta.manifest_file.as_deref());
        if runtime {
            let set = decisions.ok_or_else(|| {
                LakeBridgeError::new(
                    LakeBridgeErrorKind::NonBunRuntimeOverride,
                    "runtime entry lacks Bun decision set",
                )
            })?;
            let decision = set
                .decisions()
                .iter()
                .find(|decision| decision.package() == package.key())
                .ok_or_else(|| {
                    LakeBridgeError::new(
                        LakeBridgeErrorKind::MissingPackage,
                        "runtime decision missing",
                    )
                })?;
            output.push_str(",\"type\":\"path\",");
            field_string(output, "dir", decision.final_path());
        } else {
            match package.resolved_source() {
                ResolvedPackageSourceV1::Git {
                    url,
                    exact_revision,
                    subdir,
                } => {
                    output.push_str(",\"type\":\"git\",");
                    field_string(output, "url", url.as_str());
                    output.push(',');
                    field_string(output, "rev", exact_revision);
                    output.push_str(",\"inputRev\":");
                    optional_json_string(output, meta.input_revision.as_deref());
                    output.push_str(",\"subDir\":");
                    optional_json_string(output, subdir.as_deref());
                }
                ResolvedPackageSourceV1::PathSnapshot {
                    portable_path_token,
                } => {
                    output.push_str(",\"type\":\"path\",");
                    field_string(output, "dir", portable_path_token);
                }
                _ => {
                    return Err(LakeBridgeError::new(
                        LakeBridgeErrorKind::SourceKindDrift,
                        "unsupported future locked source kind",
                    ));
                }
            }
        }
        output.push('}');
    }
    Ok(())
}

fn declaration_identity(
    root_name: &str,
    config_file: &str,
    dependencies: &[LakeRootDependencyV1],
) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"leanbun-lake-root-declaration-v1\0");
    hash_string(&mut hasher, root_name);
    hash_string(&mut hasher, config_file);
    for dependency in dependencies {
        hash_string(&mut hasher, dependency.key.scope());
        hash_string(&mut hasher, dependency.key.name());
        hash_optional_string(&mut hasher, dependency.version.as_deref());
        match &dependency.source {
            LakeDependencySourceV1::Git {
                url,
                revision,
                subdir,
            } => {
                hasher.update(&[0]);
                hash_string(&mut hasher, url);
                hash_optional_string(&mut hasher, revision.as_deref());
                hash_optional_string(&mut hasher, subdir.as_deref());
            }
            LakeDependencySourceV1::Path { directory } => {
                hasher.update(&[1]);
                hash_string(&mut hasher, directory);
            }
            LakeDependencySourceV1::Reservoir => hasher.update(&[2]),
        }
    }
    hasher.finalize()
}

fn sha256(bytes: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}
fn hash_string(hasher: &mut Sha256Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}
fn hash_optional_string(hasher: &mut Sha256Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hash_string(hasher, value);
        }
        None => hasher.update(&[0]),
    }
}
fn field_string(output: &mut String, name: &str, value: &str) {
    json_string(output, name);
    output.push(':');
    json_string(output, value);
}
fn optional_json_string(output: &mut String, value: Option<&str>) {
    match value {
        Some(value) => json_string(output, value),
        None => output.push_str("null"),
    }
}
fn json_string(output: &mut String, value: &str) {
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
            '\u{00}'..='\u{1f}' => output.push_str(&format!("\\u{:04x}", u32::from(character))),
            _ => output.push(character),
        }
    }
    output.push('"');
}

fn validate_text(
    value: &str,
    maximum: usize,
    allow_empty: bool,
    label: &str,
) -> Result<(), LakeBridgeError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::InvalidField,
            format!("{label} is empty, too long, or contains control characters"),
        ));
    }
    Ok(())
}
fn validate_https_url(value: &str) -> Result<(), LakeBridgeError> {
    validate_text(value, MAX_TEXT_BYTES, false, "dependency URL")?;
    if !value.starts_with("https://")
        || value.contains(['?', '#', '\\'])
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::InvalidField,
            "dependency URL must be normalized HTTPS",
        ));
    }
    Ok(())
}
fn validate_relative_path(value: &str, label: &str) -> Result<(), LakeBridgeError> {
    validate_text(value, MAX_TEXT_BYTES, false, label)?;
    if value.starts_with('/')
        || value.contains('\\')
        || value.as_bytes().get(1) == Some(&b':')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(LakeBridgeError::new(
            LakeBridgeErrorKind::InvalidField,
            format!("{label} must be a normalized relative path"),
        ));
    }
    Ok(())
}
fn valid_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && value[1..]
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

fn object<'a>(
    value: &'a StrictJson,
    label: &str,
) -> Result<&'a BTreeMap<String, StrictJson>, LakeBridgeError> {
    match value {
        StrictJson::Object(value) => Ok(value),
        _ => Err(malformed(format!("{label} must be an object"))),
    }
}
fn array<'a>(
    value: Option<&'a StrictJson>,
    label: &str,
) -> Result<&'a [StrictJson], LakeBridgeError> {
    match value {
        Some(StrictJson::Array(value)) => Ok(value),
        _ => Err(malformed(format!("{label} must be an array"))),
    }
}
fn string(
    value: Option<&StrictJson>,
    maximum: usize,
    allow_empty: bool,
    label: &str,
) -> Result<String, LakeBridgeError> {
    match value {
        Some(StrictJson::String(value))
            if (allow_empty || !value.is_empty())
                && value.len() <= maximum
                && !value.chars().any(char::is_control) =>
        {
            Ok(value.clone())
        }
        _ => Err(malformed(format!("{label} must be a bounded string"))),
    }
}
fn nullable_string(
    value: Option<&StrictJson>,
    maximum: usize,
    label: &str,
) -> Result<Option<String>, LakeBridgeError> {
    match value {
        Some(StrictJson::Null) => Ok(None),
        Some(StrictJson::String(value))
            if !value.is_empty()
                && value.len() <= maximum
                && !value.chars().any(char::is_control) =>
        {
            Ok(Some(value.clone()))
        }
        _ => Err(malformed(format!(
            "{label} must be null or a bounded string"
        ))),
    }
}
fn integer(value: Option<&StrictJson>, label: &str) -> Result<u64, LakeBridgeError> {
    match value {
        Some(StrictJson::Number(value)) => value
            .as_str()
            .parse()
            .map_err(|_| malformed(format!("{label} must be an integer"))),
        _ => Err(malformed(format!("{label} must be an integer"))),
    }
}
fn exact_fields(
    value: &BTreeMap<String, StrictJson>,
    fields: &[&str],
    label: &str,
) -> Result<(), LakeBridgeError> {
    let actual = value.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(malformed(format!("{label} fields differ from schema")));
    }
    Ok(())
}
fn malformed(message: impl Into<String>) -> LakeBridgeError {
    LakeBridgeError::new(LakeBridgeErrorKind::MalformedProbeOutput, message)
}

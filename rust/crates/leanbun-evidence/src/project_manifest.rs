use leanbun_core::DiagnosticCode;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::{
    CanonicalDirectory, EvidenceError, MAX_PROVIDER_PACKAGES, PROVIDER_REGISTRY_MAX_BYTES,
    ProviderRegistry, StableTextFile, StrictJson, parse_strict_json, read_stable_text,
};

const MAX_SHORT_STRING_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_URL_BYTES: usize = 4_096;
const ROOT_FIELDS: &[&str] = &[
    "fixedToolchain",
    "lakeDir",
    "name",
    "packages",
    "packagesDir",
    "version",
];
const PACKAGE_FIELDS: &[&str] = &[
    "configFile",
    "dir",
    "inherited",
    "inputRev",
    "manifestFile",
    "name",
    "rev",
    "scope",
    "subDir",
    "type",
    "url",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectPackageSource {
    Git { revision: String },
    Path { directory: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectManifestPackage {
    pub name: String,
    pub source: ProjectPackageSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectManifest {
    pub version: String,
    pub packages_dir: String,
    pub name: String,
    pub lake_dir: String,
    pub fixed_toolchain: bool,
    pub packages: Vec<ProjectManifestPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableProjectManifestFile {
    pub file: StableTextFile,
    pub manifest: ProjectManifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectProviderMatchState {
    DependencyFree,
    Matched,
    Mismatched,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectProviderMismatch {
    pub package: String,
    pub field: String,
    pub project: Option<String>,
    pub provider: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectProviderComparison {
    pub state: ProjectProviderMatchState,
    pub mismatches: Vec<ProjectProviderMismatch>,
}

pub fn read_project_manifest(
    root: &CanonicalDirectory,
    candidate: impl AsRef<Path>,
) -> Result<StableProjectManifestFile, EvidenceError> {
    let file = read_stable_text(root, candidate, PROVIDER_REGISTRY_MAX_BYTES)?;
    let manifest = parse_project_manifest(&file.text)?;
    Ok(StableProjectManifestFile { file, manifest })
}

pub fn parse_project_manifest(text: &str) -> Result<ProjectManifest, EvidenceError> {
    decode_project_manifest(&parse_strict_json(text)?)
}

pub fn decode_project_manifest(value: &StrictJson) -> Result<ProjectManifest, EvidenceError> {
    let root = object(value, "project manifest root")?;
    reject_unknown_fields(root, ROOT_FIELDS, "project manifest root")?;

    let version = required_string(root, "version", MAX_SHORT_STRING_BYTES, "project manifest")?;
    if !supported_lake_version(version) {
        return Err(EvidenceError::new(
            DiagnosticCode::MANIFEST_SCHEMA_UNSUPPORTED,
            format!("project manifest schema {version} is not supported; supported major=1"),
        ));
    }
    let packages_dir =
        required_nonempty_string(root, "packagesDir", MAX_PATH_BYTES, "project manifest")?;
    let name = required_nonempty_string(root, "name", MAX_SHORT_STRING_BYTES, "project manifest")?;
    let lake_dir = required_nonempty_string(root, "lakeDir", MAX_PATH_BYTES, "project manifest")?;
    let fixed_toolchain = match root.get("fixedToolchain") {
        Some(StrictJson::Bool(value)) => *value,
        Some(_) => return Err(shape("project manifest fixedToolchain must be a boolean")),
        None => return Err(shape("project manifest is missing fixedToolchain")),
    };
    let packages = match root.get("packages") {
        Some(StrictJson::Array(values)) => values,
        Some(_) => return Err(shape("project manifest packages must be an array")),
        None => return Err(shape("project manifest is missing packages")),
    };
    if packages.len() > MAX_PROVIDER_PACKAGES {
        return Err(shape(format!(
            "project manifest package count {} exceeds limit {MAX_PROVIDER_PACKAGES}",
            packages.len()
        )));
    }

    let mut names = BTreeSet::new();
    let mut decoded = Vec::with_capacity(packages.len());
    for (index, package) in packages.iter().enumerate() {
        let label = format!("project manifest package {index}");
        let package = object(package, &label)?;
        reject_unknown_fields(package, PACKAGE_FIELDS, &label)?;
        let name = required_nonempty_string(package, "name", MAX_SHORT_STRING_BYTES, &label)?;
        if !names.insert(name) {
            return Err(shape(format!(
                "duplicate project manifest package name: {name}"
            )));
        }
        let source_type = required_string(package, "type", MAX_SHORT_STRING_BYTES, &label)?;
        let source = match source_type {
            "git" => decode_git_source(package, &label)?,
            "path" => decode_path_source(package, &label)?,
            _ => return Err(shape(format!("{label} type must be git or path"))),
        };
        decoded.push(ProjectManifestPackage {
            name: name.to_owned(),
            source,
        });
    }

    Ok(ProjectManifest {
        version: version.to_owned(),
        packages_dir: packages_dir.to_owned(),
        name: name.to_owned(),
        lake_dir: lake_dir.to_owned(),
        fixed_toolchain,
        packages: decoded,
    })
}

pub fn compare_project_manifest_to_provider(
    manifest: &ProjectManifest,
    provider: &ProviderRegistry,
) -> ProjectProviderComparison {
    if manifest.packages.is_empty() {
        return ProjectProviderComparison {
            state: ProjectProviderMatchState::DependencyFree,
            mismatches: Vec::new(),
        };
    }

    let mut mismatches = Vec::new();
    push_mismatch(
        &mut mismatches,
        "<document>",
        "version",
        &manifest.version,
        &provider.version,
    );
    push_mismatch(
        &mut mismatches,
        "<document>",
        "packagesDir",
        &manifest.packages_dir,
        &provider.packages_dir,
    );

    let project_by_name = manifest
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let provider_by_name = provider
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();

    for (name, package) in &provider_by_name {
        let Some(project) = project_by_name.get(name) else {
            mismatches.push(ProjectProviderMismatch {
                package: (*name).to_owned(),
                field: "package".to_owned(),
                project: None,
                provider: Some("registered".to_owned()),
            });
            continue;
        };
        match &project.source {
            ProjectPackageSource::Git { revision } => {
                push_mismatch(&mut mismatches, name, "rev", revision, &package.revision)
            }
            ProjectPackageSource::Path { directory } => {
                mismatches.push(ProjectProviderMismatch {
                    package: (*name).to_owned(),
                    field: "type".to_owned(),
                    project: Some(format!("path:{directory}")),
                    provider: Some("git".to_owned()),
                });
            }
        }
    }
    for name in project_by_name.keys() {
        if !provider_by_name.contains_key(name) {
            mismatches.push(ProjectProviderMismatch {
                package: (*name).to_owned(),
                field: "package".to_owned(),
                project: Some("unregistered".to_owned()),
                provider: None,
            });
        }
    }
    mismatches.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then_with(|| left.field.cmp(&right.field))
    });

    ProjectProviderComparison {
        state: if mismatches.is_empty() {
            ProjectProviderMatchState::Matched
        } else {
            ProjectProviderMatchState::Mismatched
        },
        mismatches,
    }
}

fn decode_git_source(
    package: &BTreeMap<String, StrictJson>,
    label: &str,
) -> Result<ProjectPackageSource, EvidenceError> {
    if package.contains_key("dir") {
        return Err(shape(format!("{label} git package must not have dir")));
    }
    let revision = required_string(package, "rev", MAX_SHORT_STRING_BYTES, label)?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(shape(format!(
            "{label} rev must be 40 lowercase hexadecimal bytes"
        )));
    }
    optional_string(package, "url", MAX_URL_BYTES, label)?;
    optional_nullable_string(package, "subDir", MAX_SHORT_STRING_BYTES, label)?;
    for field in ["scope", "manifestFile", "inputRev", "configFile"] {
        optional_string(package, field, MAX_SHORT_STRING_BYTES, label)?;
    }
    optional_boolean(package, "inherited", label)?;
    Ok(ProjectPackageSource::Git {
        revision: revision.to_owned(),
    })
}

fn decode_path_source(
    package: &BTreeMap<String, StrictJson>,
    label: &str,
) -> Result<ProjectPackageSource, EvidenceError> {
    for forbidden in ["rev", "url", "subDir", "inputRev"] {
        if package.contains_key(forbidden) {
            return Err(shape(format!(
                "{label} path package must not have {forbidden}"
            )));
        }
    }
    if let Some(scope) = package.get("scope") {
        match scope {
            StrictJson::String(scope) if scope.is_empty() => {}
            _ => {
                return Err(shape(format!(
                    "{label} path package scope must be an empty string"
                )));
            }
        }
    }
    let directory = required_nonempty_string(package, "dir", MAX_PATH_BYTES, label)?;
    optional_nullable_string(package, "manifestFile", MAX_SHORT_STRING_BYTES, label)?;
    optional_string(package, "configFile", MAX_SHORT_STRING_BYTES, label)?;
    optional_boolean(package, "inherited", label)?;
    Ok(ProjectPackageSource::Path {
        directory: directory.to_owned(),
    })
}

fn push_mismatch(
    mismatches: &mut Vec<ProjectProviderMismatch>,
    package: &str,
    field: &str,
    project: &str,
    provider: &str,
) {
    if project != provider {
        mismatches.push(ProjectProviderMismatch {
            package: package.to_owned(),
            field: field.to_owned(),
            project: Some(project.to_owned()),
            provider: Some(provider.to_owned()),
        });
    }
}

fn object<'a>(
    value: &'a StrictJson,
    label: &str,
) -> Result<&'a BTreeMap<String, StrictJson>, EvidenceError> {
    match value {
        StrictJson::Object(value) => Ok(value),
        _ => Err(shape(format!("{label} must be an object"))),
    }
}

fn reject_unknown_fields(
    value: &BTreeMap<String, StrictJson>,
    allowed: &[&str],
    label: &str,
) -> Result<(), EvidenceError> {
    if let Some(field) = value
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(shape(format!("{label} has unknown field: {field}")));
    }
    Ok(())
}

fn required_nonempty_string<'a>(
    value: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<&'a str, EvidenceError> {
    let value = required_string(value, field, maximum_bytes, label)?;
    if value.is_empty() {
        return Err(shape(format!("{label} {field} must not be empty")));
    }
    Ok(value)
}

fn required_string<'a>(
    value: &'a BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<&'a str, EvidenceError> {
    match value.get(field) {
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(value),
        Some(StrictJson::String(_)) => Err(shape(format!(
            "{label} {field} exceeds {maximum_bytes} bytes"
        ))),
        Some(_) => Err(shape(format!("{label} {field} must be a string"))),
        None => Err(shape(format!("{label} is missing {field}"))),
    }
}

fn optional_string(
    value: &BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<(), EvidenceError> {
    if value.contains_key(field) {
        required_string(value, field, maximum_bytes, label)?;
    }
    Ok(())
}

fn optional_nullable_string(
    value: &BTreeMap<String, StrictJson>,
    field: &str,
    maximum_bytes: usize,
    label: &str,
) -> Result<(), EvidenceError> {
    match value.get(field) {
        None | Some(StrictJson::Null) => Ok(()),
        Some(StrictJson::String(value)) if value.len() <= maximum_bytes => Ok(()),
        Some(StrictJson::String(_)) => Err(shape(format!(
            "{label} {field} exceeds {maximum_bytes} bytes"
        ))),
        Some(_) => Err(shape(format!("{label} {field} must be null or a string"))),
    }
}

fn optional_boolean(
    value: &BTreeMap<String, StrictJson>,
    field: &str,
    label: &str,
) -> Result<(), EvidenceError> {
    if let Some(value) = value.get(field)
        && !matches!(value, StrictJson::Bool(_))
    {
        return Err(shape(format!("{label} {field} must be a boolean")));
    }
    Ok(())
}

fn supported_lake_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    [major, minor, patch]
        .iter()
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && major.parse::<u64>() == Ok(1)
}

fn shape(message: impl Into<String>) -> EvidenceError {
    EvidenceError::new(DiagnosticCode::MANIFEST_SHAPE_INVALID, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_provider_registry;

    const REVISION: &str = "81a5d257c8e410db227a6665ed08f64fea08e997";

    #[test]
    fn shared_project_manifest_contract_cases_match() {
        for line in include_str!("../../../golden/project-manifest-cases.tsv").lines() {
            let mut fields = line.splitn(3, '\t');
            let expected = fields.next() == Some("true");
            let label = fields.next().unwrap_or("");
            let text = fields.next().unwrap_or("");
            assert_eq!(parse_project_manifest(text).is_ok(), expected, "{label}");
        }
    }

    #[test]
    fn project_provider_comparison_distinguishes_free_match_and_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let provider = parse_provider_registry(&format!(
            r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}]}}"#
        ))?;
        let free = parse_project_manifest(
            r#"{"version":"1.2.0","packagesDir":".lake/packages","packages":[],"name":"free","lakeDir":".lake","fixedToolchain":false}"#,
        )?;
        assert_eq!(
            compare_project_manifest_to_provider(&free, &provider).state,
            ProjectProviderMatchState::DependencyFree
        );

        let matched = parse_project_manifest(&format!(
            r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}],"name":"bound","lakeDir":".lake","fixedToolchain":false}}"#
        ))?;
        assert_eq!(
            compare_project_manifest_to_provider(&matched, &provider).state,
            ProjectProviderMatchState::Matched
        );

        let drifted = parse_project_manifest(
            r#"{"version":"1.2.0","packagesDir":"other","packages":[{"name":"mathlib","type":"path","dir":"dependency"},{"name":"extra","type":"git","rev":"023ce7d62a0531e22a5331e20b587817a80d49ff"}],"name":"drift","lakeDir":".lake","fixedToolchain":false}"#,
        )?;
        let comparison = compare_project_manifest_to_provider(&drifted, &provider);
        assert_eq!(comparison.state, ProjectProviderMatchState::Mismatched);
        assert_eq!(
            comparison
                .mismatches
                .iter()
                .map(|value| (value.package.as_str(), value.field.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("<document>", "packagesDir"),
                ("extra", "package"),
                ("mathlib", "type"),
            ]
        );
        Ok(())
    }

    #[test]
    fn project_manifest_package_limit_is_enforced() {
        let package = format!(r#"{{"name":"p","type":"git","rev":"{REVISION}"}}"#);
        let packages = std::iter::repeat_n(package, MAX_PROVIDER_PACKAGES + 1)
            .collect::<Vec<_>>()
            .join(",");
        let oversized = format!(
            r#"{{"version":"1.2.0","packagesDir":".lake/packages","packages":[{packages}],"name":"large","lakeDir":".lake","fixedToolchain":false}}"#
        );
        assert!(matches!(
            parse_project_manifest(&oversized),
            Err(error) if error.code == DiagnosticCode::MANIFEST_SHAPE_INVALID
        ));
    }
}

#![forbid(unsafe_code)]

use core::fmt;
use leanbun_core::{DiagnosticCode, ProjectId, Sha256, project_id};
use leanbun_evidence::{
    CanonicalPath, ProjectPackageSource, StableProjectInput, StableProviderPair,
};
use std::collections::{BTreeMap, BTreeSet};

mod lock_v1;
mod snapshot;

pub use lock_v1::{
    CanonicalSourceUrlV1, LeanBunLockV1, LeanBunLockV1Error, LeanBunLockV1ErrorKind,
    LockedLeanPackageV1, PackageDependencyV1, PackageKeyV1, PackagePathDecisionSetV1,
    PackagePathDecisionV1, PackagePathProvenanceKindV1, PackagePathProvenanceSetV1,
    PackagePathProvenanceV1, RequestedPackageSourceV1, ResolvedPackageSourceV1,
};
pub use snapshot::{
    PackageInventorySnapshotDigestV1, PackageInventorySnapshotError,
    package_inventory_snapshot_digest_v1,
};

pub const MAX_INVENTORY_PACKAGES: usize = 4_096;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitRevision(String);

impl GitRevision {
    pub fn parse(value: &str) -> Result<Self, PackageInventoryError> {
        if value.len() != 40
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PackageInventoryError::new(
                DiagnosticCode::GIT_EVIDENCE_FAILED,
                "Git revision must be 40 lowercase hexadecimal bytes",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckoutObservationStateV1 {
    Unobserved,
    Missing,
    Present {
        directory: CanonicalPath,
        revision: Option<GitRevision>,
        dirty: Option<bool>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageCheckoutObservationV1 {
    pub name: String,
    pub state: CheckoutObservationStateV1,
}

impl PackageCheckoutObservationV1 {
    pub fn missing(name: impl Into<String>) -> Result<Self, PackageInventoryError> {
        Self::new(name, CheckoutObservationStateV1::Missing)
    }

    pub fn present(
        name: impl Into<String>,
        directory: CanonicalPath,
        revision: Option<&str>,
        dirty: Option<bool>,
    ) -> Result<Self, PackageInventoryError> {
        let revision = revision.map(GitRevision::parse).transpose()?;
        Self::new(
            name,
            CheckoutObservationStateV1::Present {
                directory,
                revision,
                dirty,
            },
        )
    }

    fn new(
        name: impl Into<String>,
        state: CheckoutObservationStateV1,
    ) -> Result<Self, PackageInventoryError> {
        let name = name.into();
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(PackageInventoryError::new(
                DiagnosticCode::BUILD_INSPECTION_FAILED,
                "checkout observation package name is invalid",
            ));
        }
        Ok(Self { name, state })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeclaredPackageSourceV1 {
    Git { revision: GitRevision },
    Path { declared_directory: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPackageRegistrationV1 {
    pub revision: GitRevision,
    pub directory: CanonicalPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageInventoryEntryV1 {
    pub name: String,
    pub declaration: Option<DeclaredPackageSourceV1>,
    pub project_override_directory: Option<String>,
    pub resolved_path_directory: Option<CanonicalPath>,
    pub provider: Option<ProviderPackageRegistrationV1>,
    pub checkout: CheckoutObservationStateV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageInventoryV1 {
    pub schema_version: u8,
    pub project_id: ProjectId,
    pub project_path: String,
    pub toolchain: String,
    pub manifest_sha256: Sha256,
    pub override_sha256: Option<Sha256>,
    pub provider_registry_sha256: Option<Sha256>,
    pub provider_override_sha256: Option<Sha256>,
    pub packages: Vec<PackageInventoryEntryV1>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DependencyDriftKindV1 {
    Missing,
    RevisionMismatch,
    Dirty,
    PathMismatch,
    OverrideMismatch,
    Unobserved,
    Matched,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyDriftFindingV1 {
    pub kind: DependencyDriftKindV1,
    pub field: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDependencyDriftV1 {
    pub name: String,
    pub findings: Vec<DependencyDriftFindingV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyDriftSummaryV1 {
    Matched,
    Drifted,
    Unobserved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyDriftReportV1 {
    pub schema_version: u8,
    pub project_id: ProjectId,
    pub summary: DependencyDriftSummaryV1,
    pub packages: Vec<PackageDependencyDriftV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageInventoryError {
    pub code: DiagnosticCode,
    pub message: String,
}

impl PackageInventoryError {
    fn new(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for PackageInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PackageInventoryError {}

pub fn build_package_inventory(
    project: &StableProjectInput,
    provider: Option<&StableProviderPair>,
    checkout_observations: &[PackageCheckoutObservationV1],
) -> Result<PackageInventoryV1, PackageInventoryError> {
    let manifest = &project.manifest.manifest;
    let mut names = manifest
        .packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    if let Some(overrides) = &project.overrides {
        names.extend(
            overrides
                .overrides
                .packages
                .iter()
                .map(|package| package.name.as_str()),
        );
    }
    if let Some(provider) = provider {
        names.extend(
            provider
                .packages
                .iter()
                .map(|package| package.name.as_str()),
        );
    }
    if names.len() > MAX_INVENTORY_PACKAGES {
        return Err(PackageInventoryError::new(
            DiagnosticCode::BUILD_INSPECTION_FAILED,
            "package inventory exceeds package limit",
        ));
    }

    let mut observations = BTreeMap::new();
    for observation in checkout_observations {
        if !names.contains(observation.name.as_str()) {
            return Err(PackageInventoryError::new(
                DiagnosticCode::BUILD_INSPECTION_FAILED,
                format!(
                    "checkout observation is outside declared/provider inventory: {}",
                    observation.name
                ),
            ));
        }
        if observations
            .insert(observation.name.as_str(), &observation.state)
            .is_some()
        {
            return Err(PackageInventoryError::new(
                DiagnosticCode::BUILD_INSPECTION_FAILED,
                format!("duplicate checkout observation: {}", observation.name),
            ));
        }
    }

    let declarations = manifest
        .packages
        .iter()
        .map(|package| (package.name.as_str(), &package.source))
        .collect::<BTreeMap<_, _>>();
    let overrides = project
        .overrides
        .as_ref()
        .map(|document| {
            document
                .overrides
                .packages
                .iter()
                .map(|package| (package.name.as_str(), package.directory.as_str()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let path_packages = project
        .path_packages
        .iter()
        .map(|package| (package.name.as_str(), &package.directory))
        .collect::<BTreeMap<_, _>>();
    let provider_packages = provider
        .map(|pair| {
            pair.packages
                .iter()
                .map(|package| (package.name.as_str(), package))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    let mut packages = Vec::with_capacity(names.len());
    for name in names {
        let declaration = declarations
            .get(name)
            .map(|source| declared_source(source))
            .transpose()?;
        let provider = provider_packages
            .get(name)
            .map(|package| {
                Ok(ProviderPackageRegistrationV1 {
                    revision: GitRevision::parse(&package.revision)?,
                    directory: package.directory.clone(),
                })
            })
            .transpose()?;
        packages.push(PackageInventoryEntryV1 {
            name: name.to_owned(),
            declaration,
            project_override_directory: overrides.get(name).map(|value| (*value).to_owned()),
            resolved_path_directory: path_packages.get(name).map(|value| (*value).clone()),
            provider,
            checkout: observations
                .get(name)
                .map_or(CheckoutObservationStateV1::Unobserved, |value| {
                    (*value).clone()
                }),
        });
    }

    let project_path = project
        .project_root
        .as_path()
        .to_string_lossy()
        .into_owned();
    Ok(PackageInventoryV1 {
        schema_version: 1,
        project_id: project_id(&project_path),
        project_path,
        toolchain: project.toolchain.clone(),
        manifest_sha256: project.manifest.file.sha256,
        override_sha256: project.overrides.as_ref().map(|value| value.file.sha256),
        provider_registry_sha256: provider.map(|value| value.registry.file.sha256),
        provider_override_sha256: provider.map(|value| value.overrides.file.sha256),
        packages,
    })
}

pub fn report_dependency_drift(inventory: &PackageInventoryV1) -> DependencyDriftReportV1 {
    let packages = inventory
        .packages
        .iter()
        .map(|package| PackageDependencyDriftV1 {
            name: package.name.clone(),
            findings: classify_package(package),
        })
        .collect::<Vec<_>>();
    let has_drift = packages.iter().any(|package| {
        package.findings.iter().any(|finding| {
            !matches!(
                finding.kind,
                DependencyDriftKindV1::Matched | DependencyDriftKindV1::Unobserved
            )
        })
    });
    let has_unobserved = packages.iter().any(|package| {
        package
            .findings
            .iter()
            .any(|finding| finding.kind == DependencyDriftKindV1::Unobserved)
    });
    DependencyDriftReportV1 {
        schema_version: 1,
        project_id: inventory.project_id,
        summary: if has_drift {
            DependencyDriftSummaryV1::Drifted
        } else if has_unobserved {
            DependencyDriftSummaryV1::Unobserved
        } else {
            DependencyDriftSummaryV1::Matched
        },
        packages,
    }
}

fn declared_source(
    source: &ProjectPackageSource,
) -> Result<DeclaredPackageSourceV1, PackageInventoryError> {
    match source {
        ProjectPackageSource::Git { revision } => Ok(DeclaredPackageSourceV1::Git {
            revision: GitRevision::parse(revision)?,
        }),
        ProjectPackageSource::Path { directory } => Ok(DeclaredPackageSourceV1::Path {
            declared_directory: directory.clone(),
        }),
    }
}

fn classify_package(package: &PackageInventoryEntryV1) -> Vec<DependencyDriftFindingV1> {
    let mut findings = Vec::new();
    match (&package.declaration, &package.provider) {
        (None, Some(provider)) => findings.push(finding(
            DependencyDriftKindV1::Missing,
            "manifest-package",
            Some(provider.revision.to_string()),
            None,
        )),
        (Some(DeclaredPackageSourceV1::Git { revision }), Some(provider))
            if revision != &provider.revision =>
        {
            findings.push(finding(
                DependencyDriftKindV1::RevisionMismatch,
                "manifest-provider-revision",
                Some(provider.revision.to_string()),
                Some(revision.to_string()),
            ));
        }
        (Some(DeclaredPackageSourceV1::Path { declared_directory }), Some(provider)) => {
            findings.push(finding(
                DependencyDriftKindV1::PathMismatch,
                "manifest-provider-source",
                Some(provider.directory.to_string()),
                Some(declared_directory.clone()),
            ));
        }
        _ => {}
    }

    if let Some(provider) = &package.provider
        && package.project_override_directory.as_deref()
            != Some(provider.directory.as_path().to_string_lossy().as_ref())
    {
        findings.push(finding(
            DependencyDriftKindV1::OverrideMismatch,
            "project-provider-override",
            Some(provider.directory.to_string()),
            package.project_override_directory.clone(),
        ));
    }

    match &package.checkout {
        CheckoutObservationStateV1::Unobserved => findings.push(finding(
            DependencyDriftKindV1::Unobserved,
            "checkout",
            None,
            None,
        )),
        CheckoutObservationStateV1::Missing => findings.push(finding(
            DependencyDriftKindV1::Missing,
            "checkout",
            expected_directory(package),
            None,
        )),
        CheckoutObservationStateV1::Present {
            directory,
            revision,
            dirty,
        } => {
            if let Some(expected) = expected_directory(package)
                && directory.as_path().to_string_lossy() != expected
            {
                findings.push(finding(
                    DependencyDriftKindV1::PathMismatch,
                    "checkout-directory",
                    Some(expected),
                    Some(directory.to_string()),
                ));
            }
            if let Some(expected) = expected_revision(package) {
                match revision {
                    Some(actual) if actual.as_str() != expected => findings.push(finding(
                        DependencyDriftKindV1::RevisionMismatch,
                        "checkout-revision",
                        Some(expected.to_owned()),
                        Some(actual.to_string()),
                    )),
                    None => findings.push(finding(
                        DependencyDriftKindV1::Unobserved,
                        "checkout-revision",
                        Some(expected.to_owned()),
                        None,
                    )),
                    Some(_) => {}
                }
                match dirty {
                    Some(true) => findings.push(finding(
                        DependencyDriftKindV1::Dirty,
                        "checkout-dirty",
                        Some("false".to_owned()),
                        Some("true".to_owned()),
                    )),
                    None => findings.push(finding(
                        DependencyDriftKindV1::Unobserved,
                        "checkout-dirty",
                        Some("false".to_owned()),
                        None,
                    )),
                    Some(false) => {}
                }
            }
        }
    }

    if findings.is_empty() {
        findings.push(finding(
            DependencyDriftKindV1::Matched,
            "package",
            None,
            None,
        ));
    }
    findings.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.field.cmp(&right.field))
    });
    findings
}

fn expected_revision(package: &PackageInventoryEntryV1) -> Option<&str> {
    match &package.declaration {
        Some(DeclaredPackageSourceV1::Git { revision }) => Some(revision.as_str()),
        _ => package
            .provider
            .as_ref()
            .map(|provider| provider.revision.as_str()),
    }
}

fn expected_directory(package: &PackageInventoryEntryV1) -> Option<String> {
    package
        .resolved_path_directory
        .as_ref()
        .or_else(|| {
            package
                .provider
                .as_ref()
                .map(|provider| &provider.directory)
        })
        .map(ToString::to_string)
}

fn finding(
    kind: DependencyDriftKindV1,
    field: &str,
    expected: Option<String>,
    observed: Option<String>,
) -> DependencyDriftFindingV1 {
    DependencyDriftFindingV1 {
        kind,
        field: field.to_owned(),
        expected,
        observed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revision(value: char) -> GitRevision {
        GitRevision::parse(&value.to_string().repeat(40))
            .unwrap_or_else(|error| panic!("test revision must be valid: {error}"))
    }

    fn synthetic(
        checkout: CheckoutObservationStateV1,
        manifest_revision: char,
        provider_revision: char,
        override_matches: bool,
    ) -> PackageInventoryEntryV1 {
        let provider_directory = test_path("provider");
        PackageInventoryEntryV1 {
            name: "mathlib".to_owned(),
            declaration: Some(DeclaredPackageSourceV1::Git {
                revision: revision(manifest_revision),
            }),
            project_override_directory: override_matches.then(|| provider_directory.to_string()),
            resolved_path_directory: None,
            provider: Some(ProviderPackageRegistrationV1 {
                revision: revision(provider_revision),
                directory: provider_directory,
            }),
            checkout,
        }
    }

    fn test_path(path: &str) -> CanonicalPath {
        let root = if path == "provider" {
            std::env::temp_dir()
        } else {
            std::env::current_dir().unwrap_or_else(|error| panic!("current dir failed: {error}"))
        };
        let directory = leanbun_evidence::canonicalize_directory(&root)
            .unwrap_or_else(|error| panic!("fixture canonicalization failed: {error}"));
        leanbun_evidence::canonicalize_contained(&directory, ".")
            .unwrap_or_else(|error| panic!("fixture containment failed: {error}"))
    }

    fn kinds(package: &PackageInventoryEntryV1) -> Vec<DependencyDriftKindV1> {
        classify_package(package)
            .into_iter()
            .map(|finding| finding.kind)
            .collect()
    }

    #[test]
    fn drift_is_multivalued_and_fail_closed() {
        let package = synthetic(
            CheckoutObservationStateV1::Present {
                directory: test_path("/other/mathlib"),
                revision: Some(revision('2')),
                dirty: Some(true),
            },
            '1',
            '1',
            false,
        );
        assert_eq!(
            kinds(&package),
            vec![
                DependencyDriftKindV1::RevisionMismatch,
                DependencyDriftKindV1::Dirty,
                DependencyDriftKindV1::PathMismatch,
                DependencyDriftKindV1::OverrideMismatch,
            ]
        );
    }

    #[test]
    fn unobserved_is_not_matched() {
        let package = synthetic(CheckoutObservationStateV1::Unobserved, '1', '1', true);
        assert_eq!(kinds(&package), vec![DependencyDriftKindV1::Unobserved]);
    }

    #[test]
    fn invalid_revision_and_name_are_rejected() {
        assert!(GitRevision::parse("HEAD").is_err());
        assert!(PackageCheckoutObservationV1::missing("").is_err());
    }

    #[test]
    fn inventory_snapshot_matches_bun_canonical_golden_and_rejects_drift_forgery()
    -> Result<(), Box<dyn std::error::Error>> {
        let project_path = "/fixture/project".to_owned();
        let inventory = PackageInventoryV1 {
            schema_version: 1,
            project_id: project_id(&project_path),
            project_path,
            toolchain: "leanprover/lean4:v4.32.0".to_owned(),
            manifest_sha256: Sha256::parse(&"0".repeat(64))?,
            override_sha256: None,
            provider_registry_sha256: None,
            provider_override_sha256: None,
            packages: vec![PackageInventoryEntryV1 {
                name: "mathlib".to_owned(),
                declaration: Some(DeclaredPackageSourceV1::Git {
                    revision: revision('1'),
                }),
                project_override_directory: None,
                resolved_path_directory: None,
                provider: None,
                checkout: CheckoutObservationStateV1::Unobserved,
            }],
        };
        let drift = report_dependency_drift(&inventory);
        let snapshot = package_inventory_snapshot_digest_v1(&inventory, &drift)?;
        assert_eq!(
            snapshot.canonical_json,
            include_str!("../../../golden/package-inventory-snapshot.json").trim_end()
        );
        assert_eq!(
            snapshot.sha256.to_string(),
            "56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2"
        );

        let mut forged = drift;
        forged.summary = DependencyDriftSummaryV1::Matched;
        assert!(package_inventory_snapshot_digest_v1(&inventory, &forged).is_err());

        let mut changed = inventory.clone();
        changed.packages[0].checkout = CheckoutObservationStateV1::Missing;
        let changed_drift = report_dependency_drift(&changed);
        let changed_snapshot = package_inventory_snapshot_digest_v1(&changed, &changed_drift)?;
        assert_ne!(changed_snapshot.sha256, snapshot.sha256);
        Ok(())
    }

    #[test]
    fn tracked_mathlib_manifest_builds_unobserved_inventory()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../test/fixtures/mathlib-project");
        let root = leanbun_evidence::canonicalize_directory(fixture)?;
        let project = leanbun_evidence::read_project_input(&root, None)?;
        let inventory = build_package_inventory(&project, None, &[])?;
        assert_eq!(inventory.schema_version, 1);
        assert_eq!(inventory.packages.len(), 9);
        assert!(
            inventory
                .packages
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name)
        );
        assert_eq!(
            report_dependency_drift(&inventory).summary,
            DependencyDriftSummaryV1::Unobserved
        );
        let unknown = PackageCheckoutObservationV1::missing("not-declared")?;
        assert_eq!(
            build_package_inventory(&project, None, &[unknown]).map_err(|error| error.code),
            Err(DiagnosticCode::BUILD_INSPECTION_FAILED)
        );
        Ok(())
    }

    #[test]
    fn shared_drift_cases_match_bun_oracle() -> Result<(), Box<dyn std::error::Error>> {
        for line in include_str!("../../../golden/package-drift-cases.tsv").lines() {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 9, "{line}");
            let provider_directory = test_path("provider");
            let checkout = match fields[2] {
                "unobserved" => CheckoutObservationStateV1::Unobserved,
                "missing" => CheckoutObservationStateV1::Missing,
                "present" => CheckoutObservationStateV1::Present {
                    directory: if fields[6] == "match" {
                        provider_directory.clone()
                    } else {
                        test_path("other")
                    },
                    revision: (fields[7] != "-")
                        .then(|| revision(fields[7].chars().next().unwrap_or('0'))),
                    dirty: match fields[8] {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    },
                },
                _ => return Err(format!("unknown checkout case: {line}").into()),
            };
            let package = synthetic(
                checkout,
                fields[3].chars().next().unwrap_or('0'),
                fields[4].chars().next().unwrap_or('0'),
                fields[5] == "true",
            );
            let actual = classify_package(&package)
                .into_iter()
                .map(|finding| match finding.kind {
                    DependencyDriftKindV1::Missing => "missing",
                    DependencyDriftKindV1::RevisionMismatch => "revision-mismatch",
                    DependencyDriftKindV1::Dirty => "dirty",
                    DependencyDriftKindV1::PathMismatch => "path-mismatch",
                    DependencyDriftKindV1::OverrideMismatch => "override-mismatch",
                    DependencyDriftKindV1::Unobserved => "unobserved",
                    DependencyDriftKindV1::Matched => "matched",
                })
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(actual, fields[0], "{}", fields[1]);
        }
        Ok(())
    }
}

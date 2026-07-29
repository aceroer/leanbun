use super::{
    CheckoutObservationStateV1, DeclaredPackageSourceV1, DependencyDriftFindingV1,
    DependencyDriftKindV1, DependencyDriftReportV1, DependencyDriftSummaryV1,
    PackageInventoryEntryV1, PackageInventoryV1, report_dependency_drift,
};
use core::fmt;
use leanbun_core::{Sha256, Sha256Hasher, project_id};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageInventorySnapshotDigestV1 {
    pub schema_version: u8,
    pub canonical_json: String,
    pub sha256: Sha256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageInventorySnapshotError {
    pub message: String,
}

impl PackageInventorySnapshotError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PackageInventorySnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PackageInventorySnapshotError {}

pub fn package_inventory_snapshot_digest_v1(
    inventory: &PackageInventoryV1,
    drift: &DependencyDriftReportV1,
) -> Result<PackageInventorySnapshotDigestV1, PackageInventorySnapshotError> {
    if inventory.schema_version != 1 || drift.schema_version != 1 {
        return Err(PackageInventorySnapshotError::new(
            "inventory snapshot requires schema version 1 inputs",
        ));
    }
    if inventory.project_id != drift.project_id
        || inventory.project_id != project_id(&inventory.project_path)
    {
        return Err(PackageInventorySnapshotError::new(
            "inventory snapshot project identities differ",
        ));
    }
    if &report_dependency_drift(inventory) != drift {
        return Err(PackageInventorySnapshotError::new(
            "drift report is not the canonical classification of the inventory",
        ));
    }

    let mut inventory_by_name = BTreeMap::new();
    for package in &inventory.packages {
        if package.name.is_empty()
            || package.name.len() > 256
            || package.name.chars().any(char::is_control)
            || inventory_by_name
                .insert(package.name.as_str(), package)
                .is_some()
        {
            return Err(PackageInventorySnapshotError::new(
                "inventory package names must be bounded and unique",
            ));
        }
    }
    let mut drift_by_name = BTreeMap::new();
    for package in &drift.packages {
        if drift_by_name
            .insert(package.name.as_str(), package)
            .is_some()
        {
            return Err(PackageInventorySnapshotError::new(
                "drift package names must be unique",
            ));
        }
    }
    if inventory_by_name.keys().copied().collect::<BTreeSet<_>>()
        != drift_by_name.keys().copied().collect::<BTreeSet<_>>()
    {
        return Err(PackageInventorySnapshotError::new(
            "inventory and drift package names differ",
        ));
    }

    let mut output =
        String::from("{\"schemaVersion\":1,\"snapshotType\":\"package-inventory\",\"projectId\":");
    push_json_string(&mut output, &inventory.project_id.to_string());
    output.push_str(",\"projectPath\":");
    push_json_string(&mut output, &inventory.project_path);
    output.push_str(",\"toolchain\":");
    push_json_string(&mut output, &inventory.toolchain);
    output.push_str(",\"manifestSha256\":");
    push_json_string(&mut output, &inventory.manifest_sha256.to_string());
    output.push_str(",\"overrideSha256\":");
    push_optional_string(
        &mut output,
        inventory
            .override_sha256
            .map(|value| value.to_string())
            .as_deref(),
    );
    output.push_str(",\"providerRegistrySha256\":");
    push_optional_string(
        &mut output,
        inventory
            .provider_registry_sha256
            .map(|value| value.to_string())
            .as_deref(),
    );
    output.push_str(",\"providerOverrideSha256\":");
    push_optional_string(
        &mut output,
        inventory
            .provider_override_sha256
            .map(|value| value.to_string())
            .as_deref(),
    );
    output.push_str(",\"driftSummary\":");
    push_json_string(&mut output, summary_name(drift.summary));
    output.push_str(",\"packages\":[");
    for (index, (name, package)) in inventory_by_name.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let drift_package = drift_by_name.get(name).ok_or_else(|| {
            PackageInventorySnapshotError::new("drift package disappeared during snapshot")
        })?;
        push_package(&mut output, package, &drift_package.findings)?;
    }
    output.push_str("]}");

    let mut hasher = Sha256Hasher::new();
    hasher.update(output.as_bytes());
    Ok(PackageInventorySnapshotDigestV1 {
        schema_version: 1,
        canonical_json: output,
        sha256: hasher.finalize(),
    })
}

fn push_package(
    output: &mut String,
    package: &PackageInventoryEntryV1,
    findings: &[DependencyDriftFindingV1],
) -> Result<(), PackageInventorySnapshotError> {
    output.push_str("{\"name\":");
    push_json_string(output, &package.name);
    output.push_str(",\"declaration\":");
    match &package.declaration {
        None => output.push_str("null"),
        Some(DeclaredPackageSourceV1::Git { revision }) => {
            output.push_str("{\"type\":\"git\",\"revision\":");
            push_json_string(output, revision.as_str());
            output.push('}');
        }
        Some(DeclaredPackageSourceV1::Path { declared_directory }) => {
            output.push_str("{\"type\":\"path\",\"directory\":");
            push_json_string(output, declared_directory);
            output.push('}');
        }
    }
    output.push_str(",\"projectOverrideDirectory\":");
    push_optional_string(output, package.project_override_directory.as_deref());
    output.push_str(",\"resolvedPathDirectory\":");
    push_optional_path(output, package.resolved_path_directory.as_ref())?;
    output.push_str(",\"provider\":");
    match &package.provider {
        None => output.push_str("null"),
        Some(provider) => {
            output.push_str("{\"revision\":");
            push_json_string(output, provider.revision.as_str());
            output.push_str(",\"directory\":");
            push_path(output, &provider.directory)?;
            output.push('}');
        }
    }
    output.push_str(",\"checkout\":");
    match &package.checkout {
        CheckoutObservationStateV1::Unobserved => output.push_str("{\"state\":\"unobserved\"}"),
        CheckoutObservationStateV1::Missing => output.push_str("{\"state\":\"missing\"}"),
        CheckoutObservationStateV1::Present {
            directory,
            revision,
            dirty,
        } => {
            output.push_str("{\"state\":\"present\",\"directory\":");
            push_path(output, directory)?;
            output.push_str(",\"revision\":");
            push_optional_string(output, revision.as_ref().map(super::GitRevision::as_str));
            output.push_str(",\"dirty\":");
            match dirty {
                Some(value) => output.push_str(if *value { "true" } else { "false" }),
                None => output.push_str("null"),
            }
            output.push('}');
        }
    }
    output.push_str(",\"findings\":[");
    for (index, finding) in findings.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str("{\"kind\":");
        push_json_string(output, kind_name(finding.kind));
        output.push_str(",\"field\":");
        push_json_string(output, &finding.field);
        output.push_str(",\"expected\":");
        push_optional_string(output, finding.expected.as_deref());
        output.push_str(",\"observed\":");
        push_optional_string(output, finding.observed.as_deref());
        output.push('}');
    }
    output.push_str("]}");
    Ok(())
}

fn push_optional_path(
    output: &mut String,
    path: Option<&leanbun_evidence::CanonicalPath>,
) -> Result<(), PackageInventorySnapshotError> {
    if let Some(path) = path {
        push_path(output, path)
    } else {
        output.push_str("null");
        Ok(())
    }
}

fn push_path(
    output: &mut String,
    path: &leanbun_evidence::CanonicalPath,
) -> Result<(), PackageInventorySnapshotError> {
    let value = path.as_path().to_str().ok_or_else(|| {
        PackageInventorySnapshotError::new("inventory canonical path is not valid UTF-8")
    })?;
    push_json_string(output, value);
    Ok(())
}

fn push_optional_string(output: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        push_json_string(output, value);
    } else {
        output.push_str("null");
    }
}

fn summary_name(value: DependencyDriftSummaryV1) -> &'static str {
    match value {
        DependencyDriftSummaryV1::Matched => "matched",
        DependencyDriftSummaryV1::Drifted => "drifted",
        DependencyDriftSummaryV1::Unobserved => "unobserved",
    }
}

fn kind_name(value: DependencyDriftKindV1) -> &'static str {
    match value {
        DependencyDriftKindV1::Missing => "missing",
        DependencyDriftKindV1::RevisionMismatch => "revision-mismatch",
        DependencyDriftKindV1::Dirty => "dirty",
        DependencyDriftKindV1::PathMismatch => "path-mismatch",
        DependencyDriftKindV1::OverrideMismatch => "override-mismatch",
        DependencyDriftKindV1::Unobserved => "unobserved",
        DependencyDriftKindV1::Matched => "matched",
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => {
                use core::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

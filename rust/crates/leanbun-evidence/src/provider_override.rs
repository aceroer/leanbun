use leanbun_core::DiagnosticCode;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::{
    CanonicalDirectory, CanonicalPath, EvidenceError, MAX_PROVIDER_PACKAGES,
    PROVIDER_REGISTRY_MAX_BYTES, ProviderRegistry, StableProviderRegistryFile, StableTextFile,
    StrictJson, canonicalize_contained, canonicalize_contained_directory, parse_strict_json,
    read_provider_registry, read_stable_text,
};

const MAX_SHORT_STRING_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const ROOT_FIELDS: &[&str] = &["packages", "version"];
const PACKAGE_FIELDS: &[&str] = &[
    "configFile",
    "dir",
    "inherited",
    "manifestFile",
    "name",
    "type",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderOverridePackage {
    pub name: String,
    pub directory: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderOverride {
    pub version: String,
    pub packages: Vec<ProviderOverridePackage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableProviderOverrideFile {
    pub file: StableTextFile,
    pub overrides: ProviderOverride,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProviderPackage {
    pub name: String,
    pub revision: String,
    pub directory: CanonicalPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableProviderPair {
    pub registry: StableProviderRegistryFile,
    pub overrides: StableProviderOverrideFile,
    pub package_root: CanonicalDirectory,
    pub packages: Vec<VerifiedProviderPackage>,
}

pub fn read_provider_override(
    root: &CanonicalDirectory,
    candidate: impl AsRef<Path>,
) -> Result<StableProviderOverrideFile, EvidenceError> {
    let file = read_stable_text(root, candidate, PROVIDER_REGISTRY_MAX_BYTES)?;
    let overrides = parse_provider_override(&file.text)?;
    Ok(StableProviderOverrideFile { file, overrides })
}

pub fn parse_provider_override(text: &str) -> Result<ProviderOverride, EvidenceError> {
    decode_provider_override(&parse_strict_json(text)?)
}

pub fn decode_provider_override(value: &StrictJson) -> Result<ProviderOverride, EvidenceError> {
    let root = object(value, "provider override root")?;
    reject_unknown_fields(root, ROOT_FIELDS, "provider override root")?;

    let version = required_string(root, "version", MAX_SHORT_STRING_BYTES, "provider override")?;
    if !supported_lake_version(version) {
        return Err(EvidenceError::new(
            DiagnosticCode::MANIFEST_SCHEMA_UNSUPPORTED,
            format!("provider override schema {version} is not supported; supported major=1"),
        ));
    }
    let packages = match root.get("packages") {
        Some(StrictJson::Array(values)) => values,
        Some(_) => return Err(shape("provider override packages must be an array")),
        None => return Err(shape("provider override is missing packages")),
    };
    if packages.len() > MAX_PROVIDER_PACKAGES {
        return Err(shape(format!(
            "provider override package count {} exceeds limit {MAX_PROVIDER_PACKAGES}",
            packages.len()
        )));
    }

    let mut names = BTreeSet::new();
    let mut decoded = Vec::with_capacity(packages.len());
    for (index, package) in packages.iter().enumerate() {
        let label = format!("provider override package {index}");
        let package = object(package, &label)?;
        reject_unknown_fields(package, PACKAGE_FIELDS, &label)?;

        let name = required_string(package, "name", MAX_SHORT_STRING_BYTES, &label)?;
        if name.is_empty() {
            return Err(shape(format!("{label} name must not be empty")));
        }
        if !names.insert(name) {
            return Err(shape(format!(
                "duplicate provider override package name: {name}"
            )));
        }
        let package_type = required_string(package, "type", MAX_SHORT_STRING_BYTES, &label)?;
        if package_type != "path" {
            return Err(shape(format!("{label} type must be path")));
        }
        let directory = required_string(package, "dir", MAX_PATH_BYTES, &label)?;
        if !Path::new(directory).is_absolute() {
            return Err(shape(format!("{label} dir must be an absolute path")));
        }
        for field in ["manifestFile", "configFile"] {
            optional_string(package, field, MAX_SHORT_STRING_BYTES, &label)?;
        }
        if let Some(value) = package.get("inherited")
            && !matches!(value, StrictJson::Bool(_))
        {
            return Err(shape(format!("{label} inherited must be a boolean")));
        }

        decoded.push(ProviderOverridePackage {
            name: name.to_owned(),
            directory: directory.to_owned(),
        });
    }

    Ok(ProviderOverride {
        version: version.to_owned(),
        packages: decoded,
    })
}

pub fn read_provider_pair(
    isolation_root: &CanonicalDirectory,
    registry_candidate: impl AsRef<Path>,
    override_candidate: impl AsRef<Path>,
    package_root_candidate: impl AsRef<Path>,
) -> Result<StableProviderPair, EvidenceError> {
    let registry_candidate = registry_candidate.as_ref();
    let override_candidate = override_candidate.as_ref();
    let package_root = canonicalize_contained_directory(isolation_root, package_root_candidate)?;
    let registry = read_provider_registry(isolation_root, registry_candidate)?;
    let overrides = read_provider_override(isolation_root, override_candidate)?;
    let packages =
        match_provider_documents(&registry.registry, &overrides.overrides, &package_root)?;

    let registry_after = read_provider_registry(isolation_root, registry_candidate)?;
    let overrides_after = read_provider_override(isolation_root, override_candidate)?;
    if registry.file.sha256 != registry_after.file.sha256
        || overrides.file.sha256 != overrides_after.file.sha256
    {
        return Err(EvidenceError::new(
            DiagnosticCode::EVIDENCE_CHANGED_DURING_READ,
            "provider registry or override changed during pair verification",
        ));
    }

    Ok(StableProviderPair {
        registry,
        overrides,
        package_root,
        packages,
    })
}

fn match_provider_documents(
    registry: &ProviderRegistry,
    overrides: &ProviderOverride,
    package_root: &CanonicalDirectory,
) -> Result<Vec<VerifiedProviderPackage>, EvidenceError> {
    if registry.version != overrides.version {
        return Err(drift(format!(
            "provider registry version {} differs from override version {}",
            registry.version, overrides.version
        )));
    }
    let override_by_name = overrides
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let registry_names = registry
        .packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    let override_names = override_by_name.keys().copied().collect::<BTreeSet<_>>();
    if registry_names != override_names {
        let missing = registry_names
            .difference(&override_names)
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        let extra = override_names
            .difference(&registry_names)
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        return Err(drift(format!(
            "provider package name sets differ; missing=[{missing}] extra=[{extra}]"
        )));
    }

    let mut packages = Vec::with_capacity(registry.packages.len());
    for package in &registry.packages {
        let override_package = override_by_name.get(package.name.as_str()).ok_or_else(|| {
            drift(format!(
                "provider override is missing package: {}",
                package.name
            ))
        })?;
        let directory = canonicalize_contained(package_root, &override_package.directory)?;
        let metadata = fs::metadata(directory.as_path()).map_err(|error| {
            EvidenceError::new(
                DiagnosticCode::EVIDENCE_READ_FAILED,
                format!("provider package directory cannot be inspected: {error}"),
            )
        })?;
        if !metadata.is_dir() {
            return Err(EvidenceError::new(
                DiagnosticCode::PROJECT_NOT_DIRECTORY,
                format!(
                    "provider package path is not a directory: {}",
                    directory.as_path().display()
                ),
            ));
        }
        packages.push(VerifiedProviderPackage {
            name: package.name.clone(),
            revision: package.revision.clone(),
            directory,
        });
    }
    Ok(packages)
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
    EvidenceError::new(DiagnosticCode::PROVIDER_SCHEMA_INVALID, message)
}

fn drift(message: impl Into<String>) -> EvidenceError {
    EvidenceError::new(DiagnosticCode::OVERRIDE_DRIFTED, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonicalize_directory, decode_provider_registry};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const REVISION: &str = "81a5d257c8e410db227a6665ed08f64fea08e997";
    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct Fixture(std::path::PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "leanbun-provider-pair-{}-{nonce}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("packages/mathlib"))?;
        Ok(Fixture(path.canonicalize()?))
    }

    #[test]
    fn shared_provider_override_contract_cases_match() {
        for line in include_str!("../../../golden/provider-override-cases.tsv").lines() {
            let mut fields = line.splitn(3, '\t');
            let expected = fields.next() == Some("true");
            let label = fields.next().unwrap_or("");
            let text = fields.next().unwrap_or("");
            assert_eq!(parse_provider_override(text).is_ok(), expected, "{label}");
        }
    }

    #[test]
    fn provider_pair_binds_matching_names_and_contained_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let directory = fixture.0.join("packages/mathlib");
        let registry = format!(
            r#"{{"version":"1.2.0","packagesDir":"packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}]}}"#
        );
        let overrides = format!(
            r#"{{"version":"1.2.0","packages":[{{"name":"mathlib","type":"path","dir":"{}"}}]}}"#,
            directory.display()
        );
        fs::write(fixture.0.join("registry.json"), registry)?;
        fs::write(fixture.0.join("overrides.json"), overrides)?;
        let root = canonicalize_directory(&fixture.0)?;
        let pair = read_provider_pair(&root, "registry.json", "overrides.json", "packages")?;
        assert_eq!(pair.packages.len(), 1);
        assert_eq!(pair.packages[0].name, "mathlib");
        assert_eq!(pair.packages[0].directory.as_path(), directory);
        Ok(())
    }

    #[test]
    fn provider_pair_rejects_name_drift_and_path_escape() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture()?;
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside)?;
        let registry = format!(
            r#"{{"version":"1.2.0","packagesDir":"packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}]}}"#
        );
        fs::write(fixture.0.join("registry.json"), &registry)?;
        fs::write(
            fixture.0.join("overrides.json"),
            format!(
                r#"{{"version":"1.2.0","packages":[{{"name":"other","type":"path","dir":"{}"}}]}}"#,
                outside.display()
            ),
        )?;
        let root = canonicalize_directory(&fixture.0)?;
        assert!(matches!(
            read_provider_pair(&root, "registry.json", "overrides.json", "packages"),
            Err(error) if error.code == DiagnosticCode::OVERRIDE_DRIFTED
        ));

        fs::write(
            fixture.0.join("overrides.json"),
            format!(
                r#"{{"version":"1.2.0","packages":[{{"name":"mathlib","type":"path","dir":"{}"}}]}}"#,
                outside.display()
            ),
        )?;
        assert!(matches!(
            read_provider_pair(&root, "registry.json", "overrides.json", "packages"),
            Err(error) if error.code == DiagnosticCode::PATH_ESCAPES_ALLOWED_ROOT
        ));
        Ok(())
    }

    #[test]
    fn provider_override_package_count_limit_is_enforced() {
        let package = r#"{"name":"p","type":"path","dir":"/tmp/p"}"#;
        let packages = std::iter::repeat_n(package, MAX_PROVIDER_PACKAGES + 1)
            .collect::<Vec<_>>()
            .join(",");
        let oversized = format!(r#"{{"version":"1.2.0","packages":[{packages}]}}"#);
        assert!(matches!(
            parse_provider_override(&oversized),
            Err(error) if error.code == DiagnosticCode::PROVIDER_SCHEMA_INVALID
        ));
    }

    #[test]
    fn provider_registry_decoder_remains_composable() {
        let value = parse_strict_json(&format!(
            r#"{{"version":"1.2.0","packagesDir":"packages","packages":[{{"name":"mathlib","type":"git","rev":"{REVISION}"}}]}}"#
        ));
        assert!(matches!(value, Ok(ref value) if decode_provider_registry(value).is_ok()));
    }
}
